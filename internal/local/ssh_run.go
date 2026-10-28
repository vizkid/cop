package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type projectAgent struct {
	ctx    context.Context
	home   string
	key    Key
	public ssh.PublicKey
}

var errAgent = errors.New("cop agent refuses this operation")

func (a *projectAgent) List() ([]*agent.Key, error) {
	result, err := Call(a.ctx, a.home, Request{Action: "status"})
	if err != nil {
		return nil, errAgent
	}
	for _, key := range result.View.Projects[a.key.Project] {
		if key == a.key {
			return []*agent.Key{{Format: ssh.KeyAlgoED25519, Blob: a.public.Marshal(), Comment: "cop " + key.Project}}, nil
		}
	}
	return nil, errAgent
}
func (a *projectAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}
func (a *projectAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if flags != 0 || !bytes.Equal(key.Marshal(), a.public.Marshal()) {
		return nil, errAgent
	}
	r, err := Call(a.ctx, a.home, Request{Action: "sign", Key: a.key, Data: data})
	if err != nil {
		return nil, errAgent
	}
	return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: r.Signature}, nil
}
func (*projectAgent) Add(agent.AddedKey) error       { return errAgent }
func (*projectAgent) Remove(ssh.PublicKey) error     { return errAgent }
func (*projectAgent) RemoveAll() error               { return errAgent }
func (*projectAgent) Lock([]byte) error              { return errAgent }
func (*projectAgent) Unlock([]byte) error            { return errAgent }
func (*projectAgent) Signers() ([]ssh.Signer, error) { return nil, errAgent }
func (*projectAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// RunSSH exposes only one project identity for the lifetime of the child.
func RunSSH(ctx context.Context, home string, key Key, purpose string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(command) == 0 || key.Use != "ssh-sign" || (purpose != "sign" && purpose != "auth") {
		return errors.New("ssh-run needs a signing identity and command")
	}
	if err := key.Validate(); err != nil {
		return err
	}
	if _, err := Call(ctx, home, Request{Action: "request", Key: key}); err != nil {
		return err
	}
	public, _ := signingPublic(key.PublicKey)
	dir, err := os.MkdirTemp(home, "ssh-")
	if err != nil {
		return errors.New("cannot create agent directory")
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "agent")
	identity := filepath.Join(dir, "identity.pub")
	if err := os.WriteFile(identity, ssh.MarshalAuthorizedKey(public), 0600); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return errors.New("cannot create cop SSH socket; check Unix path length")
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	serving, cancel := context.WithCancel(ctx)
	defer cancel()
	proxy := &projectAgent{serving, home, key, public}
	slots := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				stop := context.AfterFunc(serving, func() { conn.Close() })
				defer stop()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
				_ = agent.ServeAgent(proxy, conn)
			}()
		}
	}()
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	for _, v := range os.Environ() {
		name, _, _ := strings.Cut(v, "=")
		if name == "SSH_AUTH_SOCK" || strings.HasPrefix(name, "GIT_CONFIG_") || strings.HasPrefix(name, "GIT_SSH") {
			continue
		}
		child.Env = append(child.Env, v)
	}
	child.Env = append(child.Env, "SSH_AUTH_SOCK="+socket, "GIT_SSH_VARIANT=ssh")
	transport, signer := "false", "ssh-keygen"
	if purpose == "auth" {
		transport = "ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=SSH_AUTH_SOCK -i " + shellQuote(identity)
		signer = "false"
	}
	child.Env = append(child.Env, "GIT_SSH_COMMAND="+transport)
	overrides := [][2]string{{"gpg.format", "ssh"}, {"gpg.ssh.program", signer}, {"user.signingkey", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))}, {"commit.gpgsign", "true"}}
	child.Env = append(child.Env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(overrides)))
	for i, pair := range overrides {
		child.Env = append(child.Env, "GIT_CONFIG_KEY_"+strconv.Itoa(i)+"="+pair[0], "GIT_CONFIG_VALUE_"+strconv.Itoa(i)+"="+pair[1])
	}
	child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
	return child.Run()
}
