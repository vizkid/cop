package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

func signingFixture(t *testing.T) (Key, []byte, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(public)
	return Key{Project: "alpha", Account: "synthetic", Ref: "op://fixture/identity/private key", Use: "ssh-sign", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}, pem.EncodeToMemory(block), public
}

func TestSigningAuthorityAndCache(t *testing.T) {
	key, value, public := signingFixture(t)
	defer clear(value)
	var calls atomic.Int32
	resolver := func(context.Context, Key) ([]byte, error) { calls.Add(1); return bytes.Clone(value), nil }
	s := newTestService(t, resolver, time.Minute)
	authorize(t, s, key)
	payload := []byte("synthetic commit payload")
	sign := func() Result { return s.Handle(context.Background(), Request{Action: "sign", Key: key, Data: payload}) }
	for i := 0; i < 2; i++ {
		result := sign()
		if result.Error != "" || len(result.Value) != 0 || !ed25519.Verify(public, payload, result.Signature) {
			t.Fatal("signature failed")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("signature missed cache")
	}
	if r := s.Handle(context.Background(), Request{Action: "deliver", Key: key}); r.Error == "" || len(r.Value) > 0 {
		t.Fatal("exported signing key")
	}
	other := key
	other.Project = "other"
	if r := s.Handle(context.Background(), Request{Action: "sign", Key: other, Data: payload}); r.Error == "" {
		t.Fatal("project isolation failed")
	}
	s.mu.Lock()
	e := s.cache[key]
	e.expires = time.Now().Add(-time.Second)
	s.cache[key] = e
	s.mu.Unlock()
	if sign().Error != "" || calls.Load() != 2 {
		t.Fatal("expiry failed")
	}
	handle(t, s, "clear", Key{Project: key.Project})
	if sign().Error != "" || calls.Load() != 3 {
		t.Fatal("clear failed")
	}
	handle(t, s, "revoke", key)
	if sign().Error == "" {
		t.Fatal("revoked signature allowed")
	}
	authorize(t, s, key)
	home := s.home
	s.Close()
	restored, err := New(home, resolver, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	r := restored.Handle(context.Background(), Request{Action: "sign", Key: key, Data: payload})
	if r.Error != "" || calls.Load() != 4 {
		t.Fatal("restart reused key")
	}
	status, _ := json.Marshal(handle(t, restored, "status", Key{}))
	disk, _ := os.ReadFile(filepath.Join(home, "projects.json"))
	if bytes.Contains(status, value) || bytes.Contains(disk, value) {
		t.Fatal("private key persisted or reported")
	}
}

func TestSigningRejectsWrongIdentity(t *testing.T) {
	key, value, _ := signingFixture(t)
	defer clear(value)
	other, _, _ := signingFixture(t)
	key.PublicKey = other.PublicKey
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return bytes.Clone(value), nil }, time.Minute)
	authorize(t, s, key)
	if r := s.Handle(context.Background(), Request{Action: "request", Key: key}); r.Error == "" {
		t.Fatal("mismatched identity cached")
	}
	if len(handle(t, s, "status", Key{}).View.Cache) != 0 {
		t.Fatal("bad key retained")
	}
}

func TestSigningReferenceCannotBecomeReadable(t *testing.T) {
	key, value, _ := signingFixture(t)
	defer clear(value)
	key.Ref = "op://fixture/identity/key"
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return bytes.Clone(value), nil }, time.Minute)
	authorize(t, s, key)
	readable := key
	readable.Use = ""
	readable.PublicKey = ""
	if r := s.Handle(context.Background(), Request{Action: "allow", Key: readable}); r.Error == "" {
		t.Fatal("signing reference became readable")
	}
	if r := s.Handle(context.Background(), Request{Action: "deliver", Key: readable}); r.Error == "" {
		t.Fatal("signing value exported through read identity")
	}
}

func TestSigningAgentAndGit(t *testing.T) {
	key, value, public := signingFixture(t)
	defer clear(value)
	authKey, authValue, authPublic := signingFixture(t)
	authKey.Ref = "op://fixture/auth/private key"
	defer clear(authValue)
	// A short path keeps Unix sockets portable on macOS.
	root, err := os.MkdirTemp("", "cop-sign-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	home := filepath.Join(root, "space home")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		done <- Serve(ctx, home, func(_ context.Context, k Key) ([]byte, error) {
			calls.Add(1)
			if k == authKey {
				return bytes.Clone(authValue), nil
			}
			return bytes.Clone(value), nil
		}, time.Minute, time.Second, func() { close(ready) })
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("service unavailable")
	}
	defer func() { cancel(); <-done }()
	for _, action := range []string{"create", "allow"} {
		if _, err := Call(ctx, home, Request{Action: action, Key: key}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Call(ctx, home, Request{Action: "allow", Key: authKey}); err != nil {
		t.Fatal(err)
	}
	pub, _ := signingPublic(key.PublicKey)
	proxy := &projectAgent{ctx, home, key, pub}
	left, right := net.Pipe()
	defer left.Close()
	go func() { defer right.Close(); _ = agent.ServeAgent(proxy, right) }()
	client := agent.NewClient(left)
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("listing failed")
	}
	sig, err := client.Sign(pub, []byte("ssh-auth-test"))
	if err != nil || !ed25519.Verify(public, []byte("ssh-auth-test"), sig.Blob) {
		t.Fatal("agent signature failed")
	}
	if client.RemoveAll() == nil || client.Lock([]byte("lock")) == nil {
		t.Fatal("agent mutation accepted")
	}
	if _, err := client.SignWithFlags(pub, []byte("test"), agent.SignatureFlagRsaSha256); err == nil {
		t.Fatal("unsupported flags accepted")
	}
	repo := t.TempDir()
	for _, args := range [][]string{{"init", repo}, {"-C", repo, "config", "user.name", "Synthetic"}, {"-C", repo, "config", "user.email", "test@example.invalid"}} {
		if err := exec.Command("git", args...).Run(); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := RunSSH(ctx, home, key, "sign", []string{"git", "-C", repo, "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-m", "synthetic signing test"}, nil, &output, &output); err != nil {
		t.Fatalf("Git signing failed: %v %s", err, output.String())
	}
	allowed := filepath.Join(repo, "allowed-signers")
	if err := os.WriteFile(allowed, []byte("test@example.invalid "+key.PublicKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command("git", "-C", repo, "-c", "gpg.ssh.program=ssh-keygen", "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD")
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("signature verification failed: %v %s", err, out)
	}
	if calls.Load() != 1 {
		t.Fatal("agent and Git did not share cached identity")
	}
	if err := RunSSH(ctx, home, authKey, "auth", []string{"/bin/sh", "-c", `eval "$GIT_SSH_COMMAND -G example.invalid" >/dev/null && test "$(git config --get gpg.ssh.program)" = false`}, nil, io.Discard, &output); err != nil {
		t.Fatalf("SSH config failed with spaced home: %v %s", err, output.String())
	}
	if err := RunSSH(ctx, home, key, "sign", []string{"/bin/sh", "-c", `test "$GIT_SSH_COMMAND" = false && test "$(git config --get gpg.ssh.program)" = ssh-keygen`}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	authPub, _ := signingPublic(authKey.PublicKey)
	authAgent := &projectAgent{ctx, home, authKey, authPub}
	if _, err := authAgent.Sign(pub, []byte("test")); err == nil {
		t.Fatal("auth agent accepted commit identity")
	}
	authSig, err := authAgent.Sign(authPub, []byte("auth"))
	if err != nil || !ed25519.Verify(authPublic, []byte("auth"), authSig.Blob) {
		t.Fatal("wrong authentication identity")
	}
	if calls.Load() != 2 {
		t.Fatal("separate identities did not retain separate cache entries")
	}
}
