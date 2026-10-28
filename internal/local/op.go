package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Resolver func(context.Context, Key) ([]byte, error)

type boundedOutput struct{ buffer bytes.Buffer }

func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > MaxSecret {
		return 0, errors.New("op output exceeds limit")
	}
	return b.buffer.Write(p)
}

func OP(path string) (Resolver, error) {
	executable, err := exec.LookPath(path)
	if err != nil {
		return nil, errors.New("op executable unavailable")
	}
	return func(ctx context.Context, k Key) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, "read", "--account", k.Account, "--no-newline", "--cache=false", k.Ref)
		for _, e := range os.Environ() {
			name, _, _ := strings.Cut(e, "=")
			switch name {
			case "OP_DEBUG", "OP_ACCOUNT", "OP_CACHE", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN":
				continue
			}
			cmd.Env = append(cmd.Env, e)
		}
		cmd.Env = append(cmd.Env, "OP_DEBUG=false", "OP_CACHE=false")
		// Authentication belongs to 1Password; never attach manual prompts to the service terminal.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		out := boundedOutput{buffer: *bytes.NewBuffer(make([]byte, 0, MaxSecret))}
		defer func() { clear(out.Bytes()) }()
		cmd.Stdout, cmd.Stderr = &out, io.Discard
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, errors.New("op resolution canceled or timed out")
			}
			return nil, errors.New("op resolution failed; check 1Password authentication and the exact reference")
		}
		if bytes.IndexByte(out.Bytes(), 0) >= 0 {
			return nil, errors.New("secret cannot be delivered through an environment variable")
		}
		return bytes.Clone(out.Bytes()), nil
	}, nil
}
