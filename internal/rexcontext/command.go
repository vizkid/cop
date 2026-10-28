package rexcontext

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

const maxOutput = 2 << 20

// Do not embed bytes.Buffer: its ReadFrom method would bypass Write's limit.
type output struct{ buffer bytes.Buffer }

func (o *output) Write(p []byte) (int, error) {
	if o.buffer.Len()+len(p) > maxOutput {
		return 0, errors.New("Rex response exceeds limit")
	}
	return o.buffer.Write(p)
}

func runRex(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rex", args...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "REX_CLIENT=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var out output
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("Rex command failed")
	}
	return out.buffer.Bytes(), nil
}
