package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type sdkError struct{ code int }

func (e *sdkError) Error() string {
	switch e.code {
	case 20:
		return "SDK desktop initialization failed"
	case 40:
		return "SDK could not match the vault; use its verified ID"
	case 41:
		return "SDK could not match the item in the selected vault"
	case 42:
		return "SDK could not match the field in the selected item"
	default:
		return "SDK exact-reference resolution failed"
	}
}

// SDK receives values only through a private inherited pipe, never worker logs.
func SDK(path string) (Resolver, error) {
	executable, err := exec.LookPath(path)
	if err != nil {
		return nil, errors.New("SDK worker unavailable; run make build")
	}
	return func(ctx context.Context, k Key) ([]byte, error) {
		if err := k.Validate(); err != nil {
			return nil, err
		}
		input, _ := json.Marshal(k)
		reader, writer, err := os.Pipe()
		if err != nil {
			return nil, errors.New("SDK pipe unavailable")
		}
		defer reader.Close()
		defer writer.Close()
		cmd := exec.CommandContext(ctx, executable)
		for _, e := range os.Environ() {
			name, _, _ := strings.Cut(e, "=")
			if strings.HasPrefix(name, "OP_") {
				continue
			}
			cmd.Env = append(cmd.Env, e)
		}
		cmd.Env = append(cmd.Env, "OP_DEBUG=false")
		cmd.Stdin = bytes.NewReader(input)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		cmd.ExtraFiles = []*os.File{writer}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		out := boundedOutput{}
		defer func() { clear(out.Bytes()) }()
		copied := make(chan error, 1)
		go func() { _, err := io.Copy(&out, reader); copied <- err }()
		err = cmd.Run()
		writer.Close()
		var copyErr error
		select {
		case copyErr = <-copied:
		case <-time.After(time.Second):
			reader.Close()
			<-copied
			copyErr = errors.New("SDK pipe did not close")
		}
		if ctx.Err() != nil {
			return nil, errors.New("SDK resolution canceled or timed out")
		}
		if err != nil || copyErr != nil {
			var status *exec.ExitError
			if errors.As(err, &status) {
				return nil, &sdkError{status.ExitCode()}
			}
			return nil, errors.New("SDK resolution failed; check desktop approval, account, and exact reference")
		}
		if bytes.IndexByte(out.Bytes(), 0) >= 0 {
			return nil, errors.New("secret cannot be delivered through an environment variable")
		}
		return bytes.Clone(out.Bytes()), nil
	}, nil
}
