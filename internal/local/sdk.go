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
	case 21:
		return "SDK bulk resolution failed after client initialization"
	case 22:
		return "SDK authorization or resolution was canceled"
	case 23:
		return "SDK authorization session expired"
	case 24:
		return "SDK authorization was refused"
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
func SDK(path string, args ...string) (Resolver, error) {
	executable, err := exec.LookPath(path)
	if err != nil {
		return nil, errors.New("SDK worker unavailable; run make build")
	}
	return func(ctx context.Context, k Key) ([]byte, error) {
		if err := k.Validate(); err != nil {
			return nil, err
		}
		input, _ := json.Marshal(k)
		value, err := sdkOutput(ctx, executable, args, input, MaxSecret)
		if bytes.IndexByte(value, 0) >= 0 {
			clear(value)
			return nil, errors.New("secret cannot contain NUL")
		}
		return value, err
	}, nil
}

type BatchValue struct {
	Value []byte `json:"value,omitempty"`
	Code  int    `json:"code,omitempty"`
}
type BatchResolver func(context.Context, []Key) ([]BatchValue, error)

func SDKBatch(path string, args ...string) (BatchResolver, error) {
	executable, err := exec.LookPath(path)
	if err != nil {
		return nil, errors.New("SDK worker unavailable")
	}
	return func(ctx context.Context, keys []Key) ([]BatchValue, error) {
		if len(keys) == 0 || len(keys) > 128 {
			return nil, errors.New("invalid SDK batch size")
		}
		for _, k := range keys {
			if k.Validate() != nil || k.Project != keys[0].Project || k.Account != keys[0].Account {
				return nil, errors.New("SDK batch must use one project and account")
			}
		}
		input, _ := json.Marshal(keys)
		output, err := sdkOutput(ctx, executable, args, input, 16<<20)
		defer clear(output)
		if err != nil {
			return nil, err
		}
		var values []BatchValue
		if json.Unmarshal(output, &values) != nil || len(values) != len(keys) {
			for _, v := range values {
				clear(v.Value)
			}
			return nil, errors.New("invalid SDK batch response")
		}
		return values, nil
	}, nil
}
func sdkOutput(ctx context.Context, executable string, args []string, input []byte, limit int) ([]byte, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errors.New("SDK pipe unavailable")
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.CommandContext(ctx, executable, args...)
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
	out := limitedBuffer{limit: limit}
	defer func() { clear(out.data) }()
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

	return bytes.Clone(out.data), nil
}
