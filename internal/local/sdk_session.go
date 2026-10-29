package local

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type sdkSession struct {
	cmd        *exec.Cmd
	input      io.WriteCloser
	output     *os.File
	reader     *bufio.Reader
	timer      *time.Timer
	generation uint64
}
type sdkSessions struct {
	mu         sync.Mutex
	executable string
	args       []string
	sessions   map[string]*sdkSession
	closed     bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// SDKSession reuses a process only within one account. Idle workers exit without keepalive requests.
func SDKSession(path string, args ...string) (BatchResolver, func(), error) {
	executable, err := exec.LookPath(path)
	if err != nil {
		return nil, nil, errors.New("SDK worker unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool := &sdkSessions{executable: executable, args: args, sessions: map[string]*sdkSession{}, ctx: ctx, cancel: cancel}
	return pool.resolve, pool.close, nil
}
func (s *sdkSession) close() {
	if s.timer != nil {
		s.timer.Stop()
	}
	_ = s.input.Close()
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	_ = s.output.Close()
	_ = s.cmd.Wait()
}
func (p *sdkSessions) close() {
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for account, s := range p.sessions {
		s.close()
		delete(p.sessions, account)
	}
}
func (p *sdkSessions) start() (*sdkSession, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errors.New("SDK pipe unavailable")
	}
	cmd := exec.Command(p.executable, p.args...)
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(name, "OP_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "OP_DEBUG=false")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{writer}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = time.Second
	input, err := cmd.StdinPipe()
	if err != nil {
		reader.Close()
		writer.Close()
		return nil, errors.New("SDK input unavailable")
	}
	if err := cmd.Start(); err != nil {
		input.Close()
		reader.Close()
		writer.Close()
		return nil, errors.New("SDK worker could not start")
	}
	writer.Close()
	return &sdkSession{cmd: cmd, input: input, output: reader, reader: bufio.NewReader(reader)}, nil
}
func (p *sdkSessions) resolve(ctx context.Context, keys []Key) ([]BatchValue, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopPool := context.AfterFunc(p.ctx, cancel)
	defer stopPool()
	if len(keys) == 0 || len(keys) > MaxEntries {
		return nil, errors.New("invalid SDK batch size")
	}
	account := keys[0].Account
	for _, k := range keys {
		if k.Validate() != nil || k.Account != account || k.Project != keys[0].Project {
			return nil, errors.New("SDK batch must use one project and account")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || ctx.Err() != nil {
		return nil, errors.New("SDK request canceled")
	}
	s := p.sessions[account]
	if s == nil {
		var err error
		s, err = p.start()
		if err != nil {
			return nil, err
		}
		p.sessions[account] = s
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.generation++
	generation := s.generation
	canceled := make(chan struct{})
	// Closing pipes also interrupts a worker stuck in native SDK code.
	stop := context.AfterFunc(ctx, func() {
		defer close(canceled)
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_ = s.output.Close()
		_ = s.input.Close()
	})
	input, _ := json.Marshal(keys)
	input = append(input, '\n')
	_, err := s.input.Write(input)
	var output []byte
	if err == nil {
		// ReadSlice bounds allocations even if a worker emits no newline.
		for {
			part, e := s.reader.ReadSlice('\n')
			if len(output)+len(part) > 16<<20 {
				err = errors.New("SDK response too large")
				break
			}
			output = append(output, part...)
			clear(part)
			if e == nil {
				break
			}
			if e != bufio.ErrBufferFull {
				err = e
				break
			}
		}
	}
	stopped := stop()
	if !stopped {
		<-canceled
	}
	defer clear(output)
	var values []BatchValue
	if err == nil && stopped && ctx.Err() == nil && json.Unmarshal(output, &values) == nil && len(values) == len(keys) {
		s.timer = time.AfterFunc(9*time.Minute, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.sessions[account] == s && s.generation == generation {
				s.close()
				delete(p.sessions, account)
			}
		})
		return values, nil
	}
	for _, v := range values {
		clear(v.Value)
	}
	s.close()
	delete(p.sessions, account)
	if ctx.Err() != nil {
		return nil, errors.New("SDK batch canceled or timed out")
	}
	return nil, errors.New("SDK session failed; retry the project batch")
}

// SingleFromBatch uses the same account authorization for an individual cache miss.
func SingleFromBatch(batch BatchResolver) Resolver {
	return func(ctx context.Context, key Key) ([]byte, error) {
		values, err := batch(ctx, []Key{key})
		if err != nil {
			return nil, err
		}
		if len(values) != 1 {
			for _, v := range values {
				clear(v.Value)
			}
			return nil, errors.New("invalid SDK response")
		}
		if values[0].Code != 0 {
			clear(values[0].Value)
			return nil, &sdkError{values[0].Code}
		}
		return values[0].Value, nil
	}
}
