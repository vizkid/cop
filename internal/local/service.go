package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
)

type entry struct {
	value   *secret
	expires time.Time
	jobID   uint64
}

type job struct {
	JobStatus
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type Service struct {
	mu       sync.Mutex
	home     string
	config   config
	resolve  Resolver
	ttl      time.Duration
	timeout  time.Duration
	cache    map[Key]entry
	inflight map[Key]*job
	queue    []*job
	history  []*job
	nextID   uint64
	wake     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
}

func New(home string, resolver Resolver, ttl, timeout time.Duration) (*Service, error) {
	if resolver == nil || ttl <= 0 || ttl > time.Hour || timeout <= 0 || timeout > 5*time.Minute {
		return nil, errors.New("TTL must be positive and at most 1h; op timeout must be positive and at most 5m")
	}
	c, err := loadConfig(home)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{home: home, config: c, resolve: resolver, ttl: ttl, timeout: timeout,
		cache: map[Key]entry{}, inflight: map[Key]*job{}, wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
	s.wg.Add(2)
	go s.work()
	go s.expire()
	return s, nil
}

func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.invalidateLocked(func(Key) bool { return true })
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) allowedLocked(k Key) bool { return slices.Contains(s.config.Projects[k.Project], k) }

func (s *Service) Handle(ctx context.Context, r Request) Result {
	if r.Action == "sign" {
		return s.sign(ctx, r)
	}
	if r.Action == "deliver" && r.Use == "ssh-sign" {
		return Result{Error: "signing keys cannot be read or exported"}
	}
	if r.Action == "request" || r.Action == "deliver" {
		return s.fetch(ctx, r.Key, r.Action == "deliver")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Result{Error: "service stopped"}
	}
	s.pruneLocked()
	if r.Action == "status" {
		return Result{View: s.statusLocked()}
	}
	if !ValidProjectName(r.Project) {
		return Result{Error: "invalid project name"}
	}
	_, exists := s.config.Projects[r.Project]
	if r.Action != "create" && !exists {
		return Result{Error: "unknown project"}
	}
	if r.Action == "clear" {
		s.invalidateLocked(func(k Key) bool { return k.Project == r.Project })
		return Result{Status: "cleared"}
	}
	next := config{Version: 1, Projects: make(map[string][]Key, len(s.config.Projects))}
	for name, keys := range s.config.Projects {
		next.Projects[name] = slices.Clone(keys)
	}
	switch r.Action {
	case "create":
		if exists {
			return Result{Error: "project already exists"}
		}
		next.Projects[r.Project] = []Key{}
	case "allow", "revoke":
		if err := r.Key.Validate(); err != nil {
			return Result{Error: err.Error()}
		}
		if r.Action == "allow" {
			if !s.allowedLocked(r.Key) {
				next.Projects[r.Project] = append(next.Projects[r.Project], r.Key)
			}
		} else {
			next.Projects[r.Project] = slices.DeleteFunc(next.Projects[r.Project], func(k Key) bool { return k == r.Key })
		}
	default:
		return Result{Error: "unknown action"}
	}
	if !separateSigningUses(next) {
		return Result{Error: "a signing reference cannot also be readable"}
	}
	if err := saveConfig(s.home, next); err != nil {
		s.closed = true
		s.cancel()
		s.invalidateLocked(func(Key) bool { return true })
		return Result{Error: "configuration save failed; service refuses further access until restart"}
	}
	s.config = next
	if r.Action == "revoke" {
		s.invalidateLocked(func(k Key) bool { return k == r.Key })
	}
	return Result{Status: r.Action + " completed"}
}

func (s *Service) fetch(ctx context.Context, k Key, deliver bool) Result {
	if err := k.Validate(); err != nil {
		return Result{Error: err.Error()}
	}
	s.mu.Lock()
	s.pruneLocked()
	if s.closed || !s.allowedLocked(k) {
		s.mu.Unlock()
		return Result{Error: "reference is not authorized for this project and account"}
	}
	if e, ok := s.cache[k]; ok {
		r := delivery(e, deliver, "cached")
		s.mu.Unlock()
		return r
	}
	j := s.inflight[k]
	if j == nil {
		if len(s.inflight) >= 64 || len(s.queue) >= 64 {
			s.mu.Unlock()
			return Result{Error: "resolution queue is full"}
		}
		s.nextID++
		jobCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
		j = &job{JobStatus: JobStatus{ID: s.nextID, Key: k, State: "queued", Created: time.Now().UTC()},
			ctx: jobCtx, cancel: cancel, done: make(chan struct{})}
		s.inflight[k] = j
		s.queue = append(s.queue, j)
		s.history = append(s.history, j)
		s.trimHistoryLocked()
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return Result{Error: "request canceled"}
	case <-j.done:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if j.State != "resolved" {
		return Result{Error: j.Reason}
	}
	if e, ok := s.cache[k]; ok && e.jobID == j.ID && s.allowedLocked(k) && !s.closed {
		return delivery(e, deliver, "resolved")
	}
	return Result{Error: "cache expired or was cleared; retry the request"}
}

func delivery(e entry, deliver bool, state string) Result {
	r := Result{Status: state}
	if deliver {
		r.Value = bytes.Clone(e.value.pages[:e.value.size])
	}
	return r
}

func (s *Service) finishLocked(j *job, reason string) {
	if j.State == "resolved" || j.State == "failed" {
		return
	}
	j.cancel()
	j.State, j.Reason = "resolved", reason
	if reason != "" {
		j.State = "failed"
	}
	if s.inflight[j.Key] == j {
		delete(s.inflight, j.Key)
	}
	close(j.done)
}

func (s *Service) invalidateLocked(match func(Key) bool) {
	for k, e := range s.cache {
		if match(k) {
			e.value.destroy()
			delete(s.cache, k)
		}
	}
	for k, j := range s.inflight {
		if match(k) {
			s.finishLocked(j, "request invalidated")
		}
	}
}

func (s *Service) pruneLocked() {
	for k, e := range s.cache {
		if !time.Now().Before(e.expires) {
			e.value.destroy()
			delete(s.cache, k)
		}
	}
}

func (s *Service) expire() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			s.pruneLocked()
			for _, j := range s.inflight {
				if j.ctx.Err() != nil {
					s.finishLocked(j, "op resolution canceled or timed out")
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Service) work() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			if len(s.queue) == 0 || s.closed {
				s.mu.Unlock()
				break
			}
			j := s.queue[0]
			s.queue[0] = nil
			s.queue = s.queue[1:]
			if j.State != "queued" {
				s.mu.Unlock()
				continue
			}
			if j.ctx.Err() != nil {
				s.finishLocked(j, "op resolution canceled or timed out")
				s.mu.Unlock()
				continue
			}
			j.State = "active"
			s.mu.Unlock()
			value, err := s.resolve(j.ctx, j.Key)
			if err == nil && j.Use == "ssh-sign" {
				private, parseErr := parseSigningKey(value, j.PublicKey)
				clear(private)
				if parseErr != nil {
					err = fmt.Errorf("%w: %s", errSigningIdentity, parseErr)
				}
			}
			s.mu.Lock()
			if j.State == "active" {
				s.pruneLocked()
				switch {
				case j.ctx.Err() != nil:
					s.finishLocked(j, "op resolution canceled or timed out")
				case err != nil:
					// Resolver errors are untrusted and can contain credential values.
					reason := "resolution failed; check authentication and the exact reference"
					if errors.Is(err, errSigningIdentity) {
						reason = err.Error()
					}
					var sdkErr *sdkError
					if errors.As(err, &sdkErr) {
						reason = sdkErr.Error()
					}
					s.finishLocked(j, reason)
				case len(value) > MaxSecret || bytes.IndexByte(value, 0) >= 0:
					s.finishLocked(j, "secret exceeds delivery limits")
				case len(s.cache) >= 128:
					s.finishLocked(j, "cache is full; clear a project")
				default:
					stored, memErr := keep(value)
					if memErr != nil {
						s.finishLocked(j, "secret memory unavailable")
					} else {
						s.cache[j.Key] = entry{stored, time.Now().Add(s.ttl), j.ID}
						s.finishLocked(j, "")
					}
				}
			}
			clear(value)
			s.mu.Unlock()
		}
	}
}

func (s *Service) trimHistoryLocked() {
	for len(s.history) > 128 {
		for i, j := range s.history {
			if j.State == "resolved" || j.State == "failed" {
				s.history = slices.Delete(s.history, i, i+1)
				break
			}
		}
	}
}
func (s *Service) statusLocked() *Status {
	v := &Status{Projects: map[string][]Key{}, Requests: []JobStatus{}, Cache: []Cached{}}
	for p, keys := range s.config.Projects {
		v.Projects[p] = append([]Key{}, keys...)
	}
	for _, j := range s.history {
		v.Requests = append(v.Requests, j.JobStatus)
	}
	for k, e := range s.cache {
		v.Cache = append(v.Cache, Cached{k, e.expires.UTC()})
	}
	sort.Slice(v.Cache, func(i, j int) bool {
		a, b := v.Cache[i].Key, v.Cache[j].Key
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Account != b.Account {
			return a.Account < b.Account
		}
		return a.Ref < b.Ref
	})
	return v
}
