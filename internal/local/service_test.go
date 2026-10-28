package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testKey = Key{Project: "alpha", Account: "test-account", Ref: "op://test/item/token"}

const sentinel = "synthetic-secret-never-log-7319"

func newTestService(t *testing.T, resolve Resolver, ttl time.Duration) *Service {
	t.Helper()
	home := t.TempDir()
	s, err := New(home, resolve, ttl, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func handle(t *testing.T, s *Service, action string, k Key) Result {
	t.Helper()
	r := s.Handle(context.Background(), Request{Action: action, Key: k})
	if r.Error != "" {
		t.Fatalf("%s: %s", action, r.Error)
	}
	return r
}

func authorize(t *testing.T, s *Service, k Key) {
	t.Helper()
	if _, ok := handle(t, s, "status", Key{}).View.Projects[k.Project]; !ok {
		handle(t, s, "create", Key{Project: k.Project})
	}
	handle(t, s, "allow", k)
}

func TestAuthorizationExpiryInvalidationAndPersistence(t *testing.T) {
	var calls atomic.Int32
	resolver := func(context.Context, Key) ([]byte, error) { calls.Add(1); return []byte(sentinel), nil }
	s := newTestService(t, resolver, time.Minute)
	handle(t, s, "create", Key{Project: testKey.Project})
	if got := handle(t, s, "status", Key{}).View.Projects[testKey.Project]; len(got) != 0 {
		t.Fatal("new project not empty")
	}
	if r := s.Handle(context.Background(), Request{Action: "deliver", Key: testKey}); r.Error == "" {
		t.Fatal("empty project authorized")
	}
	authorize(t, s, testKey)
	if r := handle(t, s, "request", testKey); len(r.Value) != 0 {
		t.Fatal("prewarm exposed secret")
	}
	if r := handle(t, s, "deliver", testKey); string(r.Value) != sentinel || r.Status != "cached" {
		t.Fatal("cache delivery failed")
	}
	for _, k := range []Key{
		{Project: "beta", Account: testKey.Account, Ref: testKey.Ref},
		{Project: testKey.Project, Account: "other", Ref: testKey.Ref},
		{Project: testKey.Project, Account: testKey.Account, Ref: "op://test/item/other"},
	} {
		if r := s.Handle(context.Background(), Request{Action: "deliver", Key: k}); r.Error == "" {
			t.Fatal("authorization crossed identity")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("cache miss or unauthorized op call")
	}
	view := handle(t, s, "status", Key{}).View
	data, _ := json.Marshal(view)
	if bytes.Contains(data, []byte(sentinel)) {
		t.Fatal("status leaked value")
	}
	before := view.Cache[0].Expires
	handle(t, s, "request", testKey)
	if !handle(t, s, "status", Key{}).View.Cache[0].Expires.Equal(before) {
		t.Fatal("hit extended expiry")
	}
	// Advance the stored deadline without wall-clock sleeps.
	s.mu.Lock()
	e := s.cache[testKey]
	e.expires = time.Now().Add(-time.Second)
	s.cache[testKey] = e
	s.mu.Unlock()
	handle(t, s, "request", testKey)
	if calls.Load() != 2 {
		t.Fatal("expired value reused")
	}
	handle(t, s, "clear", Key{Project: "alpha"})
	handle(t, s, "request", testKey)
	if calls.Load() != 3 {
		t.Fatal("clear did not invalidate")
	}
	handle(t, s, "revoke", testKey)
	if len(handle(t, s, "status", Key{}).View.Cache) != 0 {
		t.Fatal("revoke retained value")
	}
	if s.Handle(context.Background(), Request{Action: "request", Key: testKey}).Error == "" {
		t.Fatal("revoked key served")
	}
	authorize(t, s, testKey)
	handle(t, s, "request", testKey)
	s.Close()
	restarted, err := New(s.home, resolver, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if len(handle(t, restarted, "status", Key{}).View.Cache) != 0 {
		t.Fatal("cache survived restart")
	}
	handle(t, restarted, "request", testKey)
	if calls.Load() != 5 {
		t.Fatal("restart did not resolve again")
	}
	if err := filepath.WalkDir(s.home, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(sentinel)) {
			t.Errorf("secret persisted in %s", d.Name())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRequestsCoalesceAndSerialize(t *testing.T) {
	started := make(chan Key, 4)
	release := make(chan struct{}, 4)
	var active, peak, calls atomic.Int32
	s := newTestService(t, func(ctx context.Context, k Key) ([]byte, error) {
		calls.Add(1)
		n := active.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		defer active.Add(-1)
		started <- k
		select {
		case <-release:
			return []byte(sentinel), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, time.Minute)
	other := testKey
	other.Ref = "op://test/item/second"
	authorize(t, s, testKey)
	authorize(t, s, other)
	var wg sync.WaitGroup
	results := make(chan Result, 21)
	launch := func(k Key) {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.Handle(context.Background(), Request{Action: "request", Key: k}) }()
	}
	launch(testKey)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	for i := 0; i < 19; i++ {
		launch(testKey)
	}
	launch(other)
	waitFor(t, func() bool {
		v := handle(t, s, "status", Key{}).View
		return len(v.Requests) == 2 && v.Requests[1].State == "queued"
	})
	v := handle(t, s, "status", Key{}).View
	if v.Requests[0].State != "active" {
		t.Fatal("active status missing")
	}
	release <- struct{}{}
	select {
	case got := <-started:
		if got != other {
			t.Fatal("unexpected queued key")
		}
	case <-time.After(time.Second):
		t.Fatal("second worker did not start")
	}
	release <- struct{}{}
	wg.Wait()
	close(results)
	for r := range results {
		if r.Error != "" || len(r.Value) != 0 {
			t.Fatal("coalesced request failed or exposed value")
		}
	}
	if calls.Load() != 2 || peak.Load() != 1 {
		t.Fatal("resolutions not serialized/coalesced")
	}
	for _, j := range handle(t, s, "status", Key{}).View.Requests {
		if j.State != "resolved" {
			t.Fatal("missing resolved status")
		}
	}
}

func TestInvalidationFencesLateResolverAndFailureIsRedacted(t *testing.T) {
	for _, action := range []string{"clear", "revoke"} {
		t.Run(action, func(t *testing.T) {
			started, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			s := newTestService(t, func(context.Context, Key) ([]byte, error) {
				close(started)
				<-release
				defer close(returned)
				return []byte(sentinel), nil
			}, time.Minute)
			authorize(t, s, testKey)
			result := make(chan Result, 1)
			go func() { result <- s.Handle(context.Background(), Request{Action: "request", Key: testKey}) }()
			<-started
			handle(t, s, action, testKey)
			if r := <-result; r.Error == "" {
				t.Fatal("invalidated request succeeded")
			}
			close(release)
			<-returned
			s.Close()
			if len(s.cache) != 0 {
				t.Fatal("late result repopulated cache")
			}
		})
	}
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), errors.New(sentinel) }, time.Minute)
	authorize(t, s, testKey)
	r := s.Handle(context.Background(), Request{Action: "request", Key: testKey})
	if r.Error == "" || strings.Contains(r.Error, sentinel) || len(r.Value) > 0 {
		t.Fatal("failure leaked")
	}
	v := handle(t, s, "status", Key{}).View
	data, _ := json.Marshal(v)
	if bytes.Contains(data, []byte(sentinel)) || v.Requests[0].State != "failed" {
		t.Fatal("failed status unsafe")
	}
}

func TestExpiryPrunesIdleCache(t *testing.T) {
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), nil }, 20*time.Millisecond)
	authorize(t, s, testKey)
	handle(t, s, "request", testKey)
	waitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.cache) == 0 })
}

func TestConfigurationAndReferenceRefusals(t *testing.T) {
	for _, ref := range []string{"op://test/item/*", "op://test/item/token?attribute=otp", "op://test/item/private_key", "op://test/item/private%20key", "op://test/item/%00", "op://test/item/%xx", "op://test/item"} {
		k := testKey
		k.Ref = ref
		if k.Validate() == nil {
			t.Fatalf("accepted invalid ref: %q", ref)
		}
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "projects.json"), []byte(`{"version":1,"projects":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(home, func(context.Context, Key) ([]byte, error) { return nil, nil }, time.Minute, time.Second); err == nil {
		t.Fatal("malformed config accepted")
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func TestDeadlineBoundsActiveAndQueuedRequests(t *testing.T) {
	home := t.TempDir()
	var calls atomic.Int32
	s, err := New(home, func(ctx context.Context, k Key) ([]byte, error) { calls.Add(1); <-ctx.Done(); return nil, ctx.Err() }, time.Minute, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other := testKey
	other.Ref = "op://test/item/second"
	authorize(t, s, testKey)
	authorize(t, s, other)
	results := make(chan Result, 2)
	go func() { results <- s.Handle(context.Background(), Request{Action: "request", Key: testKey}) }()
	waitFor(t, func() bool { return calls.Load() == 1 })
	go func() { results <- s.Handle(context.Background(), Request{Action: "request", Key: other}) }()
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.Error == "" {
				t.Fatal("deadline allowed a value")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("deadline did not release caller")
		}
	}
	if len(handle(t, s, "status", Key{}).View.Cache) != 0 {
		t.Fatal("timed out result cached")
	}
}

func TestSaveFailureStopsServing(t *testing.T) {
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), nil }, time.Minute)
	authorize(t, s, testKey)
	handle(t, s, "request", testKey)
	// Force rename to fail without relying on permissions that root can bypass.
	path := filepath.Join(s.home, "projects.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if r := s.Handle(context.Background(), Request{Action: "revoke", Key: testKey}); r.Error == "" {
		t.Fatal("failed persistence accepted")
	}
	if r := s.Handle(context.Background(), Request{Action: "deliver", Key: testKey}); r.Error == "" {
		t.Fatal("served after uncertain configuration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) != 0 {
		t.Fatal("save failure retained secrets")
	}
}

func TestStartupLoadsSavedKeysAndContinuesAfterFailure(t *testing.T) {
	home := t.TempDir()
	keys := []Key{testKey, {Project: "beta", Account: testKey.Account, Ref: testKey.Ref}}
	if err := saveConfig(home, config{Version: 1, Projects: map[string][]Key{"alpha": {keys[0]}, "beta": {keys[1]}}}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	s, err := New(home, func(_ context.Context, k Key) ([]byte, error) {
		calls.Add(1)
		if k.Project == "alpha" {
			return nil, errors.New(sentinel)
		}
		return []byte(sentinel), nil
	}, time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.preload()
	if got := handle(t, s, "request", keys[1]); len(got.Value) != 0 {
		t.Fatal("startup exposed value")
	}
	if calls.Load() != 2 {
		t.Fatal("startup skipped a key or duplicated concurrent request")
	}
	view := handle(t, s, "status", Key{}).View
	if len(view.Cache) != 1 || view.Cache[0].Project != "beta" || view.Requests[0].State != "failed" {
		t.Fatal("incorrect startup status")
	}
	data, _ := json.Marshal(view)
	if bytes.Contains(data, []byte(sentinel)) {
		t.Fatal("startup leaked resolver output")
	}
	handle(t, s, "clear", Key{Project: "beta"})
	if len(handle(t, s, "status", Key{}).View.Cache) != 0 {
		t.Fatal("clear failed")
	}
}

func TestStartupClearCancelsQueuedKeys(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := newTestService(t, func(ctx context.Context, _ Key) ([]byte, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return []byte(sentinel), nil
	}, time.Minute)
	authorize(t, s, testKey)
	other := testKey
	other.Ref = "op://test/item/other"
	authorize(t, s, other)
	s.preload()
	<-started
	view := handle(t, s, "status", Key{}).View
	if view.Requests[0].State != "active" || view.Requests[1].State != "queued" {
		t.Fatal("startup progress missing")
	}
	handle(t, s, "clear", Key{Project: "alpha"})
	close(release)
	s.Close()
	if calls.Load() != 1 || len(s.cache) != 0 {
		t.Fatal("clear allowed startup refill")
	}
}

func TestStartupLargeAllowlistDoesNotStall(t *testing.T) {
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, errors.New(sentinel) }, time.Minute)
	s.mu.Lock()
	for i := 0; i < 140; i++ {
		k := testKey
		k.Ref = fmt.Sprintf("op://test/item/field%d", i)
		s.config.Projects[k.Project] = append(s.config.Projects[k.Project], k)
	}
	s.mu.Unlock()
	s.preload()
	s.mu.Lock()
	last := s.history[len(s.history)-1]
	s.mu.Unlock()
	select {
	case <-last.done:
	case <-time.After(5 * time.Second):
		t.Fatal("startup stalled")
	}
	view := handle(t, s, "status", Key{}).View
	if len(view.Requests) != 128 || view.Requests[127].State != "failed" {
		t.Fatal("startup history bound failed")
	}
}

func TestExpiryRefillsOnlyRequestedProject(t *testing.T) {
	var mu sync.Mutex
	calls := map[Key]int{}
	s := newTestService(t, func(_ context.Context, k Key) ([]byte, error) {
		mu.Lock()
		calls[k]++
		mu.Unlock()
		return []byte(sentinel), nil
	}, 7*24*time.Hour)
	a := testKey
	b := testKey
	b.Ref = "op://test/item/second"
	other := testKey
	other.Project = "beta"
	expiredOther := other
	expiredOther.Ref = "op://test/item/expired"
	for _, k := range []Key{a, b, other, expiredOther} {
		authorize(t, s, k)
		handle(t, s, "request", k)
	}
	s.mu.Lock()
	otherDeadline := s.cache[other].expires
	for _, k := range []Key{a, expiredOther} {
		e := s.cache[k]
		e.expires = time.Now().Add(-time.Second)
		s.cache[k] = e
	}
	s.pruneLocked()
	s.mu.Unlock()
	// A status poll erases expired material without contacting the resolver.
	handle(t, s, "status", Key{})
	mu.Lock()
	count := calls[a]
	mu.Unlock()
	if count != 1 {
		t.Fatal("expiry refreshed without request")
	}
	handle(t, s, "request", a)
	handle(t, s, "request", b)
	s.mu.Lock()
	if !s.cache[other].expires.Equal(otherDeadline) || !s.expired[expiredOther] {
		t.Fatal("refill changed another project")
	}
	if _, ok := s.cache[expiredOther]; ok {
		t.Fatal("other expired key was reloaded")
	}
	s.mu.Unlock()
	mu.Lock()
	if calls[a] != 2 || calls[b] != 2 || calls[other] != 1 || calls[expiredOther] != 1 {
		t.Fatal("wrong refill scope")
	}
	mu.Unlock()
	handle(t, s, "request", expiredOther)
	handle(t, s, "request", other)
	mu.Lock()
	defer mu.Unlock()
	if calls[other] != 2 || calls[expiredOther] != 2 {
		t.Fatal("second project did not refill on request")
	}
}

func TestCacheLifetimeConfigurableBeyondSevenDays(t *testing.T) {
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), nil }, 30*24*time.Hour)
	authorize(t, s, testKey)
	handle(t, s, "request", testKey)
	if time.Until(handle(t, s, "status", Key{}).View.Cache[0].Expires) < 29*24*time.Hour {
		t.Fatal("configured lifetime not used")
	}
}

func TestBatchRefillGroupsProjectAccounts(t *testing.T) {
	var mu sync.Mutex
	batches := map[[2]string]int{}
	s := newTestService(t, func(context.Context, Key) ([]byte, error) {
		t.Error("single resolution during refill")
		return nil, nil
	}, time.Hour)
	s.batch = func(_ context.Context, keys []Key) ([]BatchValue, error) {
		group := [2]string{keys[0].Project, keys[0].Account}
		mu.Lock()
		batches[group]++
		mu.Unlock()
		values := make([]BatchValue, len(keys))
		for i, k := range keys {
			if k.Project != group[0] || k.Account != group[1] {
				t.Error("mixed batch")
			}
			values[i].Value = []byte(sentinel)
		}
		return values, nil
	}
	second := testKey
	second.Ref = "op://test/item/second"
	account := testKey
	account.Account = "other"
	project := testKey
	project.Project = "beta"
	for _, k := range []Key{testKey, second, account, project} {
		authorize(t, s, k)
	}
	s.preload()
	for _, k := range []Key{testKey, second, account, project} {
		handle(t, s, "request", k)
	}
	mu.Lock()
	if len(batches) != 3 {
		t.Fatal("startup did not group accounts and projects")
	}
	for _, count := range batches {
		if count != 1 {
			t.Fatal("repeated auth")
		}
	}
	mu.Unlock()
	s.mu.Lock()
	e := s.cache[testKey]
	e.expires = time.Now().Add(-time.Second)
	s.cache[testKey] = e
	s.mu.Unlock()
	handle(t, s, "request", testKey)
	handle(t, s, "request", second)
	handle(t, s, "request", account)
	mu.Lock()
	defer mu.Unlock()
	if batches[[2]string{"alpha", testKey.Account}] != 2 || batches[[2]string{"alpha", "other"}] != 2 || batches[[2]string{"beta", testKey.Account}] != 1 {
		t.Fatal("refill scope incorrect")
	}
}

func TestBatchClearFencesLateResults(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	s := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, nil }, time.Hour)
	s.batch = func(ctx context.Context, keys []Key) ([]BatchValue, error) {
		close(started)
		<-release
		values := make([]BatchValue, len(keys))
		for i := range values {
			values[i].Value = []byte(sentinel)
		}
		return values, nil
	}
	authorize(t, s, testKey)
	other := testKey
	other.Ref = "op://test/item/other"
	authorize(t, s, other)
	s.preload()
	<-started
	handle(t, s, "clear", Key{Project: testKey.Project})
	close(release)
	s.Close()
	if len(s.cache) != 0 {
		t.Fatal("cleared batch refilled cache")
	}
}

func TestFailedBatchRetryRemainsBatched(t *testing.T) {
	s := newTestService(t, func(context.Context, Key) ([]byte, error) {
		t.Error("batch retry used single resolver")
		return nil, nil
	}, time.Hour)
	var calls atomic.Int32
	s.batch = func(_ context.Context, keys []Key) ([]BatchValue, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("authorization canceled")
		}
		if len(keys) != 2 {
			t.Error("retry lost project keys")
		}
		values := make([]BatchValue, len(keys))
		for i := range values {
			values[i].Value = []byte(sentinel)
		}
		return values, nil
	}
	authorize(t, s, testKey)
	other := testKey
	other.Ref = "op://test/item/other"
	authorize(t, s, other)
	s.preload()
	s.mu.Lock()
	done := s.history[len(s.history)-1].done
	s.mu.Unlock()
	<-done
	handle(t, s, "request", testKey)
	handle(t, s, "request", other)
	if calls.Load() != 2 {
		t.Fatal("unexpected batch retry count")
	}
}
