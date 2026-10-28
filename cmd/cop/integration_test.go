package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vizkid/cop/internal/local"
)

const fakeValue = "integration-secret-671823-never-log"

type harness struct {
	t                      *testing.T
	root, home, binary, op string
	env                    []string
	logs                   bytes.Buffer
	command                *exec.Cmd
	cancel                 context.CancelFunc
	done                   chan error
	backend                string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	// Keep socket names below the Unix socket path limit on macOS too.
	root, err := os.MkdirTemp("", "cop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	h := &harness{t: t, root: root, home: filepath.Join(root, "h"), binary: filepath.Join(root, "cop"), op: filepath.Join(root, "fake-op")}
	build := exec.Command("go", "build", "-race", "-o", h.binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	script := `#!/bin/sh
if [ "$1" != read ] || [ "$2" != --account ] || [ "$4" != --no-newline ] || [ "$5" != --cache=false ]; then exit 90; fi
if [ "$OP_DEBUG" != false ] || [ -n "$OP_SERVICE_ACCOUNT_TOKEN" ]; then exit 91; fi
if ! mkdir "$COP_FAKE_DIR/active" 2>/dev/null; then echo concurrent >> "$COP_FAKE_DIR/calls"; exit 92; fi
trap 'rmdir "$COP_FAKE_DIR/active"' EXIT
printf '%s %s\n' "$3" "$6" >> "$COP_FAKE_DIR/calls"
case "$6" in
  */slow) sleep 0.2 ;;
  */failure) printf '%s' "$COP_FAKE_VALUE"; printf '%s' "$COP_FAKE_VALUE" >&2; exit 9 ;;
esac
printf '%s' "$COP_FAKE_VALUE"
`
	if err := os.WriteFile(h.op, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "COP_") && !strings.HasPrefix(e, "OP_") && !strings.HasPrefix(e, "REX_") && !strings.HasPrefix(e, "GORACE=") {
			h.env = append(h.env, e)
		}
	}
	h.env = append(h.env, "COP_HOME="+h.home, "COP_FAKE_DIR="+root, "COP_FAKE_VALUE="+fakeValue, "OP_DEBUG=true", "OP_SERVICE_ACCOUNT_TOKEN=fake-ambient", "GORACE=atexit_sleep_ms=0")
	t.Cleanup(func() {
		if h.command != nil {
			h.stop()
		}
	})
	return h
}

func (h *harness) start() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.command = exec.CommandContext(ctx, h.binary, "serve", "--op", h.op, "--ttl", "2s", "--op-timeout", "3s")
	if h.backend == "sdk" {
		h.command = exec.CommandContext(ctx, h.binary, "serve", "--resolver", "sdk", "--sdk-worker", h.op, "--ttl", "2s", "--op-timeout", "3s")
	}
	h.command.Env = h.env
	h.command.Stdout = &h.logs
	h.command.Stderr = &h.logs
	if err := h.command.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.done = make(chan error, 1)
	go func() { h.done <- h.command.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-h.done:
			h.command = nil
			h.t.Fatalf("service startup failed: %v", err)
		default:
		}
		c := exec.Command(h.binary, "status")
		c.Env = h.env
		if c.Run() == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("service did not become ready")
}

func (h *harness) stop() {
	h.t.Helper()
	if h.command == nil {
		return
	}
	_ = h.command.Process.Signal(os.Interrupt)
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("service stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		h.cancel()
		<-h.done
		h.t.Error("service shutdown timed out")
	}
	h.cancel()
	h.command = nil
	if bytes.Contains(h.logs.Bytes(), []byte(fakeValue)) {
		h.t.Fatal("service logged a secret")
	}
	if bytes.Contains(h.logs.Bytes(), []byte("DATA RACE")) {
		h.t.Fatal("service data race")
	}
}

func (h *harness) cli(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, h.binary, args...)
	c.Env = h.env
	return c.CombinedOutput()
}

func (h *harness) ok(args ...string) []byte {
	h.t.Helper()
	out, err := h.cli(args...)
	if bytes.Contains(out, []byte(fakeValue)) {
		h.t.Fatal("CLI leaked a secret")
	}
	if err != nil {
		h.t.Fatalf("command %s failed: %v: %s", args[0], err, out)
	}
	return out
}

func (h *harness) count() int {
	data, err := os.ReadFile(filepath.Join(h.root, "calls"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	if bytes.Contains(data, []byte("concurrent")) {
		h.t.Fatal("overlapping op processes")
	}
	return bytes.Count(data, []byte("\n"))
}

func (h *harness) view() local.Status {
	h.t.Helper()
	var v local.Status
	if err := json.Unmarshal(h.ok("status"), &v); err != nil {
		h.t.Fatal(err)
	}
	return v
}

func keyArgs(action, project, ref string) []string {
	return []string{action, "--project", project, "--account", "test-account", "--ref", ref}
}

func TestLocalMilestoneEndToEnd(t *testing.T) {
	for _, backend := range []string{"op", "sdk"} {
		t.Run(backend, func(t *testing.T) { localMilestone(t, backend) })
	}
}

func useFakeSDK(t *testing.T, h *harness) {
	t.Helper()
	h.backend = "sdk"
	script := `#!/bin/sh
input=$(cat)
case "$input" in *'"account":"test-account"'*) ;; *) exit 90 ;; esac
if ! mkdir "$COP_FAKE_DIR/active" 2>/dev/null; then echo concurrent >> "$COP_FAKE_DIR/calls"; exit 92; fi
trap 'rmdir "$COP_FAKE_DIR/active"' EXIT
echo invocation >> "$COP_FAKE_DIR/calls"
echo discarded-worker-log
case "$input" in
 */slow*) sleep 0.2 ;;
 */failure*) printf '%s' "$COP_FAKE_VALUE" >&3; printf '%s' "$COP_FAKE_VALUE" >&2; exit 9 ;;
esac
printf '%s' "$COP_FAKE_VALUE" >&3
`
	if err := os.WriteFile(h.op, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

func localMilestone(t *testing.T, backend string) {
	h := newHarness(t)
	if backend == "sdk" {
		useFakeSDK(t, h)
	}
	h.start()
	ref := "op://fixture/item/token"
	h.ok("project", "create", "alpha")
	h.ok("project", "create", "beta")
	if len(h.view().Projects["alpha"]) != 0 {
		t.Fatal("project not initially empty")
	}
	if _, err := h.cli(keyArgs("request", "alpha", ref)...); err == nil {
		t.Fatal("unapproved request succeeded")
	}
	if h.count() != 0 {
		t.Fatal("unapproved request invoked op")
	}
	h.ok(keyArgs("allow", "alpha", ref)...)
	h.ok(keyArgs("request", "alpha", ref)...)
	args := append(keyArgs("run", "alpha", ref), "--env", "TEST_TOKEN", "--", "sh", "-c", `test "$TEST_TOKEN" = "$COP_FAKE_VALUE"`)
	h.ok(args...)
	h.ok(args...)
	if h.count() != 1 {
		t.Fatal("run did not reuse cache")
	}
	if _, err := h.cli(keyArgs("request", "beta", ref)...); err == nil {
		t.Fatal("project isolation failed")
	}
	wrong := keyArgs("request", "alpha", ref)
	wrong[4] = "other-account"
	if _, err := h.cli(wrong...); err == nil {
		t.Fatal("account isolation failed")
	}
	if h.count() != 1 {
		t.Fatal("denied call invoked op")
	}
	h.ok("clear", "--project", "alpha")
	h.ok(args...)
	if h.count() != 2 {
		t.Fatal("clear did not force miss")
	}
	h.ok(keyArgs("revoke", "alpha", ref)...)
	if _, err := h.cli(args...); err == nil {
		t.Fatal("revoked ref delivered")
	}
	h.ok(keyArgs("allow", "alpha", ref)...)
	h.ok(args...)
	if h.count() != 3 {
		t.Fatal("revoke retained cache")
	}
	// Process startup cannot recover a secret from disk.
	h.stop()
	h.start()
	if len(h.view().Cache) != 0 {
		t.Fatal("restart retained cache")
	}
	h.ok(args...)
	if h.count() != 4 {
		t.Fatal("restart did not invoke op")
	}
	// An abrupt exit leaves a stale socket, but no persistent secret cache.
	if err := h.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-h.done
	h.cancel()
	h.command = nil
	h.start()
	if len(h.view().Cache) != 0 {
		t.Fatal("crash retained cache")
	}
	h.ok(args...)
	if h.count() != 5 {
		t.Fatal("crash recovery did not invoke op")
	}
	// Let a real clock deadline pass; hits do not renew it.
	time.Sleep(2100 * time.Millisecond)
	h.ok(args...)
	if h.count() != 6 {
		t.Fatal("expired cache reused")
	}
	exitArgs := append(keyArgs("run", "alpha", ref), "--env", "TEST_TOKEN", "--", "sh", "-c", "exit 37")
	if _, err := h.cli(exitArgs...); err == nil {
		t.Fatal("child exit status lost")
	} else if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 37 {
		t.Fatal("child exit status changed")
	}
	failure := "op://fixture/item/failure"
	h.ok(keyArgs("allow", "alpha", failure)...)
	out, err := h.cli(keyArgs("request", "alpha", failure)...)
	if err == nil || bytes.Contains(out, []byte(fakeValue)) {
		t.Fatal("op failure was not redacted")
	}
	marker := filepath.Join(h.root, "child-started")
	failArgs := append(keyArgs("run", "alpha", failure), "--env", "TEST_TOKEN", "--", "sh", "-c", `: > "$1"`, "sh", marker)
	if _, err := h.cli(failArgs...); err == nil {
		t.Fatal("failed resolution launched a child")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("child ran after resolution failed")
	}
	if v := h.view(); v.Requests[len(v.Requests)-1].State != "failed" {
		t.Fatal("failure not visible")
	}
	for _, name := range []string{"projects.json", "service.sock", "service.lock"} {
		info, err := os.Stat(filepath.Join(h.home, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("wrong permissions on %s", name)
		}
	}
	info, _ := os.Stat(h.home)
	if info.Mode().Perm() != 0700 {
		t.Fatal("home not private")
	}
	// A second daemon must leave the first daemon and its socket intact.
	out, err = h.cli("serve", "--op", h.op)
	if err == nil || !bytes.Contains(out, []byte("already owns")) {
		t.Fatal("duplicate service accepted")
	}
	h.ok("status")
	h.stop()
	if err := filepath.WalkDir(h.home, func(path string, d os.DirEntry, err error) error {
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
		if bytes.Contains(data, []byte(fakeValue)) {
			t.Error("secret persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeOPConcurrencyThroughSocket(t *testing.T) {
	for _, backend := range []string{"op", "sdk"} {
		t.Run(backend, func(t *testing.T) { concurrencyThroughSocket(t, backend) })
	}
}

func concurrencyThroughSocket(t *testing.T, backend string) {
	h := newHarness(t)
	if backend == "sdk" {
		useFakeSDK(t, h)
	}
	h.start()
	h.ok("project", "create", "alpha")
	refs := []string{"op://fixture/first/slow", "op://fixture/second/slow"}
	for _, ref := range refs {
		h.ok(keyArgs("allow", "alpha", ref)...)
	}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := h.cli(keyArgs("request", "alpha", refs[i%2])...)
			if bytes.Contains(out, []byte(fakeValue)) {
				results <- os.ErrInvalid
				return
			}
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent request failed: %v", err)
		}
	}
	if h.count() != 2 {
		t.Fatal("concurrent requests not coalesced")
	}
}

func TestUnsafeEnvironmentNames(t *testing.T) {
	for _, name := range []string{"PATH", "LD_PRELOAD", "OP_ACCOUNT", "COP_HOME", "a=b", ""} {
		if safeEnv(name) {
			t.Fatalf("accepted %q", name)
		}
	}
	if !safeEnv("API_TOKEN") {
		t.Fatal("ordinary variable refused")
	}
}
