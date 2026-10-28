package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vizkid/cop/internal/rexcontext"
)

const rexSession = "session:11111111-1111-7111-8111-111111111111"
const rexBlock = "block:22222222-2222-7222-8222-222222222222"
const secondRexBlock = "block:33333333-3333-7333-8333-333333333333"

func TestRexContextAndLocalOperations(t *testing.T) {
	h := newHarness(t)
	standaloneEnv := append([]string{}, h.env...)
	if out := h.ok("context"); !strings.Contains(string(out), `"standalone"`) {
		t.Fatal("no Rex environment did not report standalone")
	}
	if out := h.ok("context", "--project", "outside"); !strings.Contains(string(out), `"outside"`) {
		t.Fatal("explicit standalone context unavailable")
	}
	if _, err := h.cli("clear"); err == nil {
		t.Fatal("standalone project guessed")
	}

	fake := filepath.Join(h.root, "rex")
	script := `#!/bin/sh
if [ "$1" != --server ] || [ "$3" != --autostart=false ] || [ "$4" != --timeout ] || [ "$5" != 3s ]; then exit 90; fi
if [ -n "$REX_CLIENT" ]; then exit 91; fi
shift 5
case "$1" in
  whoami) cat "$FAKE_REX_DIR/who.json" ;;
  session) if [ "$2" != inspect ] || [ "$3" != "$REX_SESSION" ]; then exit 92; fi; cat "$FAKE_REX_DIR/session.json" ;;
  block) if [ "$2" != inspect ] || [ "$3" != -s ] || [ "$4" != "$REX_SESSION" ] || [ "$5" != "$REX_BLOCK" ]; then exit 93; fi; cat "$FAKE_REX_DIR/block.json" ;;
  *) exit 94 ;;
esac
`
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	rexEnv := func(block string) []string {
		return append(append([]string{}, standaloneEnv...),
			"PATH="+h.root+string(os.PathListSeparator)+os.Getenv("PATH"), "FAKE_REX_DIR="+h.root,
			"REX_SESSION="+rexSession, "REX_BLOCK="+block, "REX_SERVER=unix:///tmp/rex-fixture.sock", "REX_CLIENT=must-not-select-viewer")
	}
	write := func(name string, v any) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.root, name+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	setContext := func(block, label string) {
		write("who", map[string]string{"session_id": rexSession, "block_id": block, "endpoint": "unix:///tmp/rex-fixture.sock", "host_id": "server-host-account"})
		write("session", map[string]any{"session_id": rexSession, "label": label, "clients": []any{map[string]string{"host_id": "viewer-not-execution-host"}}})
		write("block", map[string]any{"session_id": rexSession, "block": map[string]string{"block_id": block, "host_id": "execution-host-account"}})
	}
	h.env = rexEnv(rexBlock)
	setContext(rexBlock, "alpha")
	var c rexcontext.Context
	if err := json.Unmarshal(h.ok("context"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Project != "alpha" || c.SessionID != rexSession || c.ExecutionHostID != "execution-host-account" || c.ServerHostID != "server-host-account" {
		t.Fatalf("wrong metadata: %+v", c)
	}
	if _, err := os.Stat(h.home); !os.IsNotExist(err) {
		t.Fatal("context created or contacted service storage")
	}
	if h.count() != 0 {
		t.Fatal("context fetched a secret")
	}

	h.start()
	h.ok("project", "create")
	ref := "op://fixture/item/token"
	flags := []string{"--account", "test-account", "--ref", ref}
	h.ok(append([]string{"allow"}, flags...)...)
	h.ok(append([]string{"request"}, flags...)...)
	for _, action := range []string{"allow", "revoke", "request", "clear", "run"} {
		args := []string{action, "--project", "other"}
		if action != "clear" {
			args = append(args, flags...)
		}
		if action == "run" {
			args = append(args, "--env", "TEST_TOKEN", "--", "sh", "-c", "exit 0")
		}
		out, err := h.cli(args...)
		if err == nil || !strings.Contains(string(out), "must equal") {
			t.Fatalf("%s bypassed session project: %s", action, out)
		}
	}
	if _, err := h.cli("project", "create", "other"); err == nil {
		t.Fatal("create bypassed session label")
	}
	if _, err := h.cli("context", "--project", "other"); err == nil {
		t.Fatal("context bypassed session label")
	}
	h.ok("context", "--project", "alpha")

	// Another pane has exactly the same project and reuses the existing cache entry.
	h.env = rexEnv(secondRexBlock)
	setContext(secondRexBlock, "alpha")
	runArgs := append([]string{"run"}, flags...)
	runArgs = append(runArgs, "--env", "TEST_TOKEN", "--", "sh", "-c", `test "$TEST_TOKEN" = "$COP_FAKE_VALUE"`)
	h.ok(runArgs...)
	if h.count() != 1 {
		t.Fatal("pane change split the project cache")
	}
	h.ok("clear")
	h.ok(append([]string{"request"}, flags...)...)
	if h.count() != 2 {
		t.Fatal("session-default clear failed")
	}

	// A new label selects a new project; it does not migrate old allowlists.
	setContext(secondRexBlock, "renamed")
	out, err := h.cli(append([]string{"request"}, flags...)...)
	if err == nil || !strings.Contains(string(out), "not authorized") {
		t.Fatal("rename inherited old project keys")
	}
	if _, err := h.cli(append([]string{"request", "--project", "alpha"}, flags...)...); err == nil {
		t.Fatal("old explicit project bypassed rename")
	}

	// Failed discovery is not absence, even when --project is supplied.
	if err := os.WriteFile(filepath.Join(h.root, "who.json"), []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.cli(append([]string{"request", "--project", "alpha"}, flags...)...); err == nil {
		t.Fatal("broken Rex fell back to explicit selection")
	}
	if h.count() != 2 {
		t.Fatal("failed or mismatched context invoked op")
	}
	// Administrative service status remains available during a Rex lookup failure.
	h.ok("status")
	h.env = standaloneEnv
	h.ok(keyArgs("request", "alpha", ref)...)
}
