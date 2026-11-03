package rexcontext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const sessionID = "session:11111111-1111-7111-8111-111111111111"
const blockID = "block:22222222-2222-7222-8222-222222222222"
const otherBlock = "block:33333333-3333-7333-8333-333333333333"
const endpoint = "unix:///tmp/rex-test.sock"

func environment() Environment {
	return Environment{Session: sessionID, Block: blockID, Server: endpoint, Present: true}
}

func responses(env Environment, label, host string) []string {
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	return []string{
		// Rex always reports the test endpoint, so an explicit REX_SERVER that
		// differs from it shows which server the later lookups use.
		encode(map[string]any{"host_id": "server-account-id", "endpoint": endpoint, "session_id": env.Session, "block_id": env.Block, "account": "not-a-host-key"}),
		encode(map[string]any{"sessions": []any{
			map[string]string{"session_id": "session:99999999-9999-7999-8999-999999999999", "label": "someone-else"},
			map[string]string{"session_id": env.Session, "label": label},
		}}),
		encode(map[string]any{"session_id": env.Session, "block": map[string]string{"block_id": env.Block, "host_id": host, "owner": "viewing-client-do-not-use"}}),
	}
}

func fixture(t *testing.T, e Environment, reply []string) Runner {
	t.Helper()
	i := 0
	expected := [][]string{
		{"whoami", "--json"},
		{"session", "ls", "--json", "--short=false"},
		{"block", "inspect", "-s", e.Session, e.Block, "--json"},
	}
	return func(_ context.Context, args ...string) ([]byte, error) {
		t.Helper()
		if i >= len(reply) {
			t.Fatal("unexpected extra lookup")
		}
		server := []string{"--server", e.Server}
		if e.Server == "" {
			// Only whoami may use Rex's default server; it confirms the IDs.
			server = nil
			if i > 0 {
				server = []string{"--server", endpoint}
			}
		}
		want := append(append(server, "--autostart=false", "--timeout", "3s"), expected[i]...)
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("incorrect lookup arguments: %v", args)
		}
		v := reply[i]
		i++
		return []byte(v), nil
	}
}

func TestSessionProjectAndExecutionHost(t *testing.T) {
	for _, block := range []string{blockID, otherBlock} {
		e := environment()
		e.Block = block
		c, err := Discover(context.Background(), e, fixture(t, e, responses(e, "project-alpha", "execution-account-id")))
		if err != nil {
			t.Fatal(err)
		}
		if c.Project != "project-alpha" || c.SessionID != sessionID || c.ServerHostID != "server-account-id" || c.ExecutionHostID != "execution-account-id" {
			t.Fatalf("incorrect context: %+v", c)
		}
		if got, err := c.SelectProject("", true); err != nil || got != c.Project {
			t.Fatal("missing session default")
		}
		if _, err := c.SelectProject(c.Project, true); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SelectProject("different-project", true); err == nil {
			t.Fatal("explicit bypass accepted")
		}
		encoded, _ := json.Marshal(c)
		if strings.Contains(string(encoded), block) || strings.Contains(string(encoded), "viewing-client") {
			t.Fatal("pane/viewer became context scope")
		}
	}
	// Changing the endpoint does not change host identity, and every lookup
	// stays on the server the pane named, even when Rex reports another one.
	e := environment()
	e.Server = "https://rex.example.test"
	c, err := Discover(context.Background(), e, fixture(t, e, responses(e, "project-alpha", "server-account-id")))
	if err != nil || c.ServerHostID != "server-account-id" || c.ExecutionHostID != c.ServerHostID {
		t.Fatalf("endpoint used as host identity: %v", err)
	}
}

func TestAbsentVersusIncompleteContext(t *testing.T) {
	never := func(context.Context, ...string) ([]byte, error) { t.Fatal("unexpected Rex lookup"); return nil, nil }
	c, err := Discover(context.Background(), Environment{}, never)
	if err != nil || c.Mode != "standalone" {
		t.Fatal("absent context not standalone")
	}
	if p, err := c.SelectProject("chosen", true); err != nil || p != "chosen" {
		t.Fatal("standalone explicit selection failed")
	}
	if _, err := c.SelectProject("", true); err == nil {
		t.Fatal("standalone selection guessed")
	}
	if _, err := c.SelectProject("", false); err != nil {
		t.Fatal("standalone context inspection failed")
	}
	for _, e := range []Environment{
		{Present: true}, {Session: sessionID}, {Server: endpoint}, {Block: blockID},
		{Session: sessionID, Server: endpoint}, {Server: endpoint, Block: blockID},
		{Session: "project-alpha", Server: endpoint, Block: blockID},
		{Session: sessionID, Server: "ambiguous-server-label", Block: blockID},
		{Session: sessionID, Server: "https://user:password@example.test", Block: blockID},
		{Session: sessionID, Server: endpoint, Block: "2222"},
	} {
		if _, err := Discover(context.Background(), e, never); err == nil {
			t.Errorf("accepted partial or malformed context: %+v", e)
		}
	}
}

func TestStaleMalformedAndAmbiguousResponses(t *testing.T) {
	e := environment()
	cases := []struct {
		name  string
		index int
		reply string
	}{
		{"missing server host", 0, `{"endpoint":"unix:///tmp/rex-test.sock","session_id":"` + sessionID + `","block_id":"` + blockID + `"}`},
		{"stale session", 0, `{"host_id":"host","endpoint":"unix:///tmp/rex-test.sock","block_id":"` + blockID + `"}`},
		{"stale block", 0, `{"host_id":"host","endpoint":"unix:///tmp/rex-test.sock","session_id":"` + sessionID + `"}`},
		{"invalid JSON", 0, `broken`},
		{"multiple documents", 0, `{} {}`},
		{"session not listed", 1, `{"sessions":[{"session_id":"different","label":"project-alpha"}]}`},
		{"session listed twice", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":"project-alpha"},{"session_id":"` + sessionID + `","label":"other"}]}`},
		{"empty label", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":""}]}`},
		{"invalid project label", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":"project alpha"}]}`},
		{"duplicate label", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":"project-alpha","label":"other"}]}`},
		{"case-folded label", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":"project-alpha","LABEL":"other"}]}`},
		{"wrong label type", 1, `{"sessions":[{"session_id":"` + sessionID + `","label":[]}]}`},
		{"listing not a list", 1, `{"sessions":{"session_id":"` + sessionID + `","label":"project-alpha"}}`},
		{"missing execution host", 2, `{"session_id":"` + sessionID + `","block":{"block_id":"` + blockID + `"}}`},
		{"wrong block session", 2, `{"session_id":"different","block":{"block_id":"` + blockID + `","host_id":"host"}}`},
		{"wrong block", 2, `{"session_id":"` + sessionID + `","block":{"block_id":"` + otherBlock + `","host_id":"host"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := responses(e, "project-alpha", "execution-account-id")
			r[tc.index] = tc.reply
			if _, err := Discover(context.Background(), e, fixture(t, e, r)); err == nil {
				t.Fatal("invalid context accepted")
			}
		})
	}
	_, err := Discover(context.Background(), e, func(context.Context, ...string) ([]byte, error) { return nil, errors.New("private diagnostic text") })
	if err == nil || strings.Contains(err.Error(), "private diagnostic") {
		t.Fatal("failed lookup fell back or exposed stderr")
	}
}

func TestLabelChangesAreNotCachedOrNormalized(t *testing.T) {
	e := environment()
	for _, label := range []string{"Project_A", "Project_B"} {
		c, err := Discover(context.Background(), e, fixture(t, e, responses(e, label, "host")))
		if err != nil || c.Project != label {
			t.Fatal("label was cached or normalized")
		}
	}
	// Full IDs select sessions; equal labels deliberately select the same cop project.
	e.Session = "session:44444444-4444-7444-8444-444444444444"
	c, err := Discover(context.Background(), e, fixture(t, e, responses(e, "Project_A", "host")))
	if err != nil || c.Project != "Project_A" || c.SessionID != e.Session {
		t.Fatal("session selected by label")
	}
}

// Rex on Linux leaves REX_SERVER out of pane environments. The Rex CLI still
// finds its own server, and whoami proves the session and block there.
func TestMissingServerUsesRexDefault(t *testing.T) {
	e := environment()
	e.Server = ""
	c, err := Discover(context.Background(), e, fixture(t, e, responses(e, "project-alpha", "execution-account-id")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Project != "project-alpha" || c.ServerEndpoint != endpoint || c.ExecutionHostID != "execution-account-id" {
		t.Fatalf("incorrect context: %+v", c)
	}
	for name, who := range map[string]string{
		"unconfirmed block":   `{"host_id":"host","endpoint":"unix:///tmp/rex-test.sock","session_id":"` + sessionID + `"}`,
		"unconfirmed session": `{"host_id":"host","endpoint":"unix:///tmp/rex-test.sock","block_id":"` + blockID + `"}`,
		"other block":         `{"host_id":"host","endpoint":"unix:///tmp/rex-test.sock","session_id":"` + sessionID + `","block_id":"` + otherBlock + `"}`,
		"no endpoint":         `{"host_id":"host","session_id":"` + sessionID + `","block_id":"` + blockID + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := responses(environment(), "project-alpha", "host")
			r[0] = who
			if _, err := Discover(context.Background(), e, fixture(t, e, r)); err == nil {
				t.Fatal("unconfirmed default server accepted")
			}
		})
	}
}

// A session listing does not carry layout, so many nested panes cannot push
// it past the JSON nesting limit the way session inspect did.
func TestManySessionsListing(t *testing.T) {
	e := environment()
	sessions := []any{}
	for i := 0; i < 500; i++ {
		sessions = append(sessions, map[string]string{"session_id": fmt.Sprintf("session:00000000-0000-7000-8000-%012d", i), "label": "other"})
	}
	sessions = append(sessions, map[string]string{"session_id": sessionID, "label": "project-alpha"})
	b, _ := json.Marshal(map[string]any{"sessions": sessions})
	r := responses(e, "project-alpha", "host")
	r[1] = string(b)
	if c, err := Discover(context.Background(), e, fixture(t, e, r)); err != nil || c.Project != "project-alpha" {
		t.Fatalf("large listing rejected: %v", err)
	}
}
