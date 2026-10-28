package rexcontext

import (
	"context"
	"encoding/json"
	"errors"
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
		encode(map[string]any{"host_id": "server-account-id", "endpoint": env.Server, "session_id": env.Session, "block_id": env.Block, "account": "not-a-host-key"}),
		encode(map[string]any{"session_id": env.Session, "label": label, "active_window_id": "ignore-me", "clients": []any{map[string]string{"host_id": "viewing-client-do-not-use"}}}),
		encode(map[string]any{"session_id": env.Session, "block": map[string]string{"block_id": env.Block, "host_id": host, "owner": "viewing-client-do-not-use"}}),
	}
}

func fixture(t *testing.T, e Environment, reply []string) Runner {
	t.Helper()
	i := 0
	expected := [][]string{
		{"whoami", "--json"},
		{"session", "inspect", e.Session, "--json"},
		{"block", "inspect", "-s", e.Session, e.Block, "--json"},
	}
	return func(_ context.Context, args ...string) ([]byte, error) {
		t.Helper()
		if i >= len(reply) {
			t.Fatal("unexpected extra lookup")
		}
		want := append([]string{"--server", e.Server, "--autostart=false", "--timeout", "3s"}, expected[i]...)
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
	// Changing the endpoint does not change host identity.
	e := environment()
	e.Server = "https://rex.example.test"
	c, err := Discover(context.Background(), e, fixture(t, e, responses(e, "project-alpha", "server-account-id")))
	if err != nil || c.ServerHostID != "server-account-id" || c.ExecutionHostID != c.ServerHostID {
		t.Fatal("endpoint used as host identity")
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
		{Session: sessionID, Server: endpoint}, {Session: sessionID, Block: blockID}, {Server: endpoint, Block: blockID},
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
		{"wrong session", 1, `{"session_id":"different","label":"project-alpha"}`},
		{"empty label", 1, `{"session_id":"` + sessionID + `","label":""}`},
		{"invalid project label", 1, `{"session_id":"` + sessionID + `","label":"project alpha"}`},
		{"duplicate label", 1, `{"session_id":"` + sessionID + `","label":"project-alpha","label":"other"}`},
		{"case-folded label", 1, `{"session_id":"` + sessionID + `","label":"project-alpha","LABEL":"other"}`},
		{"wrong label type", 1, `{"session_id":"` + sessionID + `","label":[]}`},
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
