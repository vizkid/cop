// Package rexcontext discovers optional Rex metadata without granting access.
package rexcontext

import (
	"context"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/vizkid/cop/internal/local"
)

type Context struct {
	Mode            string `json:"mode"`
	Project         string `json:"project,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	ServerEndpoint  string `json:"server_endpoint,omitempty"`
	ServerHostID    string `json:"server_host_id,omitempty"`
	ExecutionHostID string `json:"execution_host_id,omitempty"`
}

type Environment struct {
	Session string
	Server  string
	Block   string
	Present bool
}

// Runner receives separate arguments, never a shell command.
type Runner func(context.Context, ...string) ([]byte, error)

func Current(ctx context.Context) (Context, error) {
	var e Environment
	for name, dest := range map[string]*string{"REX_SESSION": &e.Session, "REX_SERVER": &e.Server, "REX_BLOCK": &e.Block} {
		value, present := os.LookupEnv(name)
		*dest = value
		e.Present = e.Present || present
	}
	return Discover(ctx, e, runRex)
}

func (c Context) SelectProject(explicit string, required bool) (string, error) {
	if c.Mode == "rex" {
		if explicit != "" && explicit != c.Project {
			return "", errors.New("explicit project must equal the Rex session label")
		}
		return c.Project, nil
	}
	if explicit == "" && !required {
		return "", nil
	}
	if !local.ValidProjectName(explicit) {
		return "", errors.New("outside Rex, select an explicit valid project")
	}
	return explicit, nil
}

var fullID = regexp.MustCompile(`^(session|block):[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var hostID = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,256}$`)

func validID(value, kind string) bool {
	return strings.HasPrefix(value, kind+":") && fullID.MatchString(value)
}

func validEndpoint(value string) bool {
	if len(value) == 0 || len(value) > 4096 || strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.IsAbs() && u.Opaque == "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		(u.Host != "" || strings.HasPrefix(u.Path, "/"))
}

func Discover(ctx context.Context, env Environment, run Runner) (Context, error) {
	if !env.Present && env.Session == "" && env.Server == "" && env.Block == "" {
		return Context{Mode: "standalone"}, nil
	}
	if env.Session == "" || env.Server == "" || env.Block == "" {
		return Context{}, errors.New("incomplete Rex context: REX_SESSION, REX_SERVER, and REX_BLOCK are required")
	}
	if !validID(env.Session, "session") || !validID(env.Block, "block") || !validEndpoint(env.Server) {
		return Context{}, errors.New("malformed Rex context: use full session/block IDs and a server endpoint")
	}
	query := func(target any, args ...string) error {
		args = append([]string{"--server", env.Server, "--autostart=false", "--timeout", "3s"}, args...)
		data, err := run(ctx, args...)
		if err != nil {
			return errors.New("Rex lookup failed; no standalone fallback")
		}
		if len(data) > maxOutput || decode(data, target) != nil {
			return errors.New("invalid or ambiguous Rex response")
		}
		return nil
	}
	var who struct {
		HostID   string `json:"host_id"`
		Endpoint string `json:"endpoint"`
		Session  string `json:"session_id"`
		Block    string `json:"block_id"`
	}
	if err := query(&who, "whoami", "--json"); err != nil {
		return Context{}, err
	}
	if who.Session != env.Session || who.Block != env.Block {
		return Context{}, errors.New("stale or conflicting Rex session/block context")
	}
	if !hostID.MatchString(who.HostID) || !validEndpoint(who.Endpoint) {
		return Context{}, errors.New("Rex server identity is missing or malformed")
	}
	var session struct {
		ID    string `json:"session_id"`
		Label string `json:"label"`
	}
	if err := query(&session, "session", "inspect", env.Session, "--json"); err != nil {
		return Context{}, err
	}
	if session.ID != env.Session {
		return Context{}, errors.New("Rex returned a different session")
	}
	if !local.ValidProjectName(session.Label) {
		return Context{}, errors.New("Rex session label must be a valid cop project name; no normalization is applied")
	}
	var block struct {
		Session string `json:"session_id"`
		Block   struct {
			ID   string `json:"block_id"`
			Host string `json:"host_id"`
		} `json:"block"`
	}
	if err := query(&block, "block", "inspect", "-s", env.Session, env.Block, "--json"); err != nil {
		return Context{}, err
	}
	if block.Session != env.Session || block.Block.ID != env.Block {
		return Context{}, errors.New("Rex block does not belong to the supplied session")
	}
	if !hostID.MatchString(block.Block.Host) {
		return Context{}, errors.New("Rex execution host is unknown; refusing to guess from the server or viewing client")
	}
	return Context{Mode: "rex", Project: session.Label, SessionID: session.ID,
		ServerEndpoint: who.Endpoint, ServerHostID: who.HostID, ExecutionHostID: block.Block.Host}, nil
}
