package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/vizkid/cop/internal/local"
	"github.com/vizkid/cop/internal/rexcontext"
)

// version is set by release builds: go build -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `cop (cached one password)

Usage:
  cop setup
  cop skill show
  cop skill install [--root AGENT_HOME]
  cop connect [--topcop local|remote] TAILSCALE_IP:PORT
  cop serve [OPTIONS] (compatibility alias for copd)
  cop context [--project NAME]
  cop project create [NAME]
  cop allow   [--project NAME] --account ACCOUNT --ref op://vault/item/field
  cop revoke  [--project NAME] --account ACCOUNT --ref op://vault/item/field
  cop request [--project NAME] --account ACCOUNT --ref op://vault/item/field
  cop run     [--project NAME] --account ACCOUNT --ref op://vault/item/field --env NAME -- COMMAND [ARGS...]
  cop clear   [--project NAME]
  cop status
  cop ssh-run --sign|--auth [--project NAME] --account ACCOUNT --ref REF --public-key FILE -- COMMAND [ARGS...]
  cop version

Set COP_HOME to an absolute private directory to override the user config directory.
Inside Rex, the project must equal the session label. Outside Rex, select it explicitly.
context inspects metadata without contacting cop or 1Password. status remains service-wide.
Only run delivers a value, through the child environment. Other output contains metadata only.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var child *exec.ExitError
		if errors.As(err, &child) && child.ExitCode() >= 0 {
			os.Exit(child.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "cop:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Print(usage)
		return nil
	}
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println("cop", version)
		return nil
	}
	if args[0] == "skill" {
		return skillCommand(args[1:])
	}
	if args[0] == "setup" {
		if len(args) != 1 {
			return errors.New("usage: cop setup")
		}
		return skillCommand([]string{"install"})
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if args[0] == "context" {
		f := flags("context")
		project := f.String("project", "", "explicit project")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			return errors.New("usage: cop context [--project NAME]")
		}
		c, err := rexcontext.Current(ctx)
		if err != nil {
			return err
		}
		c.Project, err = c.SelectProject(*project, false)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(c)
	}
	home := os.Getenv("COP_HOME")
	if home == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return errors.New("user config directory unavailable; set COP_HOME")
		}
		home = filepath.Join(base, "cop")
	}
	if !filepath.IsAbs(home) {
		return errors.New("COP_HOME must be absolute")
	}
	if args[0] == "ssh-run" {
		return sshRun(ctx, home, args[1:])
	}
	if args[0] == "serve" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		daemon := filepath.Join(filepath.Dir(exe), "copd")
		return syscall.Exec(daemon, append([]string{daemon}, args[1:]...), os.Environ())
	}
	if args[0] == "connect" {
		f := flags("connect")
		topcop := f.String("topcop", "", "local for the first topcop; otherwise inherit")
		if f.Parse(args[1:]) != nil || f.NArg() != 1 {
			return errors.New("usage: cop connect [--topcop local|remote] TAILSCALE_IP:PORT")
		}
		result, err := local.Call(ctx, home, local.Request{Action: "connect", Peer: f.Arg(0), Topcop: *topcop})
		if err == nil {
			fmt.Println(result.Status)
		}
		return err
	}

	if args[0] == "project" {
		if (len(args) != 2 && len(args) != 3) || args[1] != "create" {
			return errors.New("usage: cop project create [NAME]")
		}
		explicit := ""
		if len(args) == 3 {
			explicit = args[2]
		}
		project, err := selectProject(ctx, explicit)
		if err != nil {
			return err
		}
		r, err := local.Call(ctx, home, local.Request{Action: "create", Key: local.Key{Project: project}})
		if err == nil {
			fmt.Println(r.Status)
		}
		return err
	}
	if args[0] == "status" {
		if len(args) != 1 {
			return errors.New("usage: cop status")
		}
		r, err := local.Call(ctx, home, local.Request{Action: "status"})
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(r.View)
	}
	switch args[0] {
	case "allow", "revoke", "request", "run", "clear":
	default:
		return errors.New("unsupported command; run cop --help")
	}
	f := flags(args[0])
	project := f.String("project", "", "project name")
	account := f.String("account", "", "exact account selector")
	ref := f.String("ref", "", "exact 1Password reference")
	use := f.String("use", "", "ssh-sign for signing-only authorization")
	public := f.String("public-key", "", "expected public key file")
	env := f.String("env", "", "child environment variable")
	if f.Parse(args[1:]) != nil {
		return errors.New("invalid arguments; run cop --help")
	}
	action := args[0]
	var program string
	if action == "run" {
		if f.NArg() == 0 || !safeEnv(*env) {
			return errors.New("run needs a command and a safe environment variable name")
		}
		var err error
		program, err = exec.LookPath(f.Arg(0))
		if err != nil {
			return errors.New("child executable unavailable")
		}
		if err = local.DisableCoreDumps(); err != nil {
			return err
		}
		action = "deliver"
	} else if f.NArg() != 0 || *env != "" {
		return errors.New("unexpected arguments; run cop --help")
	}
	if action == "clear" && (*account != "" || *ref != "") {
		return errors.New("clear accepts only --project")
	}
	selected, err := selectProject(ctx, *project)
	if err != nil {
		return err
	}
	key := local.Key{Project: selected, Account: *account, Ref: *ref, Use: *use}
	if *public != "" {
		data, e := os.ReadFile(*public)
		if e != nil || len(data) > 4096 {
			return errors.New("cannot read public key file")
		}
		key.PublicKey = strings.TrimSpace(string(data))
	}
	if action == "clear" && (*use != "" || *public != "") {
		return errors.New("clear accepts only project")
	}
	r, err := local.Call(ctx, home, local.Request{Action: action, Key: key})
	if err != nil {
		return err
	}
	defer clear(r.Value)
	if action != "deliver" {
		fmt.Println(r.Status)
		return nil
	}
	childEnv := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, *env+"=") {
			childEnv = append(childEnv, e)
		}
	}
	childEnv = append(childEnv, *env+"="+string(r.Value))
	clear(r.Value)
	// Replace cop so signals and exit codes belong directly to the intended child.
	stop()
	if syscall.Exec(program, f.Args(), childEnv) != nil {
		return errors.New("cannot execute child")
	}
	return nil
}

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func selectProject(ctx context.Context, explicit string) (string, error) {
	c, err := rexcontext.Current(ctx)
	if err != nil {
		return "", err
	}
	return c.SelectProject(explicit, true)
}

var envPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

func safeEnv(name string) bool {
	if !envPattern.MatchString(name) {
		return false
	}
	for _, prefix := range []string{"LD_", "DYLD_", "OP_", "COP_", "REX_"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	switch name {
	case "PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "ZDOTDIR", "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "PERL5OPT", "RUBYOPT", "GODEBUG", "GOTRACEBACK", "TMPDIR":
		return false
	}
	return true
}
