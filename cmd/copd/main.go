package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vizkid/cop/internal/desktop"
	"github.com/vizkid/cop/internal/local"
)

// version is set by release builds: go build -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--internal-sdk-session" {
		desktop.RunSession()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--internal-sdk-batch" {
		desktop.RunBatch()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--internal-sdk-worker" {
		desktop.Run()
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "copd:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("copd", version)
		return nil
	}
	f := flag.NewFlagSet("copd", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	backend := f.String("resolver", "op", "where values come from: op, sdk, or none (replica only)")
	op := f.String("op", "op", "op executable, used with --resolver op")
	worker := f.String("sdk-worker", "", "test override for SDK worker executable")
	ttl := f.Duration("ttl", 7*24*time.Hour, "how long a cached value lives; reading it does not extend it")
	timeout := f.Duration("op-timeout", 2*time.Minute, "time limit for one 1Password load, at most 5m")
	network := f.Bool("tailscale", false, "turn on replication over Tailscale")
	port := f.Int("port", 8787, "replication port on the Tailscale address")
	ts := f.String("tailscale-cli", "tailscale", "tailscale executable")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printHelp(f)
			return nil
		}
		return errors.New("invalid copd options; run copd --help")
	}
	if f.NArg() != 0 || *port < 1 || *port > 65535 {
		return errors.New("invalid daemon arguments")
	}
	home := os.Getenv("COP_HOME")
	if home == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		home = filepath.Join(base, "cop")
	}
	if err := local.DisableCoreDumps(); err != nil {
		return err
	}
	var resolver local.Resolver
	var batch local.BatchResolver
	var closeSDK func()
	var err error
	switch *backend {
	case "op":
		resolver, err = local.OP(*op)
	case "sdk":
		if *worker != "" {
			resolver, err = local.SDK(*worker)
		} else {
			exe, e := os.Executable()
			if e != nil {
				return e
			}
			resolver, err = local.SDK(exe, "--internal-sdk-worker")
			if err == nil {
				batch, closeSDK, err = local.SDKSession(exe, "--internal-sdk-session")
				if err == nil {
					resolver = local.SingleFromBatch(batch)
				}
			}
		}
	case "none":
		resolver = func(context.Context, local.Key) ([]byte, error) {
			return nil, errors.New("no local resolver configured")
		}
	default:
		return errors.New("resolver must be op, sdk, or none")
	}
	if err != nil {
		return err
	}
	if closeSDK != nil {
		defer closeSDK()
	}
	options := local.ReplicationOptions{Batch: batch}
	if *network {
		options.Identity, err = local.TailscaleIdentity(*ts)
		options.Port = *port
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return local.Serve(ctx, home, resolver, *ttl, *timeout, func() { fmt.Println("cop: local service ready") }, options)
}

// printHelp lists the flags from the flag set so the help cannot drift from the code.
// It hides --sdk-worker, which exists only for tests.
func printHelp(f *flag.FlagSet) {
	fmt.Println("usage: copd [options]")
	fmt.Println("Set COP_HOME to choose the state directory.")
	f.VisitAll(func(fl *flag.Flag) {
		if fl.Name == "sdk-worker" {
			return
		}
		name, usage := flag.UnquoteUsage(fl)
		arg := "--" + fl.Name
		if name != "" {
			arg += " " + name
		}
		if fl.DefValue != "" && fl.DefValue != "false" {
			usage += " (default " + fl.DefValue + ")"
		}
		fmt.Printf("  %-26s %s\n", arg, usage)
	})
}
