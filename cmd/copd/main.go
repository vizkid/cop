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
		fmt.Println("copd dev")
		return nil
	}
	f := flag.NewFlagSet("copd", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	backend := f.String("resolver", "op", "op, sdk, or none (replica only)")
	op := f.String("op", "op", "op executable")
	worker := f.String("sdk-worker", "", "test override for SDK worker executable")
	ttl := f.Duration("ttl", 7*24*time.Hour, "cache lifetime")
	timeout := f.Duration("op-timeout", 2*time.Minute, "resolution timeout")
	network := f.Bool("tailscale", false, "enable peer replication")
	port := f.Int("port", 8787, "Tailscale listener port")
	ts := f.String("tailscale-cli", "tailscale", "Tailscale executable")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println("copd [--resolver op|sdk|none] [--ttl 168h] [--op-timeout 2m] [--tailscale] [--port 8787]")
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
