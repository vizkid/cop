// This evaluation probe never delivers a secret or changes the cop service.
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
	"strings"
	"syscall"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/vizkid/cop/internal/local"
)

type resolveFunc func(context.Context, string) (string, error)
type factory func(context.Context, string) (resolveFunc, error)

type probeError struct {
	code    int
	message string
}

func (e *probeError) Error() string { return e.message }

var outcomes = map[int]string{
	20: "desktop client initialization failed",
	21: "desktop initialized; exact-reference resolution failed",
	22: "desktop initialized; SDK reported not found during resolution",
	23: "desktop initialized; SDK reported an expired session during resolution",
	30: "desktop resolution error mentions a field",
	31: "desktop resolution error mentions a vault",
	32: "desktop resolution error mentions an item",
	33: "desktop resolution error mentions an account",
	34: "desktop resolution error mentions permission or denial",
	35: "desktop resolution error mentions serialization or decoding",
	36: "desktop resolution error mentions a connection",
	37: "desktop resolution error mentions an unsupported operation",
	38: "desktop resolution error mentions an invalid reference",
	40: "no vault matched the secret reference query",
	41: "more than one vault matched the secret reference query",
	42: "no item matched the secret reference query",
	43: "more than one item matched the secret reference query",
	44: "the specified field cannot be found within the item",
	45: "account couldn't be found",
}

func failure(code int) error { return &probeError{code, outcomes[code]} }

func desktop(ctx context.Context, account string) (resolveFunc, error) {
	c, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("cop SDK evaluation", "0.1.0"))
	if err != nil {
		return nil, err
	}
	return c.Secrets().Resolve, nil
}

func evaluate(ctx context.Context, k local.Key, create factory) error {
	if err := k.Validate(); err != nil {
		return errors.New("invalid account or reference")
	}
	resolve, err := create(ctx, k.Account)
	if err != nil {
		return failure(20)
	}
	value, err := resolve(ctx, k.Ref)
	if err != nil {
		var expired *onepassword.DesktopSessionExpiredError
		if errors.As(err, &expired) {
			return failure(23)
		}
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return failure(22)
		}
		message := strings.ToLower(err.Error())
		for code := 40; code <= 45; code++ {
			if strings.Contains(message, outcomes[code]) {
				return failure(code)
			}
		}
		for _, category := range []struct {
			code  int
			words []string
		}{
			{30, []string{"field"}},
			{31, []string{"vault"}},
			{32, []string{"item"}},
			{33, []string{"account"}},
			{34, []string{"permission", "denied", "unauthorized"}},
			{35, []string{"serializ", "decod", "json"}},
			{36, []string{"connection", "channel"}},
			{37, []string{"unsupported", "not supported"}},
			{38, []string{"reference", "invalid"}},
		} {
			for _, word := range category.words {
				if strings.Contains(message, word) {
					return failure(category.code)
				}
			}
		}
		return failure(21)
	}
	if ctx.Err() != nil {
		return errors.New("desktop resolution canceled")
	}
	if len(value) > local.MaxSecret || strings.IndexByte(value, 0) >= 0 {
		return errors.New("value cannot be delivered by cop")
	}
	// The SDK returns immutable strings; process exit releases temporary copies.
	return nil
}

func supervise(ctx context.Context, executable string, args []string, input io.Reader) error {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = input
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return errors.New("desktop evaluation timed out or was canceled")
		}
		var exited *exec.ExitError
		if errors.As(err, &exited) {
			if _, ok := outcomes[exited.ExitCode()]; ok {
				return failure(exited.ExitCode())
			}
		}
		return errors.New("desktop evaluation failed; check SDK integration, account, approval, and reference")
	}
	return nil
}

func run() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return errors.New("cannot disable core dumps")
	}
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		var k local.Key
		if err := json.NewDecoder(io.LimitReader(os.Stdin, 8192)).Decode(&k); err != nil {
			return errors.New("invalid evaluation input")
		}
		return evaluate(context.Background(), k, desktop)
	}
	live := flag.Bool("live", false, "resolve one exact reference through desktop approval")
	account := flag.String("account", "", "explicit desktop account name or UUID (not a sign-in URL)")
	ref := flag.String("ref", "", "exact ordinary readable op:// reference")
	timeout := flag.Duration("timeout", time.Minute, "hard process deadline, at most 5m")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > 5*time.Minute {
		return errors.New("invalid arguments")
	}
	if !*live {
		fmt.Println("SDK v0.4.1 probe built; no desktop connection or secret resolution attempted")
		return nil
	}
	k := local.Key{Project: "sdk-evaluation", Account: *account, Ref: *ref}
	if err := k.Validate(); err != nil {
		return errors.New("explicit account and ordinary readable reference required")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot locate evaluation executable")
	}
	data, err := json.Marshal(k)
	if err != nil {
		return errors.New("invalid evaluation input")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	fmt.Println("active: waiting for 1Password desktop authorization and resolution")
	if err := supervise(ctx, executable, []string{"--worker"}, strings.NewReader(string(data))); err != nil {
		return err
	}
	fmt.Println("resolved: value discarded; no value, length, or hash printed")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var outcome *probeError
		if errors.As(err, &outcome) {
			os.Exit(outcome.code)
		}
		os.Exit(1)
	}
}
