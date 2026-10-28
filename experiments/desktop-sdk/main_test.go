package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vizkid/cop/internal/local"
)

func TestExactSelectionAndRedaction(t *testing.T) {
	k := local.Key{Project: "example", Account: "explicit-account", Ref: "op://test/example/token"}
	for _, tc := range []struct {
		name, value         string
		initErr, resolveErr bool
		want                string
	}{
		{name: "success", value: "synthetic-sensitive-value"},
		{name: "init", initErr: true, want: "desktop client initialization failed"},
		{name: "resolve", resolveErr: true, want: "desktop initialized; exact-reference resolution failed"},
		{name: "nul", value: "synthetic\x00value", want: "value cannot be delivered by cop"},
		{name: "large", value: strings.Repeat("s", local.MaxSecret+1), want: "value cannot be delivered by cop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluate(context.Background(), k, func(_ context.Context, account string) (resolveFunc, error) {
				if account != k.Account {
					t.Fatal("account changed")
				}
				if tc.initErr {
					return nil, errors.New("synthetic-sensitive-error")
				}
				return func(_ context.Context, ref string) (string, error) {
					if ref != k.Ref {
						t.Fatal("reference changed")
					}
					if tc.resolveErr {
						return "", errors.New("synthetic-sensitive-error")
					}
					return tc.value, nil
				}, nil
			})
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("unexpected outcome: %q", got)
			}
		})
	}
}

func TestInvalidSelectionNeverCreatesClient(t *testing.T) {
	for _, k := range []local.Key{
		{Project: "example", Ref: "op://test/example/token"},
		{Project: "example", Account: "account", Ref: "op://test/example/private key"},
	} {
		err := evaluate(context.Background(), k, func(context.Context, string) (resolveFunc, error) {
			t.Fatal("client created for invalid request")
			return nil, nil
		})
		if err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestResolutionDiagnosticsDoNotForwardSDKText(t *testing.T) {
	k := local.Key{Project: "example", Account: "account", Ref: "op://test/example/token"}
	for code := 40; code <= 45; code++ {
		err := evaluate(context.Background(), k, func(context.Context, string) (resolveFunc, error) {
			return func(context.Context, string) (string, error) {
				return "", errors.New(outcomes[code] + ": synthetic-sensitive-details")
			}, nil
		})
		if err == nil || err.Error() != outcomes[code] {
			t.Fatalf("wrong fixed diagnostic for code %d", code)
		}
	}
	for _, code := range []string{"20", "40", "41"} {
		err := supervise(context.Background(), "/bin/sh", []string{"-c", "echo synthetic-secret >&2; exit " + code}, nil)
		var diagnostic *probeError
		if !errors.As(err, &diagnostic) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("fixed worker diagnostic was lost or exposed output")
		}
	}
}

func TestWorkerDeadlineAndFailureRedaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := supervise(ctx, "/bin/sh", []string{"-c", "exec sleep 30"}, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 3*time.Second {
		t.Fatal("worker deadline not enforced")
	}
	err = supervise(context.Background(), "/bin/sh", []string{"-c", "echo synthetic-secret; echo synthetic-secret >&2; exit 1"}, nil)
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("worker failure not redacted")
	}
}
