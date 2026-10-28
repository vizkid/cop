package local

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFakeOP runs only as a subprocess with synthetic input and output.
func TestFakeOP(t *testing.T) {
	if os.Getenv("COP_FAKE_OP") != "1" {
		return
	}
	session, _, errno := syscall.Syscall(syscall.SYS_GETSID, 0, 0, 0)
	if errno != 0 || session != uintptr(os.Getpid()) {
		os.Exit(93)
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		os.Exit(90)
	}
	args = args[1:]
	if len(args) != 6 || args[0] != "read" || args[1] != "--account" || args[2] != "test-account" || args[3] != "--no-newline" || args[4] != "--cache=false" {
		os.Exit(91)
	}
	if os.Getenv("OP_DEBUG") != "false" || os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") != "" {
		os.Exit(92)
	}
	switch {
	case strings.HasSuffix(args[5], "/fail"):
		fmt.Fprint(os.Stdout, sentinel)
		fmt.Fprint(os.Stderr, sentinel)
		os.Exit(9)
	case strings.HasSuffix(args[5], "/hang"):
		time.Sleep(10 * time.Second)
	case strings.HasSuffix(args[5], "/large"):
		fmt.Fprint(os.Stdout, strings.Repeat("x", MaxSecret+1))
		os.Exit(0)
	case strings.HasSuffix(args[5], "/nul"):
		fmt.Fprint(os.Stdout, "hello\x00world")
		os.Exit(0)
	}
	fmt.Fprint(os.Stdout, sentinel)
	os.Exit(0)
}

func TestOPAdapter(t *testing.T) {
	t.Setenv("COP_FAKE_OP", "1")
	t.Setenv("OP_DEBUG", "true")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-ambient-token")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "op")
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(exe, "'", "'\"'\"'") + "' -test.run=TestFakeOP -- \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	resolver, err := OP(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := resolver(context.Background(), testKey)
	if err != nil || string(value) != sentinel {
		t.Fatalf("supported op arguments failed: %v", err)
	}
	clear(value)
	for _, field := range []string{"fail", "large", "nul", "hang"} {
		t.Run(field, func(t *testing.T) {
			k := testKey
			k.Ref = "op://test/item/" + field
			deadline := 2 * time.Second
			if field == "hang" {
				deadline = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			value, err := resolver(ctx, k)
			if err == nil || len(value) != 0 || strings.Contains(err.Error(), sentinel) {
				t.Fatal("adapter failed to redact/refuse")
			}
		})
	}
	if bytes.Contains([]byte(script), []byte(sentinel)) {
		t.Fatal("fake script contains secret")
	}
}
