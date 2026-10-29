package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// copd --help comes from the flag set, so it cannot drift from the real options.
func TestHelpListsEveryUserFlag(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "copd")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	out, err := exec.Command(binary, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("copd --help: %v: %s", err, out)
	}
	help := string(out)
	for _, want := range []string{"--resolver", "--op ", "--ttl", "168h", "--op-timeout", "2m", "--tailscale ", "--port", "8787", "--tailscale-cli"} {
		if !strings.Contains(help, want) {
			t.Errorf("help is missing %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "sdk-worker") {
		t.Errorf("help shows the test-only --sdk-worker flag:\n%s", help)
	}
}
