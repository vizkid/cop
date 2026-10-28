package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Release builds stamp the version with -ldflags; plain builds report dev.
func TestVersionIsStampedAtBuildTime(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ stamp, want string }{{"", "dev"}, {"v9.9.9-test", "v9.9.9-test"}} {
		for name, pkg := range map[string]string{"cop": ".", "copd": "../copd"} {
			binary := filepath.Join(dir, name)
			args := []string{"build", "-o", binary}
			if tc.stamp != "" {
				args = append(args, "-ldflags", "-X main.version="+tc.stamp)
			}
			if out, err := exec.Command("go", append(args, pkg)...).CombinedOutput(); err != nil {
				t.Fatalf("build %s: %v: %s", name, err, out)
			}
			out, err := exec.Command(binary, "--version").CombinedOutput()
			if got := strings.TrimSpace(string(out)); err != nil || got != name+" "+tc.want {
				t.Fatalf("%s --version = %q, %v; want %q", name, got, err, name+" "+tc.want)
			}
		}
	}
}
