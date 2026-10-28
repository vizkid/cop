package main

import (
	"strings"
	"testing"
)

func TestSSHRunRequiresExplicitPurpose(t *testing.T) {
	for _, args := range [][]string{
		{"ssh-run", "--", "true"},
		{"ssh-run", "--purpose", "both", "--", "true"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "--purpose sign|auth") {
			t.Fatal("ambiguous purpose accepted")
		}
	}
}
