package main

import (
	"strings"
	"testing"
)

func TestSSHRunRequiresExactlyOneMode(t *testing.T) {
	for _, args := range [][]string{
		{"ssh-run", "--", "true"},
		{"ssh-run", "--sign", "--auth", "--", "true"},
		{"ssh-run", "--purpose", "both", "--", "true"},
		{"ssh-run", "--sign", "--purpose", "auth", "--", "true"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "--sign or --auth") {
			t.Fatalf("%v: ambiguous mode accepted: %v", args, err)
		}
	}
}

func TestSSHRunMode(t *testing.T) {
	for _, tc := range []struct {
		sign, auth bool
		purpose    string
		want       string
	}{
		{sign: true, want: "sign"},
		{auth: true, want: "auth"},
		// --purpose stays as an undocumented alias for scripts written against v0.1.0.
		{purpose: "sign", want: "sign"},
		{purpose: "auth", want: "auth"},
	} {
		if got, err := sshMode(tc.sign, tc.auth, tc.purpose); err != nil || got != tc.want {
			t.Fatalf("sshMode(%v, %v, %q) = %q, %v; want %q", tc.sign, tc.auth, tc.purpose, got, err, tc.want)
		}
	}
}
