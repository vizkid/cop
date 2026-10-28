package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/vizkid/cop/internal/local"
)

func sshRun(ctx context.Context, home string, args []string) error {
	f := flags("ssh-run")
	sign := f.Bool("sign", false, "sign Git commits")
	auth := f.Bool("auth", false, "authenticate Git SSH transport")
	purpose := f.String("purpose", "", "deprecated: sign or auth")
	project := f.String("project", "", "project")
	account := f.String("account", "", "explicit account")
	ref := f.String("ref", "", "exact signing key reference")
	public := f.String("public-key", "", "public key file")
	if f.Parse(args) != nil || f.NArg() == 0 {
		return errSSHUsage
	}
	mode, err := sshMode(*sign, *auth, *purpose)
	if err != nil {
		return err
	}
	selected, err := selectProject(ctx, *project)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*public)
	if err != nil || len(data) > 4096 {
		return errors.New("cannot read public key file")
	}
	if err := local.DisableCoreDumps(); err != nil {
		return err
	}
	return local.RunSSH(ctx, home, local.Key{Project: selected, Account: *account, Ref: *ref, Use: "ssh-sign", PublicKey: strings.TrimSpace(string(data))}, mode, f.Args(), os.Stdin, os.Stdout, os.Stderr)
}

var errSSHUsage = errors.New("ssh-run requires --sign or --auth, identity options, and a command")

// sshMode picks exactly one mode. --purpose remains for scripts written against v0.1.0.
func sshMode(sign, auth bool, purpose string) (string, error) {
	modes := []string{}
	if sign {
		modes = append(modes, "sign")
	}
	if auth {
		modes = append(modes, "auth")
	}
	if purpose != "" {
		modes = append(modes, purpose)
	}
	if len(modes) != 1 || modes[0] != "sign" && modes[0] != "auth" {
		return "", errSSHUsage
	}
	return modes[0], nil
}
