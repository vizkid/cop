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
	purpose := f.String("purpose", "", "sign for commits, auth for SSH transport")
	project := f.String("project", "", "project")
	account := f.String("account", "", "explicit account")
	ref := f.String("ref", "", "exact signing key reference")
	public := f.String("public-key", "", "public key file")
	if f.Parse(args) != nil || f.NArg() == 0 || (*purpose != "sign" && *purpose != "auth") {
		return errors.New("ssh-run requires --purpose sign|auth, identity options, and a command")
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
	return local.RunSSH(ctx, home, local.Key{Project: selected, Account: *account, Ref: *ref, Use: "ssh-sign", PublicKey: strings.TrimSpace(string(data))}, *purpose, f.Args(), os.Stdin, os.Stdout, os.Stderr)
}
