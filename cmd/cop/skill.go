package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vizkid/cop/internal/skill"
)

func skillCommand(args []string) error {
	if len(args) == 1 && args[0] == "show" {
		fmt.Print(skill.Content)
		return nil
	}
	if len(args) == 0 || args[0] != "install" {
		return errors.New("usage: cop skill show | cop skill install [--root AGENT_HOME]")
	}
	f := flags("skill install")
	root := f.String("root", "", "agent configuration directory")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return errors.New("usage: cop skill install [--root AGENT_HOME]")
	}
	var roots []string
	if *root != "" {
		path, err := filepath.Abs(*root)
		if err != nil {
			return err
		}
		roots = []string{path}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		roots = skill.Discover(home, os.Getenv)
	}
	if len(roots) == 0 {
		return errors.New("no agent homes found; use cop skill install --root AGENT_HOME")
	}
	var failures []error
	for _, root := range roots {
		result, err := skill.Install(root)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", root, err))
			continue
		}
		fmt.Printf("%s: %s\n", root, result)
	}
	return errors.Join(failures...)
}
