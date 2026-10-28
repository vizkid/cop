// Package skill distributes cop's agent guide without changing agent configuration.
package skill

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed SKILL.md
var Content string

func digest(data []byte) string { return fmt.Sprintf("%x\n", sha256.Sum256(data)) }

func Install(root string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", errors.New("agent root must be absolute")
	}
	dir := filepath.Join(root, "skills", "cop")
	path := filepath.Join(dir, "SKILL.md")
	for _, p := range []string{filepath.Join(root, "skills"), dir, path, filepath.Join(dir, ".cop.sha256")} {
		info, err := os.Lstat(p)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "preserved operator-managed symlink", nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	previous, err := os.ReadFile(path)
	if err == nil {
		if string(previous) == Content {
			return "already current", nil
		}
		stamp, e := os.ReadFile(filepath.Join(dir, ".cop.sha256"))
		if e != nil || string(stamp) != digest(previous) {
			return "preserved operator-managed content", nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	write := func(target string, data []byte) error {
		file, err := os.CreateTemp(dir, ".cop-install-")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		_, err = file.Write(data)
		if err == nil {
			err = file.Chmod(0644)
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Rename(file.Name(), target)
	}
	if err := write(path, []byte(Content)); err != nil {
		return "", err
	}
	if err := write(filepath.Join(dir, ".cop.sha256"), []byte(digest([]byte(Content)))); err != nil {
		return "", err
	}
	return "installed", nil
}

func Discover(home string, getenv func(string) string) []string {
	roots := map[string]bool{}
	add := func(path string) {
		if !filepath.IsAbs(path) {
			return
		}
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			roots[filepath.Clean(path)] = true
		}
	}
	for _, name := range []string{".codex", ".claude"} {
		add(filepath.Join(home, name))
	}
	add(getenv("CODEX_HOME"))
	add(getenv("CLAUDE_CONFIG_DIR"))
	entries, _ := os.ReadDir(home)
	for _, entry := range entries {
		name := entry.Name()
		marker := ""
		if strings.HasPrefix(name, ".codex-") {
			marker = "config.toml"
		}
		if strings.HasPrefix(name, ".claude-") {
			marker = ".claude.json"
		}
		if marker != "" {
			root := filepath.Join(home, name)
			if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
				add(root)
			}
		}
	}
	result := make([]string, 0, len(roots))
	for root := range roots {
		result = append(result, root)
	}
	slices.Sort(result)
	return result
}
