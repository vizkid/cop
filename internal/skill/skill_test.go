package skill

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallUpdatesManagedContentButPreservesEdits(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "skills", "cop", "SKILL.md")
	if _, err := Install(root); err != nil {
		t.Fatal(err)
	}
	if result, err := Install(root); err != nil || result != "already current" {
		t.Fatal("install not idempotent")
	}
	old := []byte("previous managed version")
	os.WriteFile(path, old, 0644)
	os.WriteFile(filepath.Join(filepath.Dir(path), ".cop.sha256"), []byte(digest(old)), 0644)
	if result, err := Install(root); err != nil || result != "installed" {
		t.Fatal("managed update failed")
	}
	edited := []byte("operator's instructions")
	os.WriteFile(path, edited, 0644)
	if _, err := Install(root); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(edited) {
		t.Fatal("operator edit overwritten")
	}
}
func TestInstallPreservesSymlinks(t *testing.T) {
	for _, part := range []string{"skills", "skills/cop", "skills/cop/SKILL.md"} {
		t.Run(part, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			dest := outside
			if part == "skills/cop/SKILL.md" {
				dest = filepath.Join(outside, "file")
				os.WriteFile(dest, []byte("custom"), 0600)
			}
			target := filepath.Join(root, part)
			os.MkdirAll(filepath.Dir(target), 0755)
			os.Symlink(dest, target)
			if _, err := Install(root); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(target)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("managed symlink changed")
			}
		})
	}
}
func TestDiscoverRecognizedProfilesAndOverrides(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{".codex", ".claude-work", ".codex-unused", "custom"} {
		os.Mkdir(filepath.Join(home, name), 0700)
	}
	os.WriteFile(filepath.Join(home, ".claude-work", ".claude.json"), []byte("{}"), 0600)
	roots := Discover(home, func(key string) string {
		if key == "CODEX_HOME" {
			return filepath.Join(home, "custom")
		}
		return ""
	})
	if len(roots) != 3 {
		t.Fatalf("unexpected discovered root count: %d", len(roots))
	}
}
