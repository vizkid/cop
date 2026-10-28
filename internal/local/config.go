package local

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type config struct {
	Version  int              `json:"version"`
	Projects map[string][]Key `json:"projects"`
}

func checkOwned(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cop path must be owned by this user and inaccessible to other users")
	}
	if directory && !info.IsDir() {
		return errors.New("cop home must be a directory")
	}
	return nil
}

func PrepareHome(home string) error {
	if !filepath.IsAbs(home) {
		return errors.New("cop home must be an absolute path")
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return errors.New("cannot create cop home")
	}
	return checkOwned(home, true)
}

func loadConfig(home string) (config, error) {
	c := config{Version: 1, Projects: map[string][]Key{}}
	path := filepath.Join(home, "projects.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err := checkOwned(path, false); err != nil {
		return c, errors.New("unsafe project configuration")
	}
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot read project configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.Version != 1 || c.Projects == nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid project configuration")
	}
	for project, keys := range c.Projects {
		if !ValidProjectName(project) {
			return c, errors.New("invalid project configuration")
		}
		seen := map[Key]bool{}
		for _, k := range keys {
			if k.Project != project || k.Validate() != nil || seen[k] {
				return c, errors.New("invalid project configuration")
			}
			seen[k] = true
		}
	}
	if !separateSigningUses(c) {
		return c, errors.New("a signing reference cannot also be readable")
	}
	return c, nil
}

func separateSigningUses(c config) bool {
	uses := map[[2]string]string{}
	for _, keys := range c.Projects {
		for _, k := range keys {
			id := [2]string{k.Account, k.Ref}
			if use, ok := uses[id]; ok && use != k.Use {
				return false
			}
			uses[id] = k.Use
		}
	}
	return true
}

func saveConfig(home string, c config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil || len(data) > 1<<20 {
		return errors.New("project configuration is too large")
	}
	f, err := os.CreateTemp(home, ".projects-*")
	if err != nil {
		return errors.New("cannot save project configuration")
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(f.Name(), filepath.Join(home, "projects.json")) != nil {
		return errors.New("cannot save project configuration")
	}
	dir, err := os.Open(home)
	if err != nil {
		return errors.New("cannot confirm project configuration durability")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("cannot confirm project configuration durability")
	}
	return nil
}
