package local

import (
	"errors"
	"syscall"
)

type secret struct {
	pages []byte
	size  int
}

func keep(value []byte) (*secret, error) {
	pages, err := syscall.Mmap(-1, 0, max(1, len(value)), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, errors.New("secret memory unavailable")
	}
	if err = syscall.Mlock(pages); err != nil {
		_ = syscall.Munmap(pages)
		return nil, errors.New("cannot lock secret memory")
	}
	copy(pages, value)
	return &secret{pages, len(value)}, nil
}

func (s *secret) destroy() {
	clear(s.pages)
	_ = syscall.Munlock(s.pages)
	_ = syscall.Munmap(s.pages)
	s.pages = nil
}

func DisableCoreDumps() error {
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}) != nil {
		return errors.New("cannot disable core dumps")
	}
	return nil
}
