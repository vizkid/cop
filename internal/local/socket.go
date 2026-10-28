package local

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func Serve(ctx context.Context, home string, resolver Resolver, ttl, timeout time.Duration, ready func(), options ...ReplicationOptions) error {
	if err := PrepareHome(home); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(home, "service.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot open service lock")
	}
	defer lock.Close()
	if err := checkOwned(lock.Name(), false); err != nil {
		return err
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("a service already owns this cop home")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := filepath.Join(home, "service.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || checkOwned(path, false) != nil {
			return errors.New("unsafe existing socket path")
		}
		// The exclusive lock proves that no cooperating cop service owns this socket.
		if os.Remove(path) != nil {
			return errors.New("cannot remove stale socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect socket path")
	}
	var batch BatchResolver
	if len(options) > 0 {
		batch = options[0].Batch
	}
	s, err := New(home, resolver, ttl, timeout, batch)
	if err != nil {
		return err
	}
	defer s.Close()
	if len(options) > 0 && options[0].Identity != nil {
		network, e := startReplication(s, options[0])
		if e != nil {
			return e
		}
		s.network = network
		defer network.close()
		s.replicaMode = network.replica()
		s.wg.Add(1)
		go func() { defer s.wg.Done(); network.poll() }()
	} else if _, e := os.Lstat(filepath.Join(home, "network.json")); !errors.Is(e, os.ErrNotExist) {
		return errors.New("network configuration exists; start copd with --tailscale")
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return errors.New("cannot bind local socket; check cop home and Unix path length")
	}
	defer l.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return errors.New("cannot protect local socket")
	}
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodPost || r.URL.Path != "/v1" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
			d.DisallowUnknownFields()
			var request Request
			if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(Result{Error: "invalid request"})
				return
			}
			result := s.Handle(r.Context(), request)
			defer clear(result.Value)
			_ = json.NewEncoder(w).Encode(result)
		}),
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
			_ = server.Close()
		case <-done:
		}
	}()
	if !s.replicaMode {
		s.preload()
	}
	if ready != nil {
		ready()
	}
	if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("local service stopped unexpectedly")
	}
	return nil
}

func Call(ctx context.Context, home string, request Request) (Result, error) {
	var result Result
	if err := checkOwned(home, true); err != nil {
		return result, errors.New("cop home unavailable or unsafe")
	}
	path := filepath.Join(home, "service.sock")
	if err := checkOwned(path, false); err != nil {
		return result, errors.New("cop socket unavailable or unsafe; start cop serve")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	data, err := json.Marshal(request)
	if err != nil {
		return result, errors.New("invalid request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cop/v1", bytes.NewReader(data))
	if err != nil {
		return result, errors.New("invalid request")
	}
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return result, errors.New("cop service unavailable or request canceled")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, errors.New("cop service refused request")
	}
	if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&result) != nil {
		return Result{}, errors.New("invalid service response")
	}
	if result.Error != "" {
		clear(result.Value)
		return Result{}, errors.New(result.Error)
	}
	return result, nil
}
