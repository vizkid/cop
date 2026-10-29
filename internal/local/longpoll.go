package local

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// A replica long-polls topcop: topcop answers when the state changes, or with
// "unchanged" after longPollWait. The connection stays open and each side
// checks Tailscale identity once per connection, not once per request.
const (
	longPollWait = 30 * time.Second
	// pollSlack is how long past the wait a replica gives topcop to answer.
	pollSlack = 10 * time.Second
)

type pollRequest struct {
	Since string `json:"since"`
}

func newTokenKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func (s *Service) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// stateTokenLocked signs everything a snapshot carries except Remaining, which
// moves every instant. The HMAC key keeps values out of the token.
func (s *Service) stateTokenLocked() string {
	s.pruneLocked()
	mac := hmac.New(sha256.New, s.tokenKey)
	field := func(tag string, data []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(data)))
		mac.Write([]byte(tag))
		mac.Write(size[:])
		mac.Write(data)
	}
	name := func(k Key) []byte { data, _ := json.Marshal(k); return data }
	for _, project := range slices.Sorted(func(yield func(string) bool) {
		for p := range s.config.Projects {
			if !yield(p) {
				return
			}
		}
	}) {
		field("p", []byte(project))
		for _, k := range s.config.Projects[project] {
			field("k", name(k))
		}
	}
	cached := make([]Key, 0, len(s.cache))
	for k := range s.cache {
		cached = append(cached, k)
	}
	slices.SortFunc(cached, func(a, b Key) int { return bytes.Compare(name(a), name(b)) })
	for _, k := range cached {
		e := s.cache[k]
		var expires [8]byte
		binary.BigEndian.PutUint64(expires[:], uint64(e.expires.UnixNano()))
		field("e", name(k))
		field("v", e.value.pages[:e.value.size])
		field("t", expires[:])
	}
	expired := make([]string, 0, len(s.expired))
	for k := range s.expired {
		expired = append(expired, string(name(k)))
	}
	slices.Sort(expired)
	field("x", []byte(strings.Join(expired, "\n")))
	return hex.EncodeToString(mac.Sum(nil))
}

// waitSnapshot returns the state once its token differs from since. At the
// deadline it checks the token once more, so a missed signal costs at most one
// wait, then reports unchanged.
func (s *Service) waitSnapshot(ctx context.Context, since string, wait time.Duration) snapshot {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for last := false; ; {
		s.mu.Lock()
		token := s.stateTokenLocked()
		changed := s.changed
		if since == "" || token != since {
			v := s.snapshotLocked()
			s.mu.Unlock()
			v.Token = token
			return v
		}
		s.mu.Unlock()
		if last {
			return snapshot{Protocol: 1, Token: token, Unchanged: true}
		}
		select {
		case <-changed:
		case <-timer.C:
			last = true
		case <-ctx.Done():
			return snapshot{Protocol: 1, Token: token, Unchanged: true}
		case <-s.ctx.Done():
			return snapshot{Protocol: 1, Token: token, Unchanged: true}
		}
	}
}

// connPeer caches one connection's Tailscale identity after a successful check.
type connPeer struct {
	mu sync.Mutex
	id string
}
type connPeerKey struct{}

func withConnPeer(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connPeerKey{}, &connPeer{})
}

// peerID checks identity on a connection's first request and reuses it after.
// WireGuard binds a connection to one node, so the answer cannot change.
func (r *replication) peerID(q *http.Request) (string, error) {
	c, _ := q.Context().Value(connPeerKey{}).(*connPeer)
	if c == nil {
		return r.identity.Lookup(q.Context(), q.RemoteAddr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.id == "" {
		id, err := r.identity.Lookup(q.Context(), q.RemoteAddr)
		if err != nil || id == "" {
			return "", errors.New("Tailscale peer identity unavailable")
		}
		c.id = id
	}
	return c.id, nil
}

// pollClientLocked keeps one client per topcop. Each new connection checks
// topcop's identity before it dials.
func (r *replication) pollClientLocked(node Node) *http.Client {
	if r.poller != nil && r.pollerNode == node {
		return r.poller
	}
	if r.poller != nil {
		r.poller.CloseIdleConnections()
	}
	transport := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 1, IdleConnTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			id, err := r.identity.Lookup(ctx, node.Address)
			if err != nil || id != node.ID {
				return nil, errors.New("Tailscale peer identity changed or is unavailable")
			}
			if r.dial != nil {
				return r.dial(ctx, network, address)
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		}}
	r.poller = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r.pollerNode = node
	return r.poller
}

// fetch copies topcop's state. With wait, topcop holds the request until the
// state changes, the request uses the kept connection, and fetch takes syncMu
// only to install. Without wait, it opens a fresh connection with a fresh
// identity check. It reports whether topcop answered a waiting request, so the
// caller knows when to pace itself.
func (r *replication) fetch(ctx context.Context, wait bool) (bool, error) {
	r.mu.Lock()
	if !r.isReplicaLocked() {
		r.mu.Unlock()
		return false, nil
	}
	topcop, generation, installs := r.topology.Topcop, r.generation, r.installs
	since, client := "", (*http.Client)(nil)
	if wait {
		since, client = r.token, r.pollClientLocked(topcop)
	}
	r.mu.Unlock()
	start := time.Now()
	var v snapshot
	defer v.erase()
	var err error
	if wait {
		err = post(ctx, client, topcop, "/snapshot", pollRequest{Since: since}, &v)
	} else {
		err = r.call(ctx, topcop, "/snapshot", pollRequest{}, &v)
	}
	if wait {
		r.syncMu.Lock()
		defer r.syncMu.Unlock()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.generation != generation {
		// The topology changed while fetching; this snapshot may come from a replaced authority.
		return false, errors.New("topology changed during sync; retry")
	}
	if wait && r.installs != installs {
		// A sync installed state while this request waited; ask again from that state.
		return true, nil
	}
	if err == nil {
		err = r.applyLocked(v, since, time.Since(start))
	}
	r.connected = err == nil
	if err != nil {
		r.failure = "topcop sync failed; existing unexpired cache remains available"
		return false, err
	}
	r.failure = ""
	r.lastSync = time.Now().UTC()
	return v.Token != "", nil
}

func (r *replication) applyLocked(v snapshot, since string, elapsed time.Duration) error {
	if v.Unchanged {
		if since == "" || v.Token != since {
			return errors.New("invalid cache snapshot")
		}
		return nil
	}
	if err := r.service.installSnapshot(v, elapsed); err != nil {
		return err
	}
	r.token = v.Token
	r.installs++
	return nil
}

func (r *replication) poll() {
	for r.service.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(r.service.ctx, longPollWait+pollSlack)
		waited, err := r.fetch(ctx, true)
		cancel()
		if err == nil && waited {
			continue
		}
		// After an error, or with a topcop that cannot wait, pace the requests.
		select {
		case <-r.service.ctx.Done():
			return
		case <-time.After(syncInterval):
		}
	}
}

// post sends one JSON request to a peer and decodes exactly one JSON answer.
func post(ctx context.Context, client *http.Client, node Node, path string, input, output any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("invalid peer request")
	}
	defer clear(data)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+node.Address+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid peer request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("cop peer unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("cop peer refused request; confirm admission and topcop selection")
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, maxSnapshot+1))
	if d.Decode(output) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid cop peer response")
	}
	return nil
}
