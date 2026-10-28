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
	"reflect"
	"sync"
	"time"
)

const maxSnapshot = 16 << 20

type ReplicationOptions struct {
	Batch    BatchResolver
	Identity Identity
	Port     int
	listen   func(string, string) (net.Listener, error)
	dial     func(context.Context, string, string) (net.Conn, error)
}

type topology struct {
	Self   Node            `json:"self"`
	Topcop Node            `json:"topcop"`
	Peers  map[string]Node `json:"peers"`
}

type NetworkStatus struct {
	Protocol  int       `json:"protocol"`
	Self      Node      `json:"self"`
	Topcop    Node      `json:"topcop"`
	Connected bool      `json:"connected"`
	LastSync  time.Time `json:"last_sync,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// mu guards topology state and is never held across network I/O, so cached
// replica operations never wait on topcop. syncMu orders snapshot installs.
type replication struct {
	mu        sync.Mutex
	syncMu    sync.Mutex
	service   *Service
	identity  Identity
	topology  topology
	connected bool
	lastSync  time.Time
	failure   string
	server    *http.Server
	done      chan struct{}
	dial      func(context.Context, string, string) (net.Conn, error)
	// generation changes on every saved topology, invalidating in-flight syncs.
	generation uint64
}

type peerMessage struct {
	Node    Node    `json:"node"`
	Request Request `json:"request"`
}

type wireEntry struct {
	Key       Key           `json:"key"`
	Value     []byte        `json:"value"`
	Expires   time.Time     `json:"expires"`
	Remaining time.Duration `json:"remaining"`
}

type snapshot struct {
	Protocol int              `json:"protocol"`
	Projects map[string][]Key `json:"projects"`
	Entries  []wireEntry      `json:"entries"`
	Expired  []Key            `json:"expired"`
}

func (v *snapshot) erase() {
	for i := range v.Entries {
		clear(v.Entries[i].Value)
	}
}

func startReplication(s *Service, options ReplicationOptions) (*replication, error) {
	self, err := options.Identity.Self(s.ctx, options.Port)
	if err != nil {
		return nil, err
	}
	r := &replication{service: s, identity: options.Identity, topology: topology{Self: self, Peers: map[string]Node{}}, done: make(chan struct{})}
	path := filepath.Join(s.home, "network.json")
	if _, err := os.Lstat(path); err == nil {
		if checkOwned(path, false) != nil {
			return nil, errors.New("unsafe network configuration")
		}
		data, e := os.ReadFile(path)
		if e != nil || len(data) > 1<<20 || json.Unmarshal(data, &r.topology) != nil || r.topology.Self != self || r.topology.Peers == nil {
			return nil, errors.New("network configuration does not match this Tailscale node and port")
		}
		if err := r.validateTopology(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("cannot read network configuration")
	}
	listen := options.listen
	if listen == nil {
		listen = net.Listen
	}
	r.dial = options.dial
	l, err := listen("tcp", self.Address)
	if err != nil {
		return nil, errors.New("cannot bind Tailscale listener")
	}
	r.server = &http.Server{Handler: http.HandlerFunc(r.serveHTTP), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 6 * time.Minute, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { defer close(r.done); _ = r.server.Serve(l) }()
	return r, nil
}
func (r *replication) validateTopology() error {
	if r.topology.Topcop.ID != "" {
		if _, err := peerAddress(r.topology.Topcop.Address); err != nil {
			return err
		}
	}
	for id, node := range r.topology.Peers {
		if id == "" || node.ID != id {
			return errors.New("invalid peer configuration")
		}
		if _, err := peerAddress(node.Address); err != nil {
			return err
		}
	}
	return nil
}
func (r *replication) saveLocked() error {
	data, err := json.MarshalIndent(r.topology, "", "  ")
	if err != nil || len(data) > 1<<20 {
		return errors.New("network configuration too large")
	}
	f, err := os.CreateTemp(r.service.home, ".network-*")
	if err != nil {
		return errors.New("cannot save network configuration")
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || os.Rename(f.Name(), filepath.Join(r.service.home, "network.json")) != nil {
		return errors.New("cannot save network configuration")
	}
	r.generation++
	return nil
}
func (r *replication) isReplicaLocked() bool {
	return r.topology.Topcop.ID != "" && r.topology.Topcop.ID != r.topology.Self.ID
}
func (r *replication) replica() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.isReplicaLocked() }
func (r *replication) status() *NetworkStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &NetworkStatus{Protocol: 1, Self: r.topology.Self, Topcop: r.topology.Topcop, Connected: r.connected || r.topology.Topcop.ID == r.topology.Self.ID, LastSync: r.lastSync, Error: r.failure}
}
func (r *replication) close() { _ = r.server.Close(); <-r.done }

// Every request uses a direct Tailscale address and checks the stable node ID.
func (r *replication) call(ctx context.Context, node Node, path string, input, output any) error {
	ctx, cancelService := context.WithCancel(ctx)
	defer cancelService()
	stop := context.AfterFunc(r.service.ctx, cancelService)
	defer stop()
	id, err := r.identity.Lookup(ctx, node.Address)
	if err != nil || id != node.ID {
		return errors.New("Tailscale peer identity changed or is unavailable")
	}
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("invalid peer request")
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+node.Address+path, bytes.NewReader(data))
	if err != nil {
		return errors.New("invalid peer request")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	if r.dial != nil {
		transport.DialContext = r.dial
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
func (r *replication) serveHTTP(w http.ResponseWriter, q *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if q.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id, err := r.identity.Lookup(q.Context(), q.RemoteAddr)
	if err != nil || id == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	r.mu.Lock()
	top := r.topology.Topcop
	self := r.topology.Self
	_, admitted := r.topology.Peers[id]
	r.mu.Unlock()
	// Discovery returns topology metadata only, never project names or values.
	if q.URL.Path == "/hello" {
		_ = json.NewEncoder(w).Encode(NetworkStatus{Protocol: 1, Self: self, Topcop: top})
		return
	}
	if !admitted || top.ID != self.ID {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch q.URL.Path {
	case "/snapshot":
		v := r.service.snapshot()
		defer v.erase()
		_ = json.NewEncoder(w).Encode(v)
	case "/action", "/admit":
		var msg peerMessage
		d := json.NewDecoder(http.MaxBytesReader(w, q.Body, 128<<10))
		d.DisallowUnknownFields()
		if d.Decode(&msg) != nil || d.Decode(new(any)) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if q.URL.Path == "/admit" {
			if r.admit(q.Context(), msg.Node) != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(Result{Status: "peer admitted"})
			return
		}
		switch msg.Request.Action {
		case "create", "allow", "revoke", "clear", "request":
		default:
			w.WriteHeader(http.StatusForbidden)
			return
		}
		result := r.service.handleLocal(q.Context(), msg.Request)
		clear(result.Value)
		result.Value = nil
		_ = json.NewEncoder(w).Encode(result)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
func (r *replication) admit(ctx context.Context, node Node) error {
	id, err := r.identity.Lookup(ctx, node.Address)
	if err != nil || id != node.ID {
		return errors.New("peer identity mismatch")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.topology.Topcop.ID != r.topology.Self.ID {
		return errors.New("only topcop admits peers")
	}
	old, exists := r.topology.Peers[id]
	r.topology.Peers[id] = node
	if err := r.saveLocked(); err != nil {
		if exists {
			r.topology.Peers[id] = old
		} else {
			delete(r.topology.Peers, id)
		}
		return err
	}
	return nil
}

func (r *replication) connect(ctx context.Context, address, choice string) error {
	if choice != "" && choice != "local" && choice != "remote" {
		return errors.New("topcop must be local or remote")
	}
	address, err := peerAddress(address)
	if err != nil {
		return err
	}
	id, err := r.identity.Lookup(ctx, address)
	if err != nil {
		return err
	}
	remote := Node{id, address}
	var info NetworkStatus
	if err := r.call(ctx, remote, "/hello", nil, &info); err != nil {
		return err
	}
	if info.Protocol != 1 || info.Self != remote {
		return errors.New("peer announced a different Tailscale identity")
	}
	// Verify the announced topcop before locking; the lock never waits on Tailscale.
	if info.Topcop.ID != "" && info.Topcop != remote {
		leaderID, err := r.identity.Lookup(ctx, info.Topcop.Address)
		if err != nil || leaderID != info.Topcop.ID {
			return errors.New("announced topcop identity mismatch")
		}
	}
	admit, err := r.joinLocked(remote, info.Topcop, choice)
	if err != nil {
		return err
	}
	if admit != nil {
		var result Result
		return r.call(ctx, *admit, "/admit", peerMessage{Node: remote}, &result)
	}
	return r.sync(ctx)
}

// joinLocked applies the topology change for connect and returns the topcop to
// ask for admission, if any. Network calls happen after it releases the lock.
func (r *replication) joinLocked(remote, announced Node, choice string) (*Node, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if remote.ID == r.topology.Self.ID {
		return nil, errors.New("cannot connect cop to itself")
	}
	current := r.topology.Topcop
	if current.ID != "" && announced.ID != "" && current != announced {
		return nil, errors.New("groups have different topcops; refusing implicit replacement")
	}
	if current.ID == "" && announced.ID == "" {
		if choice != "local" {
			return nil, errors.New("select the first topcop on that machine with connect --topcop local PEER")
		}
		previous := r.topology
		r.topology.Topcop = r.topology.Self
		r.topology.Peers = map[string]Node{remote.ID: remote}
		if err := r.saveLocked(); err != nil {
			r.topology = previous
			return nil, err
		}
		return nil, nil
	}
	if current.ID == "" {
		if choice == "local" {
			return nil, errors.New("peer already has a topcop; joining cops inherit it")
		}
		// Persist the selected authority before fetching, so outages cannot fall back to local authentication.
		r.topology.Topcop = announced
		if err := r.saveLocked(); err != nil {
			r.topology.Topcop = current
			return nil, err
		}
		r.service.mu.Lock()
		r.service.replicaMode = true
		r.service.invalidateLocked(func(Key) bool { return true })
		r.service.mu.Unlock()
		return nil, nil
	}
	if choice == "local" && current.ID != r.topology.Self.ID || choice == "remote" && announced.ID == "" {
		return nil, errors.New("joining cops must inherit the existing topcop")
	}
	if current.ID == r.topology.Self.ID {
		old, exists := r.topology.Peers[remote.ID]
		r.topology.Peers[remote.ID] = remote
		if err := r.saveLocked(); err != nil {
			if exists {
				r.topology.Peers[remote.ID] = old
			} else {
				delete(r.topology.Peers, remote.ID)
			}
			return nil, err
		}
		return nil, nil
	}
	if announced.ID == "" {
		return &current, nil
	}
	return nil, nil
}

func (s *Service) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	v := snapshot{Protocol: 1, Projects: map[string][]Key{}, Entries: []wireEntry{}, Expired: []Key{}}
	for p, keys := range s.config.Projects {
		v.Projects[p] = append([]Key{}, keys...)
	}
	for k, e := range s.cache {
		v.Entries = append(v.Entries, wireEntry{k, bytes.Clone(e.value.pages[:e.value.size]), e.expires.UTC(), time.Until(e.expires)})
	}
	for k := range s.expired {
		v.Expired = append(v.Expired, k)
	}
	return v
}
func (s *Service) installSnapshot(v snapshot, elapsed time.Duration) error {
	c := config{Version: 1, Projects: v.Projects}
	if v.Protocol != 1 || c.Projects == nil || !separateSigningUses(c) || len(v.Entries) > 128 {
		return errors.New("invalid cache snapshot")
	}
	allowed := map[Key]bool{}
	for p, keys := range c.Projects {
		if !ValidProjectName(p) {
			return errors.New("invalid replicated project")
		}
		for _, k := range keys {
			if k.Project != p || k.Validate() != nil || allowed[k] {
				return errors.New("invalid replicated authorization")
			}
			allowed[k] = true
		}
	}
	entries := map[Key]entry{}
	expired := map[Key]bool{}
	defer func() {
		for _, e := range entries {
			e.value.destroy()
		}
	}()
	for _, k := range v.Expired {
		if !allowed[k] {
			return errors.New("invalid expired identity")
		}
		expired[k] = true
	}
	seen := map[Key]bool{}
	for _, e := range v.Entries {
		if !allowed[e.Key] || seen[e.Key] || len(e.Value) > MaxSecret || bytes.IndexByte(e.Value, 0) >= 0 {
			return errors.New("invalid replicated value")
		}
		seen[e.Key] = true
		if e.Key.Use == "ssh-sign" {
			private, err := parseSigningKey(e.Value, e.Key.PublicKey)
			clear(private)
			if err != nil {
				return errors.New("invalid replicated signing identity")
			}
		}
		remaining := min(e.Remaining-elapsed, time.Until(e.Expires))
		if remaining <= 0 {
			expired[e.Key] = true
			continue
		}
		stored, err := keep(e.Value)
		if err != nil {
			return errors.New("replica secret memory unavailable")
		}
		entries[e.Key] = entry{value: stored, expires: time.Now().Add(remaining)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("service stopped")
	}
	if !reflect.DeepEqual(s.config, c) {
		if err := saveConfig(s.home, c); err != nil {
			s.closed = true
			s.cancel()
			s.invalidateLocked(func(Key) bool { return true })
			return errors.New("cannot save replicated authorizations; service stopped")
		}
	}
	s.invalidateLocked(func(Key) bool { return true })
	s.config = c
	s.expired = expired
	s.cache = entries
	entries = nil
	return nil
}
func (r *replication) sync(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.mu.Lock()
	if !r.isReplicaLocked() {
		r.mu.Unlock()
		return nil
	}
	topcop, generation := r.topology.Topcop, r.generation
	r.mu.Unlock()
	start := time.Now()
	var v snapshot
	defer v.erase()
	err := r.call(ctx, topcop, "/snapshot", nil, &v)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.generation != generation {
		// The topology changed while fetching; this snapshot may come from a replaced authority.
		return errors.New("topology changed during sync; retry")
	}
	if err == nil {
		err = r.service.installSnapshot(v, time.Since(start))
	}
	r.connected = err == nil
	if err != nil {
		r.failure = "topcop sync failed; existing unexpired cache remains available"
		return err
	}
	r.failure = ""
	r.lastSync = time.Now().UTC()
	return nil
}
func (r *replication) poll() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.service.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(r.service.ctx, 10*time.Second)
		_ = r.sync(ctx)
		cancel()
	}
}
func (r *replication) forward(ctx context.Context, request Request) Result {
	r.mu.Lock()
	replica, topcop := r.isReplicaLocked(), r.topology.Topcop
	r.mu.Unlock()
	if !replica {
		return r.service.handleLocal(ctx, request)
	}
	original := request.Action
	data := request.Data
	if original == "deliver" || original == "sign" || original == "request" {
		if original == "deliver" && request.Use == "ssh-sign" {
			return Result{Error: "signing keys cannot be read or exported"}
		}
		s := r.service
		s.mu.Lock()
		s.pruneLocked()
		_, hit := s.cache[request.Key]
		allowed := s.allowedLocked(request.Key)
		s.mu.Unlock()
		if hit && allowed {
			return s.handleLocal(ctx, request)
		}
		request.Action = "request"
		request.Data = nil
	}
	var result Result
	if err := r.call(ctx, topcop, "/action", peerMessage{Request: request}, &result); err != nil {
		return Result{Error: err.Error()}
	}
	if result.Error != "" {
		return result
	}
	if err := r.sync(ctx); err != nil {
		return Result{Error: err.Error()}
	}
	if original == "deliver" || original == "sign" || original == "request" {
		request.Action = original
		request.Data = data
		// Signing data is retained only in the original local request.
		return r.service.handleLocal(ctx, request)
	}
	return result
}
