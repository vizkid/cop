package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testMesh struct {
	mu         sync.Mutex
	endpoints  map[string]string
	identities map[string]string
}
type testIdentity struct {
	mesh *testMesh
	self Node
}

func (i testIdentity) Self(context.Context, int) (Node, error) { return i.self, nil }
func (i testIdentity) Lookup(_ context.Context, address string) (string, error) {
	i.mesh.mu.Lock()
	defer i.mesh.mu.Unlock()
	id := i.mesh.identities[address]
	if id == "" {
		return "", errors.New("unknown fake peer")
	}
	return id, nil
}
func newMesh() *testMesh {
	return &testMesh{endpoints: map[string]string{}, identities: map[string]string{}}
}
func (m *testMesh) attach(t *testing.T, s *Service, n int) *replication {
	t.Helper()
	node := Node{fmt.Sprintf("node-%d", n), fmt.Sprintf("100.64.0.%d:8787", n)}
	m.mu.Lock()
	m.identities[node.Address] = node.ID
	m.mu.Unlock()
	options := ReplicationOptions{Identity: testIdentity{m, node}, Port: 8787,
		listen: func(_, address string) (net.Listener, error) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				m.mu.Lock()
				m.endpoints[address] = l.Addr().String()
				m.mu.Unlock()
			}
			return l, err
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			m.mu.Lock()
			endpoint := m.endpoints[address]
			m.mu.Unlock()
			conn, err := (&net.Dialer{}).DialContext(ctx, network, endpoint)
			if err == nil {
				m.mu.Lock()
				m.identities[conn.LocalAddr().String()] = node.ID
				m.mu.Unlock()
			}
			return conn, err
		},
	}
	r, err := startReplication(s, options)
	if err != nil {
		t.Fatal(err)
	}
	s.network = r
	s.replicaMode = r.replica()
	t.Cleanup(r.close)
	return r
}
func connectTest(t *testing.T, r *replication, other *replication, choice string) {
	t.Helper()
	if err := r.connect(context.Background(), other.topology.Self.Address, choice); err != nil {
		t.Fatal(err)
	}
}
func syncTest(t *testing.T, r *replication) {
	t.Helper()
	if err := r.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReplicationAdmissionInheritanceExpiryAndRevocation(t *testing.T) {
	mesh := newMesh()
	var calls atomic.Int32
	leader := newTestService(t, func(context.Context, Key) ([]byte, error) { calls.Add(1); return []byte(sentinel), nil }, 7*24*time.Hour)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) {
		t.Error("replica invoked local resolver")
		return nil, errors.New("forbidden")
	}, time.Hour)
	third := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, errors.New("forbidden") }, time.Hour)
	a, b, c := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2), mesh.attach(t, third, 3)
	authorize(t, leader, testKey)
	handle(t, leader, "request", testKey)
	if err := a.connect(context.Background(), b.topology.Self.Address, ""); err == nil {
		t.Fatal("implicit election allowed")
	}
	connectTest(t, a, b, "local")
	// Knowing the address and sharing the tailnet does not grant access.
	var denied snapshot
	if err := c.call(context.Background(), a.topology.Self, "/snapshot", nil, &denied); err == nil {
		t.Fatal("unadmitted peer received secrets")
	}
	connectTest(t, b, a, "")
	got := handle(t, follower, "deliver", testKey)
	if string(got.Value) != sentinel {
		t.Fatal("replication did not deliver cached value")
	}
	clear(got.Value)
	leader.mu.Lock()
	deadline := leader.cache[testKey].expires
	leader.mu.Unlock()
	follower.mu.Lock()
	replicaDeadline := follower.cache[testKey].expires
	follower.mu.Unlock()
	if replicaDeadline.After(deadline) {
		t.Fatal("replication extended expiry")
	}
	// Any admitted member can connect another cop; the existing leader is inherited.
	connectTest(t, b, c, "")
	connectTest(t, c, b, "")
	if c.status().Topcop.ID != a.topology.Self.ID {
		t.Fatal("third cop did not inherit topcop")
	}
	if calls.Load() != 1 {
		t.Fatal("replication refetched from vault")
	}
	// Revocation is applied on sync, including the saved allowlist.
	handle(t, leader, "revoke", testKey)
	syncTest(t, b)
	if r := follower.Handle(context.Background(), Request{Action: "deliver", Key: testKey}); r.Error == "" {
		t.Fatal("revocation not enforced")
	}
	// Group conflicts never silently replace authority.
	fourth := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, nil }, time.Hour)
	d := mesh.attach(t, fourth, 4)
	fifth := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, nil }, time.Hour)
	e := mesh.attach(t, fifth, 5)
	connectTest(t, d, e, "local")
	if err := b.connect(context.Background(), d.topology.Self.Address, "local"); err == nil {
		t.Fatal("conflicting topcop accepted")
	}
	// Metadata files contain no credential values.
	for _, s := range []*Service{leader, follower, third} {
		for _, name := range []string{"projects.json", "network.json"} {
			data, err := os.ReadFile(filepath.Join(s.home, name))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(sentinel)) {
				t.Fatal("credential persisted")
			}
		}
	}
}

func TestReplicaOfflineCacheAndNoLocalFallback(t *testing.T) {
	mesh := newMesh()
	leader := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), nil }, time.Hour)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) { t.Error("replica fell back locally"); return nil, nil }, time.Hour)
	a, b := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2)
	authorize(t, leader, testKey)
	handle(t, leader, "request", testKey)
	connectTest(t, a, b, "local")
	connectTest(t, b, a, "")
	a.server.Close()
	if result := handle(t, follower, "deliver", testKey); string(result.Value) != sentinel {
		t.Fatal("offline cache failed")
	}
	follower.mu.Lock()
	e := follower.cache[testKey]
	e.expires = time.Now().Add(-time.Second)
	follower.cache[testKey] = e
	follower.mu.Unlock()
	if result := follower.Handle(context.Background(), Request{Action: "request", Key: testKey}); result.Error == "" {
		t.Fatal("expired offline key accepted")
	}
	// Restart keeps topology metadata, but never retains the cache or uses local authentication.
	b.close()
	follower.Close()
	restarted, err := New(follower.home, func(context.Context, Key) ([]byte, error) { t.Error("restart used local resolver"); return nil, nil }, time.Hour, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	rb := mesh.attach(t, restarted, 2)
	if !rb.replica() || len(handle(t, restarted, "status", Key{}).View.Cache) != 0 {
		t.Fatal("restart did not preserve empty replica state")
	}
	if result := restarted.Handle(context.Background(), Request{Action: "request", Key: testKey}); result.Error == "" {
		t.Fatal("restart recovered persisted secret")
	}
}

func TestReplicatedSigningOnlyKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(private.Public())
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(block)
	defer clear(encoded)
	k := testKey
	k.Use = "ssh-sign"
	k.PublicKey = string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub)))
	mesh := newMesh()
	leader := newTestService(t, func(context.Context, Key) ([]byte, error) { return bytes.Clone(encoded), nil }, time.Hour)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, errors.New("no local vault") }, time.Hour)
	a, b := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2)
	authorize(t, leader, k)
	handle(t, leader, "request", k)
	connectTest(t, a, b, "local")
	connectTest(t, b, a, "")
	data := []byte("synthetic git payload")
	result := follower.Handle(context.Background(), Request{Action: "sign", Key: k, Data: data})
	if result.Error != "" || !ed25519.Verify(private.Public().(ed25519.PublicKey), data, result.Signature) {
		t.Fatal("replica signature failed")
	}
	if result := follower.Handle(context.Background(), Request{Action: "deliver", Key: k}); result.Error == "" {
		t.Fatal("replicated signing key exported")
	}
	// Invalid snapshots leave the existing cache intact.
	v := leader.snapshot()
	defer v.erase()
	v.Entries[0].Value = []byte("not a private key")
	if follower.installSnapshot(v, 0) == nil {
		t.Fatal("invalid signing snapshot accepted")
	}
	status, _ := json.Marshal(handle(t, follower, "status", Key{}))
	if bytes.Contains(status, encoded) {
		t.Fatal("status exported private key")
	}
}

func TestPeerAddressRejectsNonTailscaleEndpoints(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8787", "example.com:8787", "192.168.1.1:8787", "100.64.0.1:0", "100.64.0.1:70000", "http://100.64.0.1:8787"} {
		if _, err := peerAddress(address); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
}

func TestReplicaExpiryRequestsProjectRefillOnTopcop(t *testing.T) {
	mesh := newMesh()
	var mu sync.Mutex
	counts := map[Key]int{}
	leader := newTestService(t, func(_ context.Context, k Key) ([]byte, error) {
		mu.Lock()
		counts[k]++
		mu.Unlock()
		return []byte(sentinel), nil
	}, 7*24*time.Hour)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) { t.Error("local resolution on replica"); return nil, nil }, time.Hour)
	a, b := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2)
	second := testKey
	second.Ref = "op://test/item/second"
	other := testKey
	other.Project = "other"
	for _, k := range []Key{testKey, second, other} {
		authorize(t, leader, k)
		handle(t, leader, "request", k)
	}
	connectTest(t, a, b, "local")
	connectTest(t, b, a, "")
	leader.mu.Lock()
	e := leader.cache[testKey]
	e.expires = time.Now().Add(-time.Second)
	leader.cache[testKey] = e
	leader.mu.Unlock()
	syncTest(t, b)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); handle(t, follower, "request", testKey) }()
	}
	wg.Wait()
	handle(t, leader, "request", second)
	syncTest(t, b)
	mu.Lock()
	defer mu.Unlock()
	if counts[testKey] != 2 || counts[second] != 2 || counts[other] != 1 {
		t.Fatal("refill duplicated or crossed project boundary")
	}
	// Peer pinning detects a changed node even at the same address.
	mesh.mu.Lock()
	mesh.identities[a.topology.Self.Address] = "replacement"
	mesh.mu.Unlock()
	if b.sync(context.Background()) == nil {
		t.Fatal("changed identity accepted")
	}
}

func TestReplicaCachedOperationsIgnoreStalledTopcop(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(private.Public())
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(block)
	defer clear(encoded)
	signing := testKey
	signing.Ref = "op://test/item/signing"
	signing.Use = "ssh-sign"
	signing.PublicKey = string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub)))
	slow := testKey
	slow.Ref = "op://test/item/slow"
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	mesh := newMesh()
	// The approval wait must outlast every cached check below.
	leader, err := New(t.TempDir(), func(ctx context.Context, k Key) ([]byte, error) {
		switch k {
		case signing:
			return bytes.Clone(encoded), nil
		case slow:
			// Simulates a desktop approval prompt that nobody has answered yet.
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte(sentinel), nil
	}, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leader.Close)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, errors.New("no local vault") }, time.Hour)
	a, b := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2)
	for _, k := range []Key{testKey, signing, slow} {
		authorize(t, leader, k)
	}
	handle(t, leader, "request", testKey)
	handle(t, leader, "request", signing)
	connectTest(t, a, b, "local")
	connectTest(t, b, a, "")
	stalled := make(chan Result, 1)
	go func() { stalled <- follower.Handle(context.Background(), Request{Action: "request", Key: slow}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		leader.mu.Lock()
		j := leader.inflight[slow]
		active := j != nil && j.State == "active"
		leader.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forwarded request never reached topcop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data := []byte("synthetic git payload")
	for name, request := range map[string]Request{
		"deliver": {Action: "deliver", Key: testKey},
		"sign":    {Action: "sign", Key: signing, Data: data},
		"status":  {Action: "status"},
	} {
		done := make(chan Result, 1)
		go func() { done <- follower.Handle(context.Background(), request) }()
		select {
		case result := <-done:
			if result.Error != "" {
				t.Fatalf("cached %s failed: %s", name, result.Error)
			}
			clear(result.Value)
		case <-time.After(time.Second):
			t.Fatalf("cached %s waited on a stalled topcop request", name)
		}
	}
	close(release)
	select {
	case result := <-stalled:
		if result.Error != "" {
			t.Fatalf("forwarded request failed after approval: %s", result.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwarded request did not finish after approval")
	}
}

func TestReplicaDiscardsSnapshotFetchedBeforeTopologyChange(t *testing.T) {
	mesh := newMesh()
	leader := newTestService(t, func(context.Context, Key) ([]byte, error) { return []byte(sentinel), nil }, time.Hour)
	follower := newTestService(t, func(context.Context, Key) ([]byte, error) { return nil, errors.New("no local vault") }, time.Hour)
	a, b := mesh.attach(t, leader, 1), mesh.attach(t, follower, 2)
	connectTest(t, a, b, "local")
	connectTest(t, b, a, "")
	authorize(t, leader, testKey)
	handle(t, leader, "request", testKey)
	// A topology save lands while the snapshot request is in flight.
	dial := b.dial
	b.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		b.mu.Lock()
		b.generation++
		b.mu.Unlock()
		return dial(ctx, network, address)
	}
	if b.sync(context.Background()) == nil {
		t.Fatal("snapshot from an older topology was accepted")
	}
	follower.mu.Lock()
	_, cached := follower.cache[testKey]
	follower.mu.Unlock()
	if cached {
		t.Fatal("snapshot from an older topology was installed")
	}
}
