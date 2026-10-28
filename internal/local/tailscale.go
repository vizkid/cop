package local

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Node struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type Identity interface {
	Self(context.Context, int) (Node, error)
	Lookup(context.Context, string) (string, error)
}

type tailscaleIdentity struct{ executable string }

func TailscaleIdentity(path string) (Identity, error) {
	p, err := exec.LookPath(path)
	if err != nil {
		return nil, errors.New("tailscale executable unavailable")
	}
	return tailscaleIdentity{p}, nil
}

type limitedBuffer struct {
	data  []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, errors.New("output limit exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func (t tailscaleIdentity) query(ctx context.Context, out any, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, t.executable, args...)
	b := limitedBuffer{limit: 4 << 20}
	cmd.Stdout = &b
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || json.Unmarshal(b.data, out) != nil {
		return errors.New("Tailscale identity lookup failed")
	}
	return nil
}
func (t tailscaleIdentity) Self(ctx context.Context, port int) (Node, error) {
	var result struct {
		BackendState string
		Self         struct {
			ID           string
			TailscaleIPs []string
		}
	}
	if t.query(ctx, &result, "status", "--json") != nil || result.BackendState != "Running" || result.Self.ID == "" {
		return Node{}, errors.New("Tailscale is not running")
	}
	for _, ip := range result.Self.TailscaleIPs {
		addr, err := netip.ParseAddr(ip)
		if err == nil && addr.Is4() && tailAddress(addr) {
			return Node{result.Self.ID, net.JoinHostPort(ip, strconv.Itoa(port))}, nil
		}
	}
	return Node{}, errors.New("Tailscale IPv4 address unavailable")
}
func (t tailscaleIdentity) Lookup(ctx context.Context, address string) (string, error) {
	if _, err := peerAddress(address); err != nil {
		return "", err
	}
	var result struct{ Node struct{ StableID string } }
	if t.query(ctx, &result, "whois", "--json", address) != nil || result.Node.StableID == "" {
		return "", errors.New("Tailscale peer identity unavailable")
	}
	return result.Node.StableID, nil
}
func tailAddress(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}
func peerAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("peer must be a Tailscale IP:port")
	}
	ip, err := netip.ParseAddr(host)
	n, e := strconv.Atoi(port)
	if err != nil || !tailAddress(ip) || ip.Zone() != "" || e != nil || n < 1 || n > 65535 || strings.TrimSpace(address) != address {
		return "", errors.New("peer must be a Tailscale IP:port")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}
