package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrNotAllowlisted: the broker refused to dial a host:port outside the
// allowlist (nothing was sent).
var ErrNotAllowlisted = errors.New("upstream not allowlisted")

// allowlist is the set of host:port names the broker may dial.
type allowlist map[string]bool

func (a allowlist) allows(hostport string) bool {
	return a[strings.ToLower(hostport)] // MUTANT:allowAny
}

// specialUse lists address space that is never a cloud provider's public
// endpoint: private, shared, loopback, link-local, documentation,
// benchmarking, IETF protocol assignments, reserved, multicast, translation
// (NAT64, 6to4, Teredo) and the tailnet. The policy is inverted: an address
// is dialable only if it is global unicast and in none of these.
var specialUse = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

// isPublic reports whether a resolved address may be dialled for a provider.
func isPublic(a netip.Addr) bool {
	if a.Is4In6() {
		a = a.Unmap()
	}
	if !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range specialUse {
		if p.Contains(a) { // MUTANT:specialUseAllowed
			return false
		}
	}
	return true
}

// candidates keeps the resolved addresses the broker may dial, in order.
func (b *Broker) candidates(ips []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, ip := range ips {
		if isPublic(ip) || b.cfg.AllowPrivateUpstream {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// Resolver resolves provider names (net.DefaultResolver; tests inject one).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// dialAllowed dials only allowlisted names, and (unless the config allows
// it for tests) only to public addresses those names resolve to, so DNS
// cannot turn an allowed name into a LAN or tailnet address.
func (b *Broker) dialAllowed(ctx context.Context, network, addr string) (net.Conn, error) {
	if !b.allow.allows(addr) {
		return nil, fmt.Errorf("%w: %s", ErrNotAllowlisted, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var res Resolver = net.DefaultResolver
	if b.cfg.Resolver != nil {
		res = b.cfg.Resolver
	}
	ips, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	cands := b.candidates(ips)
	if len(cands) == 0 {
		return nil, fmt.Errorf("%w: %s resolves to no public address", ErrNotAllowlisted, host)
	}
	var last error
	for _, ip := range cands {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (b *Broker) cloudTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never the environment's proxy
		DialContext:           b.dialAllowed,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: b.cfg.CloudRootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: b.cfg.CloudHeaderTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		DisableCompression:    true,
	}
}

// haloTransport dials exactly halo's address, nothing else.
func (b *Broker) haloTransport(u *url.URL) *http.Transport {
	want := hostPort(u)
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.ToLower(addr) != want {
				return nil, fmt.Errorf("%w: %s", ErrNotAllowlisted, addr)
			}
			return d.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: b.cfg.HaloHeaderTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		DisableCompression:    true,
	}
}
