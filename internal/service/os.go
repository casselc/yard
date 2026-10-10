package service

import (
	"context"
	"net"
	"net/http"
	"os"

	"yard/internal/spawn"
)

// Proc is one process of a jail as the host sees it (zombies excluded).
type Proc struct {
	PID     int
	Stopped bool // state T: SIGSTOPped (or job-control stopped)
}

// OS is everything the service backend does to the host: yard-spawn's Sys
// (jails, mounts, rctl, the shim) plus a process listing and zfs(8). The
// FreeBSD implementation is HostOS; tests use a fake.
type OS interface {
	spawn.Sys
	// Procs lists the live processes whose jail is jid, from the host (it
	// works for a dying jail too). Signals are not sent from the host by
	// pid: see Backend.signal.
	Procs(jid int) ([]Proc, error)
	// Zfs runs zfs(8). lock, if not nil, is inherited by the process, so an
	// op's flock is held until zfs exits (the op's settle bound).
	Zfs(ctx context.Context, lock *os.File, args ...string) (string, error)
	// ZfsIn is Zfs with stdin (a raw key for create / load-key / change-key).
	ZfsIn(ctx context.Context, lock *os.File, stdin []byte, args ...string) (string, error)
	// ZpoolSync forces a txg sync of the pool (`zpool sync`): space
	// properties such as written@snap count only synced data.
	ZpoolSync(ctx context.Context, pool string) error
}

// Prober runs the network readiness probes from the host.
type Prober interface {
	TCP(ctx context.Context, addr string) error
	// HTTP does one GET and returns the status code.
	HTTP(ctx context.Context, url string) (int, error)
}

// NetProber is the real Prober: a TCP connect and a plain HTTP GET, both
// bounded by ctx, no keep-alive (each attempt is a fresh connection).
type NetProber struct{}

func (NetProber) TCP(ctx context.Context, addr string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

var probeClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (NetProber) HTTP(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
