// Package frontend is how callers reach yard-ctl. Production is tsnet (the
// tailnet, with WhoIs + app capabilities identifying the caller); that is
// stubbed here behind the Frontend interface. The working implementation is
// a Unix socket whose callers are identified by kernel peer credentials.
package frontend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
)

// Caller is an authenticated caller.
type Caller struct {
	Name  string   // stable name used in logs and rate limits
	Roles []string // "mint", "admin"
}

// Has reports whether the caller holds role.
func (c Caller) Has(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Frontend listens and identifies callers of HTTP requests.
type Frontend interface {
	Listen() (net.Listener, error)
	// ConnContext is installed as http.Server.ConnContext to capture
	// per-connection identity.
	ConnContext(ctx context.Context, c net.Conn) context.Context
	// Identify returns the caller of r, or an error if unknown.
	Identify(r *http.Request) (Caller, error)
	String() string
}

// ErrUnknownCaller is returned for callers without a mapping.
var ErrUnknownCaller = errors.New("frontend: unknown caller")

type uidKey struct{}

// Unix serves on a Unix socket; callers are mapped by peer uid.
type Unix struct {
	Path  string
	Mode  os.FileMode       // socket file mode, default 0660
	Users map[uint32]Caller // uid -> caller
}

func (u *Unix) String() string { return "unix:" + u.Path }

// Listen removes a stale socket and listens.
func (u *Unix) Listen() (net.Listener, error) {
	if fi, err := os.Lstat(u.Path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("frontend: %s exists and is not a socket", u.Path)
		}
		os.Remove(u.Path)
	}
	l, err := net.Listen("unix", u.Path)
	if err != nil {
		return nil, err
	}
	mode := u.Mode
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(u.Path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (u *Unix) ConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	uid, err := PeerUID(uc)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, uidKey{}, uid)
}

func (u *Unix) Identify(r *http.Request) (Caller, error) {
	uid, ok := r.Context().Value(uidKey{}).(uint32)
	if !ok {
		return Caller{}, errors.New("frontend: no peer credentials")
	}
	c, ok := u.Users[uid]
	if !ok {
		return Caller{}, fmt.Errorf("%w: uid %d", ErrUnknownCaller, uid)
	}
	if c.Name == "" {
		c.Name = "uid:" + strconv.FormatUint(uint64(uid), 10)
	}
	return c, nil
}

// Tsnet is the production frontend: yard-ctl joins the tailnet as
// tag:yard with tsnet and identifies callers with LocalClient.WhoIs plus the
// tailnet app capability (CONTROL-PLANE §4). Not built in this skeleton: no
// tailnet joins from Phase 1, and tsnet on GOOS=freebsd is spike S6.
type Tsnet struct {
	Hostname string
	StateDir string
}

// ErrNotBuilt is returned by the tsnet stub.
var ErrNotBuilt = errors.New("frontend: tsnet frontend not built in this skeleton (spike S6)")

func (t *Tsnet) String() string                                              { return "tsnet:" + t.Hostname }
func (t *Tsnet) Listen() (net.Listener, error)                               { return nil, ErrNotBuilt }
func (t *Tsnet) ConnContext(ctx context.Context, _ net.Conn) context.Context { return ctx }
func (t *Tsnet) Identify(*http.Request) (Caller, error)                      { return Caller{}, ErrNotBuilt }
