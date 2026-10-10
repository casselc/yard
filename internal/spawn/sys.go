// Package spawn is yard-spawn J0: sandbox jails, per-call child jails, and
// per-task uids on a FreeBSD host (HARNESS.md "Executor design").
//
// Every privileged effect goes through the Sys interface, so the ordering
// and cleanup logic is unit-tested with a fake on any OS; the FreeBSD
// implementation is in sys_freebsd.go.
package spawn

import (
	"io"
	"time"

	"yard/internal/jail"
	"yard/internal/mount"
)

// ProcSpec starts the exec shim.
type ProcSpec struct {
	Path   string
	Args   []string // argv[1:]
	Env    []string
	Stdout io.Writer
	Stderr io.Writer
}

// Exit describes how a process ended.
type Exit struct {
	Code     int // exit status, or -1 if signalled
	Signal   int // signal number if signalled
	UserTime time.Duration
	SysTime  time.Duration
	MaxRSSKB int64
}

// Proc is a started process.
type Proc interface {
	Pid() int
	Wait() (Exit, error)
	Kill() error
}

// Sys is everything yard-spawn does to the host.
type Sys interface {
	AddRule(rule string) error
	RemoveRules(filter string) error
	Mount(s mount.Spec) error
	Unmount(target string, force bool) error
	Mounts() ([]string, error)
	Mkdir(path string, perm uint32) error
	Rmdir(path string) error
	Chown(path string, uid, gid uint32) error
	CreateJail(ps []jail.Param, flags int) (int, error)
	RemoveJail(jid int) error
	JID(name string) (int, error)
	Start(p ProcSpec) (Proc, error)
	// Run runs a host command (ifconfig, jexec, pfctl) and returns its output.
	Run(stdin string, argv ...string) (string, error)
}
