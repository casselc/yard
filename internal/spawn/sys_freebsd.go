//go:build freebsd

package spawn

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"yard/internal/jail"
	"yard/internal/mount"
	"yard/internal/rctl"
)

// HostSys is the real FreeBSD implementation of Sys.
type HostSys struct{}

func (HostSys) AddRule(r string) error                         { return rctl.Add(r) }
func (HostSys) RemoveRules(f string) error                     { return rctl.Remove(f) }
func (HostSys) Mount(s mount.Spec) error                       { return mount.Mount(s) }
func (HostSys) Unmount(t string, force bool) error             { return mount.Unmount(t, force) }
func (HostSys) Mounts() ([]string, error)                      { return mount.List() }
func (HostSys) Mkdir(p string, perm uint32) error              { return os.Mkdir(p, os.FileMode(perm)) }
func (HostSys) Chown(p string, u, g uint32) error              { return os.Chown(p, int(u), int(g)) }
func (HostSys) Rmdir(p string) error                           { return syscall.Rmdir(p) }
func (HostSys) CreateJail(ps []jail.Param, f int) (int, error) { return jail.Set(ps, f) }
func (HostSys) RemoveJail(jid int) error                       { return jail.Remove(jid) }
func (HostSys) JID(name string) (int, error)                   { return jail.JID(name) }

func (HostSys) Run(stdin string, argv ...string) (string, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin"}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

type hostProc struct{ c *exec.Cmd }

func (p hostProc) Pid() int    { return p.c.Process.Pid }
func (p hostProc) Kill() error { return p.c.Process.Kill() }
func (p hostProc) Wait() (Exit, error) {
	err := p.c.Wait()
	ps := p.c.ProcessState
	if ps == nil {
		return Exit{Code: -1}, err
	}
	e := Exit{Code: ps.ExitCode(), UserTime: ps.UserTime(), SysTime: ps.SystemTime()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		e.Code, e.Signal = -1, int(ws.Signal())
	}
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
		e.MaxRSSKB = ru.Maxrss
	}
	if _, isExit := err.(*exec.ExitError); isExit {
		err = nil
	}
	return e, err
}

func (HostSys) Start(s ProcSpec) (Proc, error) {
	cmd := exec.Command(s.Path, s.Args...)
	cmd.Env = s.Env
	if cmd.Env == nil {
		cmd.Env = []string{"PATH=/bin:/usr/bin", "HOME=/workspace"}
	}
	cmd.Stdout, cmd.Stderr = s.Stdout, s.Stderr
	cmd.ExtraFiles = s.ExtraFiles
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second // do not hang on pipes held by orphans
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return hostProc{cmd}, nil
}
