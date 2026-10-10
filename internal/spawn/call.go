package spawn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"yard/internal/jail"
	"yard/internal/mount"
	"yard/internal/rctl"
)

// Net is a per-call network profile.
type Net string

const (
	NetNone    Net = "none"    // ip4=disable ip6=disable
	NetInherit Net = "inherit" // share the sandbox's addresses (broker profile, in a VNET sandbox)
)

// Audit classes for the per-call mask (audit_class(5)).
const (
	AuditPC = 0x00000080
	AuditEX = 0x40000000
)

// Call is one per-call child jail run.
type Call struct {
	Sandbox   *Sandbox
	ID        string // call id; the jail is <sandbox>.<id>
	Argv      []string
	Env       []string
	Cwd       string // inside the jail; default /workspace
	UID, GID  uint32
	Class     string // login class applied by the shim ("" = none)
	AuditUID  int64  // audit user (the human); < 0 disables per-call audit state
	AuditMask uint32 // default ex|pc
	Net       Net
	Workspace string // "ro" | "rw" | "none"
	TmpSize   string // tmpfs size, default 64m
	Mem       string // per-call vmemoryuse deny (e.g. "512m"); "" = no rule
	Timeout   time.Duration
	Devfs     int // devfs ruleset (0 = no /dev)
	Stdout    io.Writer
	Stderr    io.Writer
}

// Result of a call.
type Result struct {
	Jail      string        `json:"jail"`
	JID       int           `json:"jid"`
	Exit      int           `json:"exit"`   // -1 when signalled or not started
	Signal    int           `json:"signal"` // non-zero when signalled
	TimedOut  bool          `json:"timed_out"`
	Canceled  bool          `json:"canceled"`
	ShimError bool          `json:"shim_error"` // exit 120..127: the shim failed before exec
	Poisoned  bool          `json:"poisoned"`   // teardown incomplete: do not reuse the sandbox
	Setup     time.Duration `json:"setup_ns"`
	Run       time.Duration `json:"run_ns"`
	Teardown  time.Duration `json:"teardown_ns"`
	Total     time.Duration `json:"total_ns"`
	MaxRSSKB  int64         `json:"maxrss_kb"`
	Errors    []string      `json:"errors,omitempty"` // teardown problems
}

var callRe = regexp.MustCompile(`^c[a-z0-9]{1,31}$`)

// KillWait bounds how long Run waits for the process after jail_remove.
var KillWait = 5 * time.Second

// UnmountRetries x UnmountBackoff is how long a busy unmount is retried
// before a forced unmount (processes of a removed jail die asynchronously).
var (
	UnmountRetries = 20
	UnmountBackoff = 10 * time.Millisecond
)

type undo struct {
	what string
	fn   func() error
}

// Spawner runs calls.
type Spawner struct {
	Sys  Sys
	Shim string // path to yard-exec-shim
	Now  func() time.Time
}

func (sp *Spawner) now() time.Time {
	if sp.Now != nil {
		return sp.Now()
	}
	return time.Now()
}

func (c *Call) validate() error {
	if c.Sandbox == nil {
		return errors.New("call: no sandbox")
	}
	if !callRe.MatchString(c.ID) {
		return fmt.Errorf("call id %q: want c[a-z0-9]{1,31}", c.ID)
	}
	if len(c.Argv) == 0 {
		return errors.New("call: empty argv")
	}
	if c.UID == 0 || c.GID == 0 {
		return errors.New("call: uid/gid 0 not allowed")
	}
	switch c.Net {
	case NetNone:
	case NetInherit:
		if c.Sandbox.Net != SbxBroker {
			return fmt.Errorf("call: net=inherit needs a broker sandbox (sandbox %s is %s)", c.Sandbox.ID, c.Sandbox.Net)
		}
	default:
		return fmt.Errorf("call: net %q", c.Net)
	}
	switch c.Workspace {
	case "ro", "rw", "none":
	default:
		return fmt.Errorf("call: workspace %q (ro|rw|none)", c.Workspace)
	}
	if c.Mem != "" {
		if err := rctl.Amount(c.Mem); err != nil {
			return err
		}
	}
	if c.TmpSize != "" {
		if err := rctl.Amount(c.TmpSize); err != nil {
			return err
		}
	}
	if c.Timeout <= 0 {
		return errors.New("call: timeout required")
	}
	return nil
}

// Name is the hierarchical jail name.
func (c *Call) Name() string { return c.Sandbox.JailName() + "." + c.ID }

// Root is the host path of the call's root directory.
func (c *Call) Root() string { return filepath.Join(c.Sandbox.Root(), ".yard", "calls", c.ID) }

// ShimArgs returns the shim's argv[1:].
func (c *Call) ShimArgs(jid int) []string {
	cwd := c.Cwd
	if cwd == "" {
		cwd = "/workspace"
		if c.Workspace == "none" {
			cwd = "/"
		}
	}
	a := []string{"-j", strconv.Itoa(jid), "-u", strconv.FormatUint(uint64(c.UID), 10), "-g", strconv.FormatUint(uint64(c.GID), 10), "-d", cwd}
	if c.Class != "" {
		a = append(a, "-c", c.Class)
	}
	if c.AuditUID >= 0 {
		m := c.AuditMask
		if m == 0 {
			m = AuditEX | AuditPC
		}
		a = append(a, "-a", strconv.FormatInt(c.AuditUID, 10), "-m", fmt.Sprintf("0x%x", m))
	}
	return append(append(a, "--"), c.Argv...)
}

// JailParams returns the child jail's parameters.
func (c *Call) JailParams() []jail.Param {
	ps := []jail.Param{
		jail.Str("name", c.Name()),
		jail.Str("path", c.Root()),
		jail.Str("host.hostname", c.ID),
		jail.Bool("persist"),
		jail.Int("children.max", 0),
		jail.Int("securelevel", 3),
	}
	ps = append(ps, jail.Hardened()...)
	sys := int32(jail.SysDisable)
	if c.Net == NetInherit {
		sys = jail.SysInherit
	}
	return append(ps, jail.Int("ip4", sys), jail.Int("ip6", sys))
}

// Run runs one call: per-call rctl rule, mounts, child jail, shim, wait
// with timeout, then jail_remove and teardown in reverse order. Teardown
// always runs; a failed unmount marks the result Poisoned.
func (sp *Spawner) Run(ctx context.Context, c *Call) (res *Result, err error) {
	t0 := sp.now()
	res = &Result{Jail: c.Name(), JID: -1, Exit: -1}
	if err := c.validate(); err != nil {
		return res, err
	}
	var stack []undo
	defer func() {
		t1 := sp.now()
		for i := len(stack) - 1; i >= 0; i-- {
			if e := stack[i].fn(); e != nil {
				res.Errors = append(res.Errors, stack[i].what+": "+e.Error())
				res.Poisoned = true
			}
		}
		res.Teardown = sp.now().Sub(t1)
		res.Total = sp.now().Sub(t0)
	}()
	S := sp.Sys
	name, root := c.Name(), c.Root()

	if c.Mem != "" {
		rule, err := rctl.JailRule(name, rctl.Limit("vmemoryuse:deny="+c.Mem))
		if err != nil {
			return res, err
		}
		filter, _ := rctl.JailFilter(name)
		if err := S.AddRule(rule); err != nil {
			return res, fmt.Errorf("rctl add %s: %w", rule, err)
		}
		stack = append(stack, undo{"rctl remove " + filter, func() error { return S.RemoveRules(filter) }})
	}
	if err := S.Mkdir(root, 0o700); err != nil {
		return res, fmt.Errorf("mkdir %s: %w", root, err)
	}
	stack = append(stack, undo{"rmdir " + root, func() error { return S.Rmdir(root) }})

	mounts := []mount.Spec{{Type: "nullfs", Source: c.Sandbox.Template, Target: root, RO: true}}
	if c.Workspace != "none" {
		mounts = append(mounts, mount.Spec{Type: "nullfs", Source: c.Sandbox.WorkspaceDir(), Target: root + "/workspace", RO: c.Workspace == "ro"})
	}
	tsz := c.TmpSize
	if tsz == "" {
		tsz = "64m"
	}
	mounts = append(mounts, mount.Spec{Type: "tmpfs", Target: root + "/tmp", Size: tsz, Mode: 0o1777})
	if c.Devfs > 0 {
		mounts = append(mounts, mount.Spec{Type: "devfs", Target: root + "/dev", Ruleset: c.Devfs})
	}
	for _, m := range mounts {
		if err := S.Mount(m); err != nil {
			return res, err
		}
		tgt := m.Target
		stack = append(stack, undo{"unmount " + tgt, func() error { return sp.unmount(tgt) }})
	}

	jid, err := S.CreateJail(c.JailParams(), jail.Create)
	if err != nil {
		return res, fmt.Errorf("jail_set %s: %w", name, err)
	}
	res.JID = jid
	removed := false
	stack = append(stack, undo{"jail_remove " + name, func() error {
		if removed {
			return nil
		}
		return S.RemoveJail(jid)
	}})

	p, err := S.Start(ProcSpec{Path: sp.Shim, Args: c.ShimArgs(jid), Env: c.Env, Stdout: c.Stdout, Stderr: c.Stderr})
	if err != nil {
		return res, fmt.Errorf("start shim: %w", err)
	}
	t1 := sp.now()
	res.Setup = t1.Sub(t0)

	type waited struct {
		e   Exit
		err error
	}
	done := make(chan waited, 1)
	go func() { e, err := p.Wait(); done <- waited{e, err} }()
	tctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var w waited
	select {
	case w = <-done:
	case <-tctx.Done():
		if ctx.Err() != nil {
			res.Canceled = true
		} else {
			res.TimedOut = true
		}
		// Kill the whole call: jail_remove kills every process in the jail
		// (closing a jail descriptor would NOT -- Phase 0 spike 21 E). The
		// direct kill covers a shim that has not attached yet.
		if err := S.RemoveJail(jid); err != nil {
			res.Errors = append(res.Errors, "jail_remove on timeout: "+err.Error())
		} else {
			removed = true
		}
		p.Kill()
		select {
		case w = <-done:
		case <-time.After(KillWait):
			res.Poisoned = true
			res.Errors = append(res.Errors, fmt.Sprintf("process %d still running %s after jail_remove", p.Pid(), KillWait))
			return res, nil
		}
	}
	res.Run = sp.now().Sub(t1)
	if w.err != nil {
		return res, w.err
	}
	res.Exit, res.Signal, res.MaxRSSKB = w.e.Code, w.e.Signal, w.e.MaxRSSKB
	if !res.TimedOut && !res.Canceled && res.Exit >= 120 && res.Exit <= 127 {
		res.ShimError = true
	}
	return res, nil
}

// unmount retries a busy unmount, then forces it.
func (sp *Spawner) unmount(target string) error {
	var err error
	for i := 0; i < UnmountRetries; i++ {
		if err = sp.Sys.Unmount(target, false); err == nil {
			return nil
		}
		time.Sleep(UnmountBackoff)
	}
	if ferr := sp.Sys.Unmount(target, true); ferr != nil {
		return fmt.Errorf("%v; forced: %v", err, ferr)
	}
	return nil
}
