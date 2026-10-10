package spawn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"yard/internal/jail"
	"yard/internal/keyring"
	"yard/internal/mount"
	"yard/internal/pfanchor"
)

// SbxNet is a sandbox network profile.
type SbxNet string

const (
	SbxNone   SbxNet = "none"   // no network at all (ip4/ip6 disabled)
	SbxBroker SbxNet = "broker" // VNET + routed /30 epair; metadata IPs rdr'd to the broker; rest blocked
)

// Sandbox is a long-lived parent jail that per-call children run under.
type Sandbox struct {
	ID         string `json:"id"`
	Base       string `json:"base"`     // e.g. /yard/jails; the sandbox lives in <base>/<id>
	Template   string `json:"template"` // read-only base, e.g. /yard/tmpl/base
	Net        SbxNet `json:"net"`
	Subnet     int    `json:"subnet,omitempty"` // broker: 10.77.<subnet>.0/30
	BrokerPort uint16 `json:"broker_port,omitempty"`
	Epair      string `json:"epair,omitempty"`     // host side, e.g. epair3a
	OwnerUID   uint32 `json:"owner_uid,omitempty"` // task uid that owns the workspace (0 = root)
	OwnerGID   uint32 `json:"owner_gid,omitempty"`
	// WorkspacePath is a workspace that exists already (SR1: a ZFS dataset's
	// mountpoint, so it can be snapshotted on its own); "" = <dir>/ws, made
	// here. A given path is never created, removed or purged by yard-spawn.
	WorkspacePath string `json:"workspace_path,omitempty"`
	// Expose lists TCP ports of the sandbox address the host may connect to
	// (SR1: readiness probes of a service; broker sandboxes only).
	Expose  []uint16  `json:"expose,omitempty"`
	JID     int       `json:"jid"`
	Created time.Time `json:"created"`
}

var sbxRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

func (s *Sandbox) Dir() string  { return filepath.Join(s.Base, s.ID) }
func (s *Sandbox) Root() string { return filepath.Join(s.Dir(), "root") }
func (s *Sandbox) WorkspaceDir() string {
	if s.WorkspacePath != "" {
		return s.WorkspacePath
	}
	return filepath.Join(s.Dir(), "ws")
}
func (s *Sandbox) StateFile() string { return filepath.Join(s.Dir(), "sandbox.json") }
func (s *Sandbox) JailName() string  { return "ysbx_" + s.ID }

// HostAddr / JailAddr are the /30 addresses of a broker sandbox.
func (s *Sandbox) HostAddr() netip.Addr { return netip.AddrFrom4([4]byte{10, 77, byte(s.Subnet), 1}) }
func (s *Sandbox) JailAddr() netip.Addr { return netip.AddrFrom4([4]byte{10, 77, byte(s.Subnet), 2}) }

// Anchor returns the pf anchor spec for a broker sandbox.
func (s *Sandbox) Anchor() pfanchor.Spec {
	return pfanchor.Spec{ID: s.ID, Iface: s.Epair, Jail: s.JailAddr(), Broker: s.HostAddr(), BrokerPort: s.BrokerPort, Expose: s.Expose}
}

func (s *Sandbox) validate() error {
	if !sbxRe.MatchString(s.ID) {
		return fmt.Errorf("sandbox id %q: want [a-z0-9]{1,16}", s.ID)
	}
	if !filepath.IsAbs(s.Base) || !filepath.IsAbs(s.Template) {
		return errors.New("sandbox: base and template must be absolute")
	}
	switch s.Net {
	case SbxNone:
	case SbxBroker:
		if s.Subnet < 0 || s.Subnet > 255 {
			return fmt.Errorf("sandbox subnet %d", s.Subnet)
		}
		if s.BrokerPort == 0 {
			return errors.New("sandbox: broker port required")
		}
	default:
		return fmt.Errorf("sandbox net %q", s.Net)
	}
	if len(s.Expose) > 0 && s.Net != SbxBroker {
		return errors.New("sandbox: expose needs a broker (VNET) sandbox")
	}
	if s.WorkspacePath != "" && !filepath.IsAbs(s.WorkspacePath) {
		return errors.New("sandbox: workspace path must be absolute")
	}
	return nil
}

// LoadSandbox reads <base>/<id>/sandbox.json.
func LoadSandbox(base, id string) (*Sandbox, error) {
	if !sbxRe.MatchString(id) {
		return nil, fmt.Errorf("sandbox id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(base, id, "sandbox.json"))
	if err != nil {
		return nil, err
	}
	var s Sandbox
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Sandbox) save() error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return keyring.WriteFileAtomic(s.StateFile(), append(b, '\n'), 0o600)
}

// SandboxOpts are creation options.
type SandboxOpts struct {
	ChildrenMax int // default 8
	Devfs       int // devfs ruleset for the sandbox's /dev (0 = none)
	YardTmpSize string
}

// CreateSandbox builds the parent jail: read-only template root, tmpfs on
// /.yard for per-call roots, the workspace at /workspace, optional VNET
// epair + pf anchor. On failure everything done so far is undone.
func (sp *Spawner) CreateSandbox(s *Sandbox, o SandboxOpts) (err error) {
	if err := s.validate(); err != nil {
		return err
	}
	S := sp.Sys
	if _, err := os.Stat(s.StateFile()); err == nil {
		return fmt.Errorf("sandbox %s already exists (%s)", s.ID, s.StateFile())
	}
	if o.ChildrenMax <= 0 {
		o.ChildrenMax = 8
	}
	if o.YardTmpSize == "" {
		o.YardTmpSize = "16m"
	}
	var stack []undo
	defer func() {
		if err == nil {
			return
		}
		for i := len(stack) - 1; i >= 0; i-- {
			if e := stack[i].fn(); e != nil {
				err = fmt.Errorf("%w (and undo %s: %v)", err, stack[i].what, e)
			}
		}
	}()
	dirs := []string{s.Dir(), s.Root()}
	if s.WorkspacePath == "" {
		dirs = append(dirs, s.WorkspaceDir())
	} else if fi, err := os.Stat(s.WorkspacePath); err != nil || !fi.IsDir() {
		return fmt.Errorf("sandbox: workspace path %s is not a directory", s.WorkspacePath)
	}
	for _, d := range dirs {
		if err := S.Mkdir(d, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
		d := d
		stack = append(stack, undo{"rmdir " + d, func() error { return S.Rmdir(d) }})
	}
	// the workspace belongs to the task that will use this sandbox
	if s.OwnerUID != 0 {
		if err := S.Chown(s.WorkspaceDir(), s.OwnerUID, s.OwnerGID); err != nil {
			return fmt.Errorf("chown workspace: %w", err)
		}
	}
	mounts := []mount.Spec{
		{Type: "nullfs", Source: s.Template, Target: s.Root(), RO: true},
		{Type: "tmpfs", Target: s.Root() + "/.yard", Size: o.YardTmpSize, Mode: 0o700},
		{Type: "nullfs", Source: s.WorkspaceDir(), Target: s.Root() + "/workspace"},
	}
	if o.Devfs > 0 {
		mounts = append(mounts, mount.Spec{Type: "devfs", Target: s.Root() + "/dev", Ruleset: o.Devfs})
	}
	for _, m := range mounts {
		if err := S.Mount(m); err != nil {
			return err
		}
		t := m.Target
		stack = append(stack, undo{"unmount " + t, func() error { return sp.unmount(t) }})
	}
	if err := S.Mkdir(s.Root()+"/.yard/calls", 0o700); err != nil {
		return err
	}
	if err := S.Mkdir(s.Root()+"/.yard/svc", 0o700); err != nil {
		return err
	}
	ps := []jail.Param{
		jail.Str("name", s.JailName()),
		jail.Str("path", s.Root()),
		jail.Str("host.hostname", s.JailName()),
		jail.Bool("persist"),
		jail.Int("children.max", int32(o.ChildrenMax)),
	}
	ps = append(ps, jail.Hardened()...)
	if s.Net == SbxBroker {
		ps = append(ps, jail.Int("vnet", jail.SysNew))
	} else {
		ps = append(ps, jail.Int("ip4", jail.SysDisable), jail.Int("ip6", jail.SysDisable))
	}
	jid, err := S.CreateJail(ps, jail.Create)
	if err != nil {
		return fmt.Errorf("jail_set %s: %w", s.JailName(), err)
	}
	s.JID = jid
	stack = append(stack, undo{"jail_remove", func() error { return S.RemoveJail(jid) }})

	if s.Net == SbxBroker {
		if err := sp.setupBrokerNet(s, &stack); err != nil {
			return err
		}
	}
	// securelevel only after the network is configured (ifconfig in the jail)
	if _, err := S.CreateJail([]jail.Param{jail.Str("name", s.JailName()), jail.Int("securelevel", 3)}, jail.Update); err != nil {
		return fmt.Errorf("securelevel: %w", err)
	}
	s.Created = sp.now().UTC()
	return s.save()
}

func (sp *Spawner) setupBrokerNet(s *Sandbox, stack *[]undo) error {
	S := sp.Sys
	out, err := S.Run("", "/sbin/ifconfig", "epair", "create")
	if err != nil {
		return fmt.Errorf("epair create: %w", err)
	}
	a := strings.TrimSpace(out)
	if !strings.HasPrefix(a, "epair") || !strings.HasSuffix(a, "a") {
		return fmt.Errorf("epair create returned %q", a)
	}
	s.Epair = a
	b := strings.TrimSuffix(a, "a") + "b"
	*stack = append(*stack, undo{"destroy " + a, func() error { _, err := S.Run("", "/sbin/ifconfig", a, "destroy"); return err }})
	j := strconv.Itoa(s.JID)
	host := s.HostAddr().String() + "/30"
	steps := [][]string{
		{"/sbin/ifconfig", a, "description", "yard sbx " + s.ID},
		{"/sbin/ifconfig", a, "inet", host, "up"},
		{"/sbin/ifconfig", b, "vnet", j},
		{"/usr/sbin/jexec", j, "/sbin/ifconfig", b, "inet", s.JailAddr().String() + "/30", "up"},
		{"/usr/sbin/jexec", j, "/sbin/ifconfig", "lo0", "inet", "127.0.0.1/8", "up"},
		{"/usr/sbin/jexec", j, "/sbin/route", "-q", "add", "default", s.HostAddr().String()},
	}
	for _, st := range steps {
		if _, err := S.Run("", st...); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(st, " "), err)
		}
	}
	rules, err := s.Anchor().Render()
	if err != nil {
		return err
	}
	if _, err := S.Run(rules, "/sbin/pfctl", "-q", "-a", s.Anchor().Name(), "-f", "-"); err != nil {
		return fmt.Errorf("load anchor: %w", err)
	}
	*stack = append(*stack, undo{"flush anchor", func() error { return flushAnchor(S, s.Anchor().Name()) }})
	return nil
}

// flushAnchor empties an anchor by loading an empty ruleset into it, which
// replaces its filter, nat and rdr rules in one transaction. `pfctl -a X -F all`
// failed on the NUC (15.1-STABLE, t20 G) with "Operation not supported by
// device" before flushing anything: -F all also flushes the anchor's ethernet
// rules and tables first.
func flushAnchor(S Sys, name string) error {
	_, err := S.Run("", "/sbin/pfctl", "-q", "-a", name, "-f", "/dev/null")
	return err
}

// DestroySandbox removes the jail (and every child and process in it),
// the anchor and the epair, unmounts everything under the root and removes
// the root. The workspace directory is kept unless purge is set.
func (sp *Spawner) DestroySandbox(s *Sandbox, purge bool) error {
	S := sp.Sys
	var errs []string
	if jid, err := S.JID(s.JailName()); err == nil {
		if err := S.RemoveJail(jid); err != nil {
			errs = append(errs, "jail_remove: "+err.Error())
		}
	}
	if s.Net == SbxBroker {
		if err := flushAnchor(S, s.Anchor().Name()); err != nil {
			errs = append(errs, "flush anchor: "+err.Error())
		}
		if s.Epair != "" {
			if _, err := S.Run("", "/sbin/ifconfig", s.Epair, "destroy"); err != nil {
				errs = append(errs, "destroy epair: "+err.Error())
			}
		}
	}
	mps, err := S.Mounts()
	if err != nil {
		return err
	}
	for _, m := range mount.Under(mps, s.Root()) {
		if err := sp.unmount(m); err != nil {
			errs = append(errs, "unmount "+m+": "+err.Error())
		}
	}
	if left := mount.Under(mustMounts(S), s.Dir()); len(left) > 0 {
		errs = append(errs, fmt.Sprintf("still mounted: %v", left))
		return fmt.Errorf("destroy %s: %s", s.ID, strings.Join(errs, "; "))
	}
	if err := S.Rmdir(s.Root()); err != nil {
		errs = append(errs, "rmdir root: "+err.Error())
	}
	os.Remove(s.StateFile())
	if purge {
		// a given workspace (WorkspacePath) belongs to its owner, not to the sandbox
		if s.WorkspacePath == "" {
			if err := os.RemoveAll(s.WorkspaceDir()); err != nil {
				errs = append(errs, "purge workspace: "+err.Error())
			}
		}
		os.Remove(s.Dir())
	}
	if len(errs) > 0 {
		return fmt.Errorf("destroy %s: %s", s.ID, strings.Join(errs, "; "))
	}
	return nil
}

func mustMounts(S Sys) []string {
	m, _ := S.Mounts()
	return m
}
