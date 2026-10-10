package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"yard/internal/issuer"
)

// RunClass is the run's capture class (TRAINING-DATA.md "Run classes"),
// declared on the control-plane side, never in the VM.
type RunClass string

const (
	ClassOwnCode        RunClass = "own-code"
	ClassCloudIaC       RunClass = "cloud-iac"
	ClassUntrustedWeb   RunClass = "untrusted-web"
	ClassSecretTouching RunClass = "secret-touching"
)

// Link is one sandbox's host-side link allocation. The broker listens on
// Addr (the host side of the sandbox's epair or tap; pf rdr's the metadata
// IPs to it), and a request is attributed to Workload only because it
// arrived on this listener, from one of Peers, on a connection accepted
// while this Incarnation held the address. Nothing in the request names the
// caller.
type Link struct {
	Addr netip.AddrPort `json:"addr"`
	// Incarnation is the host-assigned id of this allocation (yard-spawn
	// creates a fresh one each time it hands an address to a sandbox). An
	// address reused by another allocation carries another incarnation, and
	// connections accepted under the old one are closed and refused.
	Incarnation string            `json:"incarnation"`
	Peers       []netip.Prefix    `json:"peers"` // the jail's address and its per-call children
	Workload    issuer.WorkloadID `json:"workload"`
	Epoch       uint64            `json:"epoch"`   // SR0 credential epoch (never decreases per principal)
	Class       RunClass          `json:"class"`   // capture class
	Session     string            `json:"session"` // optional halo session id (X-Halo-Session-Id)
}

var (
	sessionRe     = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)
	incarnationRe = regexp.MustCompile(`^[0-9a-f]{32}$`) // 128-bit random, from yard-spawn
)

// normalize unmaps 4-in-6 addresses so one allocation has one key.
func (l *Link) normalize() {
	l.Addr = netip.AddrPortFrom(l.Addr.Addr().Unmap(), l.Addr.Port())
	for i, p := range l.Peers {
		if p.IsValid() && p.Addr().Is4In6() && p.Bits() >= 96 {
			l.Peers[i] = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
		}
	}
}

func (l *Link) validate(allowLoopback bool) error {
	l.normalize()
	if !l.Addr.IsValid() || l.Addr.Port() == 0 {
		return fmt.Errorf("link %v: need an address and a port", l.Addr)
	}
	if l.Addr.Addr().IsUnspecified() {
		return fmt.Errorf("link %v: unspecified address (one listener per link)", l.Addr)
	}
	if l.Addr.Addr().IsLoopback() && !allowLoopback {
		// Phase 0 S4: a loopback rdr target got the request but no reply back.
		return fmt.Errorf("link %v: loopback listen address", l.Addr)
	}
	if !incarnationRe.MatchString(l.Incarnation) { // MUTANT:incarnationFormatUnchecked
		return fmt.Errorf("link %v: incarnation must be 32 lowercase hex digits (128 random bits)", l.Addr)
	}
	if len(l.Peers) == 0 {
		return fmt.Errorf("link %v: no peers", l.Addr)
	}
	for _, p := range l.Peers {
		if !p.IsValid() {
			return fmt.Errorf("link %v: bad peer prefix", l.Addr)
		}
	}
	if err := l.Workload.Validate(); err != nil {
		return fmt.Errorf("link %v: %w", l.Addr, err)
	}
	switch l.Class {
	case ClassOwnCode, ClassCloudIaC, ClassUntrustedWeb, ClassSecretTouching:
	default:
		return fmt.Errorf("link %v: run class %q", l.Addr, l.Class)
	}
	if l.Session != "" && !sessionRe.MatchString(l.Session) {
		return fmt.Errorf("link %v: session id", l.Addr)
	}
	return nil
}

func (l Link) peerOK(a netip.Addr) bool {
	a = a.Unmap() // MUTANT:peerUnchecked
	for _, p := range l.Peers {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// sameAllocation: everything that makes up the caller's identity is equal
// (the epoch may move within one allocation: suspend and resume).
func (l Link) sameAllocation(o Link) bool {
	if l.Addr != o.Addr || l.Incarnation != o.Incarnation || l.Workload != o.Workload || len(l.Peers) != len(o.Peers) {
		return false
	}
	for i := range l.Peers {
		if l.Peers[i] != o.Peers[i] {
			return false
		}
	}
	return true
}

// Snapshot is one version of yard-ctl's link table for this node. Serial
// increases with every write (heartbeats that change nothing included);
// Issued is the writer's clock at the write. A snapshot authorizes nothing
// once Issued + the broker's lease has passed.
type Snapshot struct {
	Serial uint64    `json:"serial"`
	Issued time.Time `json:"issued"`
	Links  []Link    `json:"links"`
}

// Registry is yard-ctl's view of the sandboxes this node's broker serves
// (yard-spawn's allocations plus SR0's credential epochs).
type Registry interface {
	Snapshot(ctx context.Context) (Snapshot, error)
}

// StaticRegistry is a mutable in-memory Registry (tests). Set publishes a
// new version (serial + 1, issued now).
type StaticRegistry struct {
	S   Snapshot
	Err error
	Now func() time.Time
}

func (s *StaticRegistry) Snapshot(context.Context) (Snapshot, error) {
	if s.Err != nil {
		return Snapshot{}, s.Err
	}
	c := s.S
	c.Links = append([]Link(nil), s.S.Links...)
	for i := range c.Links {
		c.Links[i].Peers = append([]netip.Prefix(nil), c.Links[i].Peers...)
	}
	return c, nil
}

// Set publishes a new version.
func (s *StaticRegistry) Set(ls []Link) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	s.S = Snapshot{Serial: s.S.Serial + 1, Issued: now(), Links: ls}
}

// FileRegistry reads a Snapshot as JSON. The writer must replace the file
// by rename (a partial file is a parse error, which keeps the previous
// snapshot only until its lease ends).
type FileRegistry struct{ Path string }

func (f FileRegistry) Snapshot(context.Context) (Snapshot, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", f.Path, err)
	}
	return s, nil
}

// Floors are the broker's persisted high-water marks: the highest snapshot
// serial applied and its content digest, the highest epoch per principal,
// the allocations active in the last applied snapshot (incarnation -> address
// and principal), and the incarnations retired since. They survive a broker
// restart. Incarnations are 128 random bits from yard-spawn (an invariant
// checked at validate), so the bounded tombstone list is a second check,
// not the only protection against reuse.
type Floors struct {
	Version int                    `json:"version"` // 1
	Serial  uint64                 `json:"serial"`
	Digest  string                 `json:"digest"` // sha256 of the applied snapshot (issued + links)
	Epochs  map[string]uint64      `json:"epochs"`
	Active  map[string]AllocRecord `json:"active"`  // incarnation -> allocation
	Retired map[string]uint64      `json:"retired"` // incarnation -> serial that retired it
}

// AllocRecord is a persisted allocation.
type AllocRecord struct {
	Addr      string `json:"addr"`
	Principal string `json:"principal"`
}

// NewFloors is the floor document of a freshly initialised broker.
func NewFloors() Floors {
	return Floors{Version: 1, Epochs: map[string]uint64{}, Active: map[string]AllocRecord{}, Retired: map[string]uint64{}}
}

// validateFloors refuses documents that would silently reset protection
// (`{}`, missing maps, unknown version, malformed keys).
func validateFloors(f Floors) error {
	if f.Version != 1 { // MUTANT:floorsUnvalidated
		return fmt.Errorf("floors: version %d, want 1", f.Version)
	}
	if f.Epochs == nil || f.Active == nil || f.Retired == nil {
		return errors.New("floors: epochs, active and retired must all be present")
	}
	if f.Serial > 0 && len(f.Digest) != 64 {
		return errors.New("floors: digest missing for a non-zero serial")
	}
	for inc, a := range f.Active {
		if !incarnationRe.MatchString(inc) || a.Principal == "" {
			return fmt.Errorf("floors: active entry %q", inc)
		}
		if _, err := netip.ParseAddrPort(a.Addr); err != nil {
			return fmt.Errorf("floors: active %s addr: %v", inc, err)
		}
	}
	for inc := range f.Retired {
		if !incarnationRe.MatchString(inc) {
			return fmt.Errorf("floors: retired entry %q", inc)
		}
	}
	return nil
}

// FloorStore persists Floors. B0: a file in the broker's own dataset. B1
// alternative or cross-check: yard-ctl's handshake (spec/broker B15).
type FloorStore interface {
	Load() (Floors, error) // ErrNoFloors when nothing is persisted
	Save(Floors) error     // ErrFloorsUncertain when the new file may or may not be durable
}

var (
	// ErrNoFloors: nothing persisted. On an established install this means
	// recovery is required; only an explicit first boot may start from zero.
	ErrNoFloors = errors.New("no persisted floors")
	// ErrFloorsUncertain: the rename happened but its durability is not
	// established (directory open or fsync failed): the file on disk after a
	// crash may be the old one or the new one.
	ErrFloorsUncertain = errors.New("floors persistence uncertain")
)

// floorOps are the filesystem steps of a save (tests inject failures).
type floorOps struct {
	createTemp func(dir string) (*os.File, error)
	write      func(f *os.File, b []byte) error
	syncFile   func(f *os.File) error
	rename     func(from, to string) error
	syncDir    func(dir string) error
}

var defaultFloorOps = floorOps{
	createTemp: func(dir string) (*os.File, error) { return os.CreateTemp(dir, ".floors-*") },
	write:      func(f *os.File, b []byte) error { _, err := f.Write(b); return err },
	syncFile:   func(f *os.File) error { return f.Sync() },
	rename:     os.Rename,
	syncDir: func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	},
}

// FileFloors stores Floors as JSON: temp file, write, fsync, rename, fsync
// the directory. A failure before the rename leaves the old file (the save
// did not happen); a failure after it is ErrFloorsUncertain.
type FileFloors struct {
	Path string
	ops  *floorOps
}

func (f FileFloors) Load() (Floors, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Floors{}, ErrNoFloors
	}
	if err != nil {
		return Floors{}, err
	}
	var fl Floors
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fl); err != nil {
		return Floors{}, fmt.Errorf("%s: %w (refusing to start without valid floors)", f.Path, err)
	}
	if err := validateFloors(fl); err != nil {
		return Floors{}, fmt.Errorf("%s: %w (refusing to start without valid floors)", f.Path, err)
	}
	return fl, nil
}

func (f FileFloors) Save(fl Floors) error {
	if err := validateFloors(fl); err != nil {
		return err
	}
	ops := defaultFloorOps
	if f.ops != nil {
		ops = *f.ops
	}
	b, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	tmp, err := ops.createTemp(dir)
	if err != nil {
		return err
	}
	name := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			os.Remove(name)
		}
	}()
	if err := ops.write(tmp, b); err != nil {
		tmp.Close()
		return err
	}
	if err := ops.syncFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := ops.rename(name, f.Path); err != nil {
		return err
	}
	renamed = true
	if err := ops.syncDir(dir); err != nil { // MUTANT:dirSyncIgnored
		return fmt.Errorf("%w: %v", ErrFloorsUncertain, err)
	}
	return nil
}

// InitFileFloors creates a fresh floors file; it refuses if one exists
// (yard-broker -init-floors, run once by the install script).
func InitFileFloors(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s exists: an established install is never re-initialised", path)
	}
	return FileFloors{Path: path}.Save(NewFloors())
}

// MemFloors is an in-memory FloorStore (tests).
type MemFloors struct {
	mu    sync.Mutex
	F     *Floors
	Err   error         // Save fails with this when set
	Delay time.Duration // Save sleeps this long first (slow disk)
}

func (m *MemFloors) Load() (Floors, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.F == nil {
		return Floors{}, ErrNoFloors
	}
	if err := validateFloors(*m.F); err != nil {
		return Floors{}, err
	}
	return cloneFloors(*m.F), nil
}

func (m *MemFloors) Save(f Floors) error {
	time.Sleep(m.Delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Err != nil {
		return m.Err
	}
	c := cloneFloors(f)
	m.F = &c
	return nil
}

func cloneFloors(f Floors) Floors {
	c := NewFloors()
	c.Version, c.Serial, c.Digest = f.Version, f.Serial, f.Digest
	for k, v := range f.Epochs {
		c.Epochs[k] = v
	}
	for k, v := range f.Active {
		c.Active[k] = v
	}
	for k, v := range f.Retired {
		c.Retired[k] = v
	}
	return c
}

// mergeFloors is the conservative union of two floor documents (the
// recovery after an uncertain save): every maximum, every tombstone, and the
// active set of the newer serial.
func mergeFloors(a, b Floors) Floors {
	m := cloneFloors(a)
	if b.Serial > m.Serial {
		m.Serial, m.Digest, m.Active = b.Serial, b.Digest, map[string]AllocRecord{}
		for k, v := range b.Active {
			m.Active[k] = v
		}
	}
	for k, v := range b.Epochs {
		if v > m.Epochs[k] {
			m.Epochs[k] = v
		}
	}
	for k, v := range b.Retired {
		if v > m.Retired[k] {
			m.Retired[k] = v
		}
	}
	for k := range m.Retired {
		delete(m.Active, k)
	}
	return m
}

// snapshotDigest identifies a snapshot's content (issue time and links).
func snapshotDigest(sn Snapshot) string {
	b, _ := json.Marshal(struct {
		Issued time.Time `json:"issued"`
		Links  []Link    `json:"links"`
	}{sn.Issued.UTC(), sn.Links})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ChainSource gives the A2A chain root a sandbox currently serves, from the
// relay's delivery context (yard-relay stamps yard_chain on deliveries;
// A2A-MCP.md 9). Never from the sandbox's own request.
type ChainSource interface {
	ChainRoot(ctx context.Context, l Link) (root string, ok bool)
}

// NoChains: no relay yet (B0); every sandbox is its own chain root.
type NoChains struct{}

func (NoChains) ChainRoot(context.Context, Link) (string, bool) { return "", false }

var chainRe = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)
