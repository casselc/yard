package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"yard/internal/keyring"
	"yard/internal/spawn"
)

// Session is the host-side record of one service session: where it runs,
// as whom, on which workspace dataset, from which spec. The lifecycle row
// (internal/lifecycle) is the session's state; this is its configuration.
type Session struct {
	ID       string `json:"id"`      // lifecycle session id
	Sandbox  string `json:"sandbox"` // yard-spawn sandbox id
	Base     string `json:"base"`    // sandbox base directory
	UID      uint32 `json:"uid"`     // task uid the service runs as
	GID      uint32 `json:"gid"`
	Class    string `json:"class,omitempty"` // login class applied by the shim
	AuditUID int64  `json:"audit_uid"`       // < 0: no per-call audit state
	Devfs    int    `json:"devfs"`           // devfs ruleset of the instance's /dev
	Dataset  string `json:"dataset"`         // ZFS dataset mounted at the workspace
	// Project is the workspace key's project ("": the dataset is under the
	// data root, no key of its own); Dataset is then ws/<project>/<session>.
	Project string `json:"project,omitempty"`
	// Workspace is the host directory mounted at /workspace in every
	// instance ("": the sandbox's workspace).
	Workspace string `json:"workspace,omitempty"`
	Spec      Spec   `json:"spec"`
}

// workspaceDir is where the session's dataset must be mounted.
func (s *Session) workspaceDir(sbx *spawn.Sandbox) string {
	if s.Workspace != "" {
		return s.Workspace
	}
	return sbx.WorkspaceDir()
}

var (
	sessRe = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	dsRe   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,200}$`)
)

func (s *Session) validate() error {
	if !sessRe.MatchString(s.ID) {
		return fmt.Errorf("session id %q: want [a-z0-9]{1,16}", s.ID)
	}
	if s.UID == 0 || s.GID == 0 {
		return errors.New("session: uid/gid 0 not allowed")
	}
	if !dsRe.MatchString(s.Dataset) || strings.Contains(s.Dataset, "@") || strings.HasPrefix(s.Dataset, "-") {
		return fmt.Errorf("session dataset %q", s.Dataset)
	}
	if s.Project != "" {
		if err := checkProject(s.Project); err != nil {
			return err
		}
	}
	if s.Workspace != "" && (!filepath.IsAbs(s.Workspace) || filepath.Clean(s.Workspace) != s.Workspace) {
		return fmt.Errorf("session workspace %q", s.Workspace)
	}
	return nil
}

func (b *Backend) sessDir(id string) string { return filepath.Join(b.State, "svc", id) }

func (b *Backend) saveSession(s *Session) error {
	if err := os.MkdirAll(b.sessDir(s.ID), 0o700); err != nil {
		return err
	}
	j, _ := json.MarshalIndent(s, "", "  ")
	return keyring.WriteFileAtomic(filepath.Join(b.sessDir(s.ID), "session.json"), append(j, '\n'), 0o600)
}

// LoadSession reads a session record.
func (b *Backend) LoadSession(id string) (*Session, error) {
	if !sessRe.MatchString(id) {
		return nil, fmt.Errorf("session id %q", id)
	}
	j, err := os.ReadFile(filepath.Join(b.sessDir(id), "session.json"))
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(j, &s); err != nil {
		return nil, fmt.Errorf("session %s: %w", id, err)
	}
	return &s, nil
}

// ----------------------------------------------------------- artifacts

// Artifact is a checkpoint's record on the encrypted artifact dataset: the
// spec the instance ran and the workspace snapshot. Its digest covers every
// other field; a partial or edited file does not verify.
type Artifact struct {
	Session  string    `json:"session"`
	Gen      int64     `json:"gen"`
	Ckpt     int64     `json:"ckpt"`
	Snapshot string    `json:"snapshot"` // dataset@ysr1-<sess>-g<gen>-c<ckpt>
	Spec     Spec      `json:"spec"`
	Created  time.Time `json:"created"`
	Digest   string    `json:"digest"`
}

func (a Artifact) digest() string {
	a.Digest = ""
	j, _ := json.Marshal(a)
	h := sha256.Sum256(j)
	return hex.EncodeToString(h[:])
}

// SnapName is the workspace snapshot of checkpoint ckpt: named by session,
// generation (the suspend epoch) and the checkpoint op, so a retaken
// checkpoint never collides with the partial one it replaces.
func SnapName(dataset, sess string, gen, ckpt int64) string {
	return fmt.Sprintf("%s@ysr1-%s-g%d-c%d", dataset, sess, gen, ckpt)
}

// snapOf reports whether snapshot name belongs to checkpoint ckpt of sess
// (any generation); ckpt < 0 matches every checkpoint of the session.
func snapOf(name, sess string, ckpt int64) bool {
	_, short, ok := strings.Cut(name, "@")
	pre := "ysr1-" + sess + "-g"
	if !ok || !strings.HasPrefix(short, pre) {
		return false
	}
	g, c, ok := strings.Cut(strings.TrimPrefix(short, pre), "-c")
	if !ok || g == "" || strings.Trim(g, "0123456789") != "" || strings.Trim(c, "0123456789") != "" {
		return false
	}
	return ckpt < 0 || c == fmt.Sprint(ckpt)
}

func (b *Backend) artPath(sess string, ckpt int64) string {
	return filepath.Join(b.ArtDir, sess, fmt.Sprintf("%d.json", ckpt))
}

// writeArtifact writes the artifact create-only: a temp file, fsync, then
// link(2) to the final name (EEXIST if a copy of this op already wrote it).
// A crash or a kill mid-write leaves at most the temp file, which
// CheckpointOK does not accept and Delete removes.
func (b *Backend) writeArtifact(a Artifact) (int64, error) {
	a.Digest = a.digest()
	j, _ := json.MarshalIndent(a, "", "  ")
	j = append(j, '\n')
	dir := filepath.Join(b.ArtDir, a.Session)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	final := b.artPath(a.Session, a.Ckpt)
	tmp := fmt.Sprintf("%s.tmp.%d", final, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	_, werr := f.Write(j)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			if old, rerr := b.readArtifact(a.Session, a.Ckpt); rerr == nil && old.Snapshot == a.Snapshot {
				return int64(len(j)), nil // an earlier copy of this op wrote it
			}
		}
		return 0, err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return int64(len(j)), nil
}

func (b *Backend) readArtifact(sess string, ckpt int64) (Artifact, error) {
	var a Artifact
	j, err := os.ReadFile(b.artPath(sess, ckpt))
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(j, &a); err != nil {
		return a, fmt.Errorf("artifact %s/%d: %w", sess, ckpt, err)
	}
	if a.Digest != a.digest() || a.Session != sess || a.Ckpt != ckpt {
		return a, fmt.Errorf("artifact %s/%d: digest or identity mismatch", sess, ckpt)
	}
	return a, nil
}

// artFiles lists the artifact's files: the final one and any temp files.
func (b *Backend) artFiles(sess string, ckpt int64) []string {
	m, _ := filepath.Glob(b.artPath(sess, ckpt) + "*")
	return m
}

// --------------------------------------------------------------- op locks

// opLock takes the op's lock file (<state>/ops/<id>.lock) for the duration
// of one copy. Every child process the copy starts (zfs, the shim)
// inherits it, so after a crash of this process InFlight still sees the op
// in flight until the last of them is gone (A1, the settle bound). A lock
// already held means an earlier copy is still running: this copy refuses
// (its answer is an error, unknown, and the op waits to settle).
func (b *Backend) opLock(id int64) (*os.File, func(), error) {
	dir := filepath.Join(b.State, "ops")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%d.lock", id)), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, fmt.Errorf("op %d: an earlier copy is still in flight", id)
		}
		return nil, nil, err
	}
	b.mu.Lock()
	b.inflight[id]++
	b.mu.Unlock()
	return f, func() {
		b.mu.Lock()
		b.inflight[id]--
		b.mu.Unlock()
		f.Close()
	}, nil
}

// lockHeld reports whether some process holds op id's lock.
func (b *Backend) lockHeld(id int64) (bool, error) {
	f, err := os.OpenFile(filepath.Join(b.State, "ops", fmt.Sprintf("%d.lock", id)), os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return true, nil
		}
		return false, err
	}
	return false, nil // closing f releases it
}

// ---------------------------------------------------------------- timings

// Timing is one backend call, as measured inside it (the e2e reads these
// from <state>/timings.jsonl).
type Timing struct {
	Op    string             `json:"op"` // up quiesce checkpoint destroy restore unquiesce pause unpause delete
	Sess  string             `json:"sess"`
	Inst  int64              `json:"inst"`
	Ckpt  int64              `json:"ckpt,omitempty"`
	OpID  int64              `json:"op_id,omitempty"`
	OK    bool               `json:"ok"`
	Err   string             `json:"err,omitempty"`
	Ms    float64            `json:"ms"`
	Steps map[string]float64 `json:"steps_ms,omitempty"`
	Info  map[string]any     `json:"info,omitempty"`
	At    time.Time          `json:"at"`
}

type timer struct {
	b    *Backend
	t    Timing
	t0   time.Time
	mark time.Time
}

func (b *Backend) timer(op, sess string, inst, ckpt, opID int64) *timer {
	now := b.now()
	return &timer{b: b, t: Timing{Op: op, Sess: sess, Inst: inst, Ckpt: ckpt, OpID: opID, At: now.UTC(),
		Steps: map[string]float64{}, Info: map[string]any{}}, t0: now, mark: now}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// step records the time since the previous step (or the start) as name.
func (t *timer) step(name string) {
	now := t.b.now()
	t.t.Steps[name] += ms(now.Sub(t.mark))
	t.mark = now
}

func (t *timer) info(k string, v any) { t.t.Info[k] = v }

func (t *timer) done(err *error) {
	t.t.Ms = ms(t.b.now().Sub(t.t0))
	t.t.OK = *err == nil
	if *err != nil {
		t.t.Err = (*err).Error()
	}
	t.b.record(t.t)
}

func (b *Backend) record(t Timing) {
	if b.OnTiming != nil {
		b.OnTiming(t)
	}
	if b.State == "" {
		return
	}
	j, _ := json.Marshal(t)
	b.mu.Lock()
	defer b.mu.Unlock()
	if f, err := os.OpenFile(filepath.Join(b.State, "timings.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
		f.Write(append(j, '\n'))
		f.Close()
	}
}
