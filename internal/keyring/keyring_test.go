package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yard/internal/sts"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const hA, hB Handle = 0x81010010, 0x81010011

var cfg = Config{PublishDelay: 24 * time.Hour, RetireGrace: time.Hour}

func newRing(t *testing.T) (*Ring, *MemStore, *clock, string) {
	t.Helper()
	st := NewMemStore()
	st.Bits = 1024 // speed; the key size is not what these tests are about
	c := &clock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	p := filepath.Join(t.TempDir(), "keyring.json")
	r, err := Init(st, p, hA, hB, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return r, st, c, p
}

func kids(set sts.JWKS) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func slot(r *Ring, h Handle) Slot {
	for _, s := range r.Snapshot().Slots {
		if s.Handle == h {
			return s
		}
	}
	return Slot{}
}

func signVerify(t *testing.T, r *Ring, set sts.JWKS) (string, error) {
	t.Helper()
	var tok string
	err := r.WithActive(func(k sts.KeySigner, kid string) error {
		var err error
		tok, err = sts.SignJWT(k, kid, map[string]any{"iss": "i", "iat": 1, "exp": 2})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sts.Verify(tok, set, sts.VerifyOptions{Issuer: "i"})
	return tok, err
}

func TestInitPublishesBothKeysActiveFirst(t *testing.T) {
	r, _, _, p := newRing(t)
	set := r.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("jwks has %d keys, want 2", len(set.Keys))
	}
	if set.Keys[0].Kid != slot(r, hA).Kid || set.Keys[1].Kid != slot(r, hB).Kid {
		t.Fatalf("order: %v", kids(set))
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if _, err := Init(NewMemStore(), p, hA, hB, cfg, nil); err == nil {
		t.Fatal("Init over an existing state file must fail")
	}
}

func TestInitAdoptsExistingKeys(t *testing.T) {
	st := NewMemStore()
	st.Bits = 1024
	k, _ := st.Create(hA)
	r, err := Init(st, filepath.Join(t.TempDir(), "s.json"), hA, hB, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if slot(r, hA).Kid != sts.Thumbprint(k.Public()) {
		t.Fatal("existing key at the active handle was not adopted")
	}
}

func TestFullRotationCycle(t *testing.T) {
	r, st, c, p := newRing(t)
	kidA, kidB := slot(r, hA).Kid, slot(r, hB).Kid
	before := r.JWKS()

	// a token signed by A before rotation
	tokA, err := signVerify(t, r, before)
	if err != nil {
		t.Fatal(err)
	}
	// rotation is refused until the standby has been published long enough
	if err := r.Rotate(); !errors.Is(err, ErrNotDue) {
		t.Fatalf("early rotate: %v", err)
	}
	c.add(cfg.PublishDelay)
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, kid := r.Active(); kid != kidB {
		t.Fatalf("active after rotate = %s, want B %s", kid, kidB)
	}
	mid := r.JWKS()
	if got := kids(mid); len(got) != 2 || got[0] != kidB || got[1] != kidA {
		t.Fatalf("jwks during grace = %v, want [B A]", got)
	}
	// old tokens still verify during grace, new ones are signed by B
	if _, err := sts.Verify(tokA, mid, sts.VerifyOptions{Issuer: "i"}); err != nil {
		t.Fatalf("A token during grace: %v", err)
	}
	if _, err := signVerify(t, r, mid); err != nil {
		t.Fatal(err)
	}
	// only one rotation in flight
	if err := r.Rotate(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second rotate: %v", err)
	}
	if err := r.Retire(); !errors.Is(err, ErrNotDue) {
		t.Fatalf("early retire: %v", err)
	}
	if r.RetireDue() {
		t.Fatal("RetireDue before grace")
	}
	c.add(cfg.RetireGrace)
	if !r.RetireDue() {
		t.Fatal("RetireDue after grace")
	}
	if err := r.Retire(); err != nil {
		t.Fatal(err)
	}
	after := r.JWKS()
	sA := slot(r, hA)
	if sA.State != Standby || sA.Kid == kidA || !sA.Published.Equal(c.now()) {
		t.Fatalf("A after retire: %+v", sA)
	}
	if got := kids(after); len(got) != 2 || got[0] != kidB || got[1] != sA.Kid {
		t.Fatalf("jwks after retire = %v", got)
	}
	if _, err := sts.Verify(tokA, after, sts.VerifyOptions{Issuer: "i"}); err == nil {
		t.Fatal("retired key's token must no longer verify")
	}
	// evict happened before create on the same handle
	j := strings.Join(st.Calls, ",")
	if !strings.Contains(j, "evict 0x81010010,create 0x81010010") {
		t.Fatalf("store calls: %s", j)
	}
	// state survives a reopen, and the next rotation starts the cycle again
	r2, err := Open(st, p, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Snapshot().Generation != r.Snapshot().Generation {
		t.Fatal("generation not persisted")
	}
	if err := r2.Rotate(); !errors.Is(err, ErrNotDue) {
		t.Fatalf("fresh standby must wait PublishDelay: %v", err)
	}
	c.add(cfg.PublishDelay)
	if err := r2.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, kid := r2.Active(); kid != sA.Kid {
		t.Fatal("second rotation did not activate the new A")
	}
}

func TestRetireCrashBetweenEvictAndCreate(t *testing.T) {
	r, st, c, p := newRing(t)
	c.add(cfg.PublishDelay)
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	c.add(cfg.RetireGrace)
	st.FailNext["create"] = errors.New("power cut")
	if err := r.Retire(); err == nil {
		t.Fatal("expected failure")
	}
	if s := slot(r, hA); s.State != Replacing {
		t.Fatalf("slot A = %s, want replacing", s.State)
	}
	if ok, _ := st.Exists(hA); ok {
		t.Fatal("old key should be evicted")
	}
	if n := len(r.JWKS().Keys); n != 1 {
		t.Fatalf("jwks during replace has %d keys, want 1 (active only)", n)
	}
	// a restart finishes the replace
	r2, err := Open(st, p, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if s := slot(r2, hA); s.State != Standby {
		t.Fatalf("after reopen: %+v", s)
	}
	if n := len(r2.JWKS().Keys); n != 2 {
		t.Fatalf("jwks has %d keys", n)
	}
}

func TestRetireResumesInProcess(t *testing.T) {
	r, st, c, _ := newRing(t)
	c.add(cfg.PublishDelay)
	r.Rotate()
	c.add(cfg.RetireGrace)
	st.FailNext["evict"] = errors.New("tpm busy")
	if err := r.Retire(); err == nil {
		t.Fatal("expected failure")
	}
	if err := r.Retire(); err != nil { // second call finishes the replace
		t.Fatal(err)
	}
	if s := slot(r, hA); s.State != Standby {
		t.Fatalf("%+v", s)
	}
}

func TestCrashAfterCreateBeforeSaveIsAdopted(t *testing.T) {
	r, st, c, p := newRing(t)
	c.add(cfg.PublishDelay)
	r.Rotate()
	c.add(cfg.RetireGrace)
	// simulate: state says replacing, old key evicted, new key created, then crash before save
	r.mu.Lock()
	i := r.find(Retiring)
	r.st.Slots[i].State = Replacing
	r.save()
	r.mu.Unlock()
	st.Evict(hA)
	k, _ := st.Create(hA)
	r2, err := Open(st, p, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if slot(r2, hA).Kid != sts.Thumbprint(k.Public()) {
		t.Fatal("key created before the crash was not adopted")
	}
}

func TestOpenDetectsSwappedKey(t *testing.T) {
	_, st, _, p := newRing(t)
	st.Evict(hB)
	st.Create(hB)
	if _, err := Open(st, p, cfg, nil); !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("got %v, want ErrStateMismatch", err)
	}
}

func TestOpenRejectsBadState(t *testing.T) {
	_, st, _, p := newRing(t)
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), `"standby"`, `"active"`, 1)
	os.WriteFile(p, []byte(bad), 0o600)
	if _, err := Open(st, p, cfg, nil); err == nil || !strings.Contains(err.Error(), "2 active") {
		t.Fatalf("got %v", err)
	}
}

func TestDirStore(t *testing.T) {
	d := DirStore{Dir: t.TempDir()}
	if ok, _ := d.Exists(hA); ok {
		t.Fatal("empty dir")
	}
	k, err := d.Create(hA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Create(hA); !errors.Is(err, ErrOccupied) {
		t.Fatalf("create over existing: %v", err)
	}
	k2, err := d.Open(hA)
	if err != nil || sts.Thumbprint(k2.Public()) != sts.Thumbprint(k.Public()) {
		t.Fatal("reopen mismatch")
	}
	fi, _ := os.Stat(d.file(hA))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode())
	}
	if err := d.Evict(hA); err != nil {
		t.Fatal(err)
	}
}

func TestTPMStoreRefusesNonPersistentHandle(t *testing.T) {
	s := TPMStore{}
	if _, err := s.Create(0x80000001); err == nil {
		t.Fatal("transient handle accepted")
	}
}
