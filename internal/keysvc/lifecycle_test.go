package keysvc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"yard/internal/lifecycle"
)

type entryMap map[string]uint64

func (m entryMap) EntryOf(s string) (uint64, bool) { v, ok := m[s]; return v, ok }

type okMinter struct{}

func (okMinter) Mint(context.Context, string, int64) error            { return nil }
func (okMinter) Holds(context.Context, string, int64) (bool, error)   { return true, nil }
func (okMinter) InFlight(context.Context, lifecycle.Op) (bool, error) { return false, nil }

type quiet struct{}

func (quiet) Activity(context.Context, string) (int64, error) { return 0, nil }

// TestLifecycleKV drives the SR0 lifecycle Machine with the kv backend:
// suspend (Checkpoint = seal at E + spill), SuspendCommit (E+1), resume
// (Restore = open at E+1 + restore), ResumeComplete's ODelete (the key's
// shred), a second suspend with a fresh key at E+1, and the shred claim.
func TestLifecycleKV(t *testing.T) {
	e := newEnv(t, mutants{})
	ctx := context.Background()
	e.halo.AddEntry(7)
	st, err := lifecycle.OpenStore(filepath.Join(t.TempDir(), "lifecycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := lifecycle.Config{OpTimeout: 15_000, MaxAttempts: 3, Clients: []string{"msg"},
		Policies: map[string]lifecycle.Policy{"kv": {IdleAfter: 1000, MaxAge: 3_600_000}}}
	router := &lifecycle.Router{Backends: map[string]lifecycle.Backend{lifecycle.KindKV: &KV{Svc: e.svc, Entries: entryMap{"s1": 7}}},
		Mint: okMinter{}, Artifacts: &Artifacts{Svc: e.svc}, Act: quiet{}}
	now := func() int64 { return e.clock.Load() }
	m, err := lifecycle.Start(ctx, st, cfg, router, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	e.is.SetEpochs(m)
	e.svc.o.Epochs = m
	if err := m.AddSession("s1", "kv", lifecycle.KindKV, ""); err != nil {
		t.Fatal(err)
	}
	until := func(what string, ok func(r lifecycle.Row) bool) {
		t.Helper()
		for i := 0; i < 200; i++ {
			_ = m.Poll(ctx)
			m.Wait()
			e.svc.Poll(ctx)
			if ok(m.State().Rows["s1"]) {
				return
			}
			e.advance(300 * time.Millisecond)
		}
		t.Fatalf("%s: stuck at %+v; keysvc %+v", what, m.State().Rows["s1"], e.svc.State().Sess["s1"])
	}
	until("suspend", func(r lifecycle.Row) bool { return r.State == lifecycle.Suspended })
	if r := m.State().Rows["s1"]; r.CredEpoch != 2 {
		t.Fatalf("epoch %d after the suspend", r.CredEpoch)
	}
	if en, _ := e.halo.entry(7); !en.spilled || en.keyID[len(en.keyID)-6:] != ":e1:s1" {
		t.Fatalf("spill: %+v", en)
	}
	if err := m.Resume("s1", "msg", m.Token("s1")); err != nil {
		t.Fatal(err)
	}
	until("resume", func(r lifecycle.Row) bool { return r.State == lifecycle.Active })
	if en, _ := e.halo.entry(7); en.spilled {
		t.Fatal("not restored")
	}
	until("delete", func(lifecycle.Row) bool { k := e.svc.State().Keys[1]; return k.Shredding && !k.Wrapped })
	if hs := e.halo.state("s1"); hs.lastSpill != 1 || hs.lastRestore != 2 {
		t.Fatalf("halo epochs %+v", hs)
	}
	until("second suspend", func(r lifecycle.Row) bool { return r.State == lifecycle.Suspended && r.CredEpoch == 3 })
	en, _ := e.halo.entry(7)
	if en.keyID[len(en.keyID)-6:] != ":e2:s1" {
		t.Fatalf("second spill %q", en.keyID)
	}
	e.advance(310 * time.Second)
	e.svc.Poll(ctx)
	if !e.svc.Shredded("s1", e.svc.State().Keys[1].Ckpt) {
		t.Fatalf("first key not shredded: %+v", e.svc.State().Keys[1])
	}
	if e.svc.State().Keys[2].Shredding {
		t.Fatal("the live checkpoint's key is shredding")
	}
}
