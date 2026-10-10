package lifecycle

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSessionPolicyDoesNotSuspendOrPausePeers(t *testing.T) {
	for _, pause := range []bool{false, true} {
		t.Run(map[bool]string{false: "suspend", true: "pause"}[pause], func(t *testing.T) {
			st, err := OpenOwned(filepath.Join(t.TempDir(), "lifecycle.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			w := newFakeWorld()
			for _, s := range []string{"target", "peer"} {
				w.addSession(s)
				w.addProject(s, "shared-project")
			}
			cfg := Config{OpTimeout: 200, MaxAttempts: 3, Clients: []string{"cli"},
				Policies:        map[string]Policy{"shared-class": {KeepWarm: true, IdleAfter: 1 << 50, MaxAge: 60_000}},
				SessionPolicies: map[string]Policy{"target": {IdleAfter: 0, MaxAge: 60_000, Pause: pause, KeepWarm: pause}}}
			clk := &clock{t: 1}
			m, err := Start(context.Background(), st, cfg, w, &factLog{}, clk.now)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Wait()
			for _, s := range []string{"target", "peer"} {
				if err := m.AddSession(s, "shared-class", KindService, "shared-project"); err != nil {
					t.Fatal(err)
				}
			}
			want := Suspended
			if pause {
				want = Paused
			}
			for i := 0; i < 300; i++ {
				m.Poll(context.Background())
				m.Wait()
				clk.add(1)
				runtime.Gosched()
				c := m.State()
				if c.Rows["peer"].State != Active {
					t.Fatalf("command affected peer: %s", c.Rows["peer"].State)
				}
				if c.Rows["target"].State == want && c.Rows["target"].Phase == PNone {
					break
				}
			}
			if c := m.State(); c.Rows["target"].State != want {
				t.Fatalf("target policy not applied: %+v", c.Rows["target"])
			}
			w.mu.Lock()
			loaded := w.keyLoaded["shared-project"]
			w.mu.Unlock()
			if !loaded {
				t.Fatal("shared key unloaded while peer remains active")
			}
		})
	}
}

func TestSessionSettlementPrecedesProjectCleanup(t *testing.T) {
	c := NewCtl(Config{})
	c.AddSession("web", "class", KindService, "project")
	r := c.Rows["web"]
	r.State = Removed
	c.Rows["web"] = r
	c.Ops[10] = Op{ID: 10, Sess: "project", Kind: OUnmount, St: Unknown}
	if !SessionOpsSettled(c, "web") {
		t.Fatal("orphan cleanup cannot wait for blocked project unmount")
	}
	r.Op = 11
	c.Rows["web"] = r
	c.Ops[11] = Op{ID: 11, Sess: "web", Kind: ODestroy, St: NotDone}
	if SessionOpsSettled(c, "web") {
		t.Fatal("destroy-done fence bypassed")
	}
	o := c.Ops[11]
	o.St = Done
	c.Ops[11] = o
	if !SessionOpsSettled(c, "web") {
		t.Fatal("completed session cleanup still blocked by project work")
	}
}
