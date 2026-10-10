package keysvc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type historyFullPeer struct {
	HaloAPI
	full  bool
	calls int
}

func (h *historyFullPeer) Register(ctx context.Context, sess, use, token string, key []byte) Answer {
	h.calls++
	if h.full {
		return Answer{Out: OutNotDone, Status: 409, Reason: "too many recent operations; retry later"}
	}
	return h.HaloAPI.Register(ctx, sess, use, token, key)
}

func TestHistoryBackpressureWaitsAndRecovers(t *testing.T) {
	e := newEnv(t, mutants{})
	e.epochs.set("s1", 1)
	e.halo.AddEntry(7)
	h := &historyFullPeer{HaloAPI: e.svc.o.Halo, full: true}
	e.svc.o.Halo = h
	if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); !errors.Is(err, ErrRetryLater) || h.calls != 1 {
		t.Fatalf("backpressure retried immediately: calls=%d err=%v", h.calls, err)
	}
	h.full = false
	if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
		t.Fatalf("later retry: %v", err)
	}
}

func TestDatabaseNoncePersistsAndNamesOperations(t *testing.T) {
	e := newEnv(t, mutants{})
	// Pin a known database id, avoiding probabilistic random-uniqueness assertions.
	if _, err := e.st.db.Exec(`UPDATE spill_meta SET v=1234567890123 WHERE k='nonce'`); err != nil {
		t.Fatal(err)
	}
	e.start()
	if got := e.svc.opID(Op{Oid: 7}); got != "y1234567890123.7" {
		t.Fatalf("persisted nonce not used: %s", got)
	}
	e.start()
	if got := e.svc.opID(Op{Oid: 7}); got != "y1234567890123.7" {
		t.Fatalf("nonce changed after restart: %s", got)
	}
}

// Exercise actual signed JWTs through the Unix client and the fake peer,
// including an answer lost before cancellation/TTL expiry and a yard restart.
func renewedRegistration(e *env, cancel bool) error {
	e.epochs.set("s1", 1)
	e.halo.AddEntry(7)
	if err := e.svc.apply(func(c *Ctl) error { c.AddSession("s1", 1); return nil }); err != nil {
		return err
	}
	if err := e.svc.suspendBegin("s1", 10, 7); err != nil {
		return err
	}
	old := e.svc.State().Sess["s1"]
	op := e.svc.State().Ops[old.Op]
	id := e.svc.opID(op)
	e.halo.setFault(func(path, use string) Fault { return FLoseAnswer })
	if a := e.svc.send(e.ctx, old.Op); a.Out != OutUnknown {
		return fmt.Errorf("lost answer: %+v", a)
	}
	e.halo.setFault(nil)
	// A restart must not relabel a retried operation, even with a fresh JWT.
	e.start()
	if got := e.svc.opID(e.svc.State().Ops[old.Op]); got != id {
		return fmt.Errorf("restart changed operation identity: %s != %s", got, id)
	}
	if cancel {
		e.halo.set(func(f *fakeHalo) { f.zero(f.sess("s1"), &f.sess("s1").seal, "seal", "revoked") })
		e.advance(16 * time.Second)
	} else {
		e.advance(601 * time.Second)
	}
	if _, err := e.svc.Seal(e.ctx, "s1", 10, 7); err != nil {
		return err
	}
	c := e.svc.State()
	if c.Sess["s1"].Spill == old.Spill || !c.Keys[old.Spill].Shredding || c.Keys[old.Spill].Wrapped {
		return fmt.Errorf("renewal did not replace/shred old key: %+v", c.Keys[old.Spill])
	}
	e.halo.mu.Lock()
	defer e.halo.mu.Unlock()
	recs := e.halo.sess("s1").ops
	if len(recs) < 2 || recs[0].op != id || recs[len(recs)-1].op == id {
		return fmt.Errorf("peer did not receive distinct signed operation ids: %+v", recs)
	}
	return nil
}

func init() {
	scenarios = append(scenarios,
		scenario{"cancelledRegistrationRenews", func(e *env) error { return renewedRegistration(e, true) }},
		scenario{"outlivedRegistrationRenews", func(e *env) error { return renewedRegistration(e, false) }})
}

func TestRegistrationRefusalClasses(t *testing.T) {
	for _, tt := range []struct {
		reason string
		class  string
		err    error
	}{
		{"operation id x already names another operation (key or epoch)", RefOpConflict, ErrOpConflict},
		{"too many recent operations; retry later", RefBackpressure, ErrRetryLater},
	} {
		a := Answer{Out: OutNotDone, Status: 409, Reason: tt.reason}
		if a.Class() != tt.class || !errors.Is(terminal(a), tt.err) {
			t.Fatalf("refusal %q: class=%s error=%v", tt.reason, a.Class(), terminal(a))
		}
	}
}
