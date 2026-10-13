package ledger

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"hegel.dev/go/hegel"
)

var ctx = context.Background()

// The test valuation: a priced provider route and a resource-valued local route (money 0).
var testVal = Valuation{Digest: "v1", Routes: map[string]Route{
	"local": {Units: Prices{Input: 1_000_000, CacheRead: 250_000, CacheWrite: 1_000_000, Output: 2_000_000}},
	"provider": {Units: Prices{Input: 3_000_000, CacheRead: 300_000, CacheWrite: 3_750_000, Output: 15_000_000},
		Money: Prices{Input: 3_000_000, CacheRead: 300_000, CacheWrite: 3_750_000, Output: 15_000_000}},
}}

var testLimits = Limits{Tokens: 600, Charge: 2500, Money: 2000}

// worstIn is the oracle's own price for an input bound: the dearest input class, written out independently of
// Prices.maxIn so a wrong maxIn cannot agree with it.
func worstIn(p Prices) int64 {
	w := p.Input
	if p.CacheRead > w {
		w = p.CacheRead
	}
	if p.CacheWrite > w {
		w = p.CacheWrite
	}
	return w
}

// mcall is the model's view of a call; real is what the world actually charged (a ghost the ledger never sees).
type mcall struct {
	attempt, route, state string
	maxIn, maxOut         int64
	served                bool
	real                  Usage
	settled               Usage
}

// machine drives the real ledger and a model of it. Rules: reserve, send, answer, lose, serve (the provider
// serves a call whose answer is lost), resolve, crash (close and reopen: recovery), end, report.
type machine struct {
	path    string
	l       *Ledger
	calls   map[string]*mcall
	order   []string
	ended   map[string]bool
	next    int
	crashes int
}

var attempts = []string{"a1", "a2"}

func (m *machine) pick(tc hegel.TestCase, states ...string) *mcall {
	var c []string
	for _, id := range m.order {
		for _, s := range states {
			if m.calls[id].state == s {
				c = append(c, id)
			}
		}
	}
	tc.Assume(len(c) > 0)
	id := c[hegel.Draw(tc, hegel.Integers(0, len(c)-1))]
	return m.calls[id]
}

func (m *machine) id(c *mcall) string {
	for id, x := range m.calls {
		if x == c {
			return id
		}
	}
	panic("no id")
}

// what the model says the attempt holds
func (m *machine) heldOf(attempt string) (t, ch, mo int64) {
	for _, c := range m.calls {
		if c.attempt != attempt {
			continue
		}
		r := testVal.Routes[c.route]
		if c.state == Settled {
			t += c.settled.tokens()
			ch += c.settled.cost(r.Units)
			mo += c.settled.cost(r.Money)
		} else {
			t += c.maxIn + c.maxOut
			ch += ceilDiv(c.maxIn*worstIn(r.Units)+c.maxOut*r.Units.Output, perMillion)
			mo += ceilDiv(c.maxIn*worstIn(r.Money)+c.maxOut*r.Money.Output, perMillion)
		}
	}
	return
}

func (m *machine) RuleReserve(tc hegel.TestCase) {
	attempt := attempts[hegel.Draw(tc, hegel.Integers(0, 1))]
	route := []string{"local", "provider"}[hegel.Draw(tc, hegel.Integers(0, 1))]
	in := int64(hegel.Draw(tc, hegel.Integers(0, 300)))
	want := int64(hegel.Draw(tc, hegel.Integers(1, 300)))
	minOut := int64(hegel.Draw(tc, hegel.Integers(1, int(want))))
	m.next++
	id := fmt.Sprintf("c%d", m.next)
	ht, hc, hm := m.heldOf(attempt)
	got, err := m.l.Reserve(ctx, attempt, id, route, in, want, minOut)
	r := testVal.Routes[route]
	fits := func(out int64) bool {
		return ht+in+out <= testLimits.Tokens &&
			hc+ceilDiv(in*worstIn(r.Units)+out*r.Units.Output, perMillion) <= testLimits.Charge &&
			hm+ceilDiv(in*worstIn(r.Money)+out*r.Money.Output, perMillion) <= testLimits.Money
	}
	switch {
	case m.ended[attempt]:
		if !errors.Is(err, ErrEnded) {
			tc.Errorf("reserve on an ended attempt: %v", err)
		}
	case errors.Is(err, ErrLimit):
		if fits(minOut) {
			tc.Errorf("refused %s although min %d fits (held %d/%d/%d, in %d)", route, minOut, ht, hc, hm, in)
		}
	case err != nil:
		tc.Errorf("reserve: %v", err)
	default:
		if got < minOut || got > want || !fits(got) {
			tc.Errorf("reserve granted %d (min %d, want %d) fits=%v", got, minOut, want, fits(got))
		}
		if got < want && fits(got+1) {
			tc.Errorf("reserve granted %d but %d fits", got, got+1)
		}
		m.calls[id] = &mcall{attempt: attempt, route: route, state: Reserved, maxIn: in, maxOut: got}
		m.order = append(m.order, id)
	}
}

func (m *machine) RuleSend(tc hegel.TestCase) {
	c := m.pick(tc, Reserved)
	if err := m.l.MarkSent(ctx, m.id(c), "ext-"+m.id(c)); err != nil {
		tc.Errorf("send: %v", err)
	}
	c.state = Sent
}

// drawUsage is a usage within the call's maximum: the input bound split into classes, the output up to max.
func drawUsage(tc hegel.TestCase, c *mcall) Usage {
	in := int64(hegel.Draw(tc, hegel.Integers(0, int(c.maxIn))))
	cr := int64(hegel.Draw(tc, hegel.Integers(0, int(c.maxIn-in))))
	cw := int64(hegel.Draw(tc, hegel.Integers(0, int(c.maxIn-in-cr))))
	return Usage{Input: in, CacheRead: cr, CacheWrite: cw, Output: int64(hegel.Draw(tc, hegel.Integers(0, int(c.maxOut))))}
}

func (m *machine) RuleAnswer(tc hegel.TestCase) {
	c := m.pick(tc, Sent)
	u := drawUsage(tc, c)
	if err := m.l.Settle(ctx, m.id(c), u); err != nil {
		tc.Errorf("settle: %v", err)
	}
	c.state, c.served, c.real, c.settled = Settled, true, u, u
}

func (m *machine) RuleLose(tc hegel.TestCase) {
	c := m.pick(tc, Sent)
	if err := m.l.Unresolve(ctx, m.id(c)); err != nil {
		tc.Errorf("unresolve: %v", err)
	}
	c.state = Unresolved
}

// the provider serves a call whose answer never came back (or that was in flight at a crash)
func (m *machine) RuleServeUnanswered(tc hegel.TestCase) {
	c := m.pick(tc, Unresolved)
	tc.Assume(!c.served)
	c.served, c.real = true, drawUsage(tc, c)
}

// an authoritative record resolves an unresolved call: halo's usage for a served one, zero for one halo never
// accepted and whose deadline closed
func (m *machine) RuleResolve(tc hegel.TestCase) {
	c := m.pick(tc, Unresolved)
	u := c.real // zero if never served
	if err := m.l.Settle(ctx, m.id(c), u); err != nil {
		tc.Errorf("resolve: %v", err)
	}
	c.state, c.settled = Settled, u
}

func (m *machine) RuleCrash(tc hegel.TestCase) {
	tc.Assume(m.crashes < 3)
	m.crashes++
	if err := m.l.Close(); err != nil {
		tc.Errorf("close: %v", err)
	}
	l, err := Open(m.path)
	if err != nil {
		tc.Errorf("reopen: %v", err)
	}
	m.l = l
	for _, c := range m.calls {
		if c.state == Reserved || c.state == Sent {
			c.state = Unresolved
		}
	}
}

func (m *machine) RuleEnd(tc hegel.TestCase) {
	attempt := attempts[hegel.Draw(tc, hegel.Integers(0, 1))]
	if err := m.l.End(ctx, attempt); err != nil {
		tc.Errorf("end: %v", err)
	}
	m.ended[attempt] = true
}

func (m *machine) RuleReport(tc hegel.TestCase) {
	attempt := attempts[hegel.Draw(tc, hegel.Integers(0, 1))]
	s, err := m.l.Report(ctx, attempt)
	inflight, unresolved := false, false
	var want Pair
	for _, c := range m.calls {
		if c.attempt != attempt {
			continue
		}
		r := testVal.Routes[c.route]
		switch c.state {
		case Reserved, Sent:
			inflight = true
		case Unresolved:
			unresolved = true
			want.UnresolvedMax += ceilDiv(c.maxIn*worstIn(r.Units)+c.maxOut*r.Units.Output, perMillion)
		case Settled:
			want.Confirmed += c.settled.cost(r.Units)
		}
	}
	if inflight {
		if !errors.Is(err, ErrInFlight) {
			tc.Errorf("report with calls in flight: %v", err)
		}
		return
	}
	if err != nil {
		tc.Errorf("report: %v", err)
	}
	if s.Charge != want {
		tc.Errorf("report charge %+v, model %+v", s.Charge, want)
	}
	if (s.Certainty == "bounded") != unresolved {
		tc.Errorf("certainty %s with unresolved=%v", s.Certainty, unresolved)
	}
}

// withinLimits: what each attempt holds fits every limit
func (m *machine) InvariantWithinLimits(tc hegel.TestCase) {
	for _, a := range attempts {
		t, ch, mo := m.heldOf(a)
		if t > testLimits.Tokens || ch > testLimits.Charge || mo > testLimits.Money {
			tc.Errorf("%s holds %d/%d/%d over %+v", a, t, ch, mo, testLimits)
		}
	}
}

// accounted: what the world charged never exceeds what the ledger holds (per attempt, in charge and money)
func (m *machine) InvariantAccounted(tc hegel.TestCase) {
	for _, a := range attempts {
		_, ch, mo := m.heldOf(a)
		var rc, rm int64
		for _, c := range m.calls {
			if c.attempt == a && c.served {
				r := testVal.Routes[c.route]
				rc += c.real.cost(r.Units)
				rm += c.real.cost(r.Money)
			}
		}
		if rc > ch || rm > mo {
			tc.Errorf("%s: real %d/%d exceeds held %d/%d", a, rc, rm, ch, mo)
		}
	}
}

func newMachine(t testing.TB, dir string) *machine {
	path := filepath.Join(dir, "ledger.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range attempts {
		if err := l.Begin(a, testLimits, testVal); err != nil {
			t.Fatal(err)
		}
	}
	return &machine{path: path, l: l, calls: map[string]*mcall{}, ended: map[string]bool{}}
}

func TestLedgerAgainstModel(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		m := newMachine(t, t.TempDir())
		defer func() { m.l.Close() }()
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantWithinLimits", "InvariantAccounted"))
	})
}

// Concurrent reservations of one attempt never pass a limit together (the reservation is one immediate
// transaction). Run under -race.
func TestConcurrentReservations(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		l, err := Open(filepath.Join(t.TempDir(), "ledger.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if err := l.Begin("a", testLimits, testVal); err != nil {
			t.Fatal(err)
		}
		n := hegel.Draw(ht, hegel.Integers(2, 12))
		type req struct {
			in, want int64
			route    string
		}
		reqs := make([]req, n)
		for i := range reqs {
			reqs[i] = req{int64(hegel.Draw(ht, hegel.Integers(0, 200))), int64(hegel.Draw(ht, hegel.Integers(1, 200))),
				[]string{"local", "provider"}[hegel.Draw(ht, hegel.Integers(0, 1))]}
		}
		var wg sync.WaitGroup
		for i, r := range reqs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := l.Reserve(ctx, "a", fmt.Sprintf("c%d", i), r.route, r.in, r.want, 1)
				if err != nil && !errors.Is(err, ErrLimit) {
					t.Errorf("reserve: %v", err)
				}
			}()
		}
		wg.Wait()
		tx, _ := l.db.BeginTx(ctx, nil)
		ht2, hc, hm, err := held(ctx, tx, "a")
		tx.Rollback()
		if err != nil {
			t.Fatal(err)
		}
		if ht2 > testLimits.Tokens || hc > testLimits.Charge || hm > testLimits.Money {
			ht.Fatalf("concurrent reservations hold %d/%d/%d over %+v", ht2, hc, hm, testLimits)
		}
	})
}

// Settled amounts round up per call, and a pinned valuation is the one used even if the caller's table changes.
func TestRoundingAndPinning(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Begin("a", testLimits, testVal); err != nil {
		t.Fatal(err)
	}
	other := Valuation{Digest: "v2", Routes: map[string]Route{"local": {}}}
	if err := l.Begin("a", testLimits, other); err != nil { // a second Begin does not re-price the attempt
		t.Fatal(err)
	}
	if _, err := l.Reserve(ctx, "a", "c1", "local", 10, 10, 1); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkSent(ctx, "c1", ""); err != nil {
		t.Fatal(err)
	}
	if err := l.Settle(ctx, "c1", Usage{CacheRead: 1}); err != nil { // 0.25 units: rounds up to 1
		t.Fatal(err)
	}
	s, err := l.Report(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if s.Charge.Confirmed != 1 || s.Valuation != "v1" || s.Certainty != "exact" {
		t.Fatalf("spend %+v", s)
	}
}
