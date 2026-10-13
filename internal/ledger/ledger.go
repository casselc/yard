// Package ledger is the broker's reservation ledger (design/AGENT-OPERATIONS.md section 6; spec/agentop/broker.qnt).
//
// One row per model call. A call is reserved at its maximum cost, in one immediate transaction that checks every
// limit of its attempt against everything the attempt already holds (confirmed usage, unresolved maxima, open
// reservations), before the call is sent. An answered call is settled at its confirmed usage under the attempt's
// pinned valuation. A call without an answer is unresolved and stays charged at its maximum until something
// authoritative resolves it (for the local route, halo's operation record while halo still holds it). Opening the
// ledger recovers it: every reserved or sent row is unresolved, since its connection is gone.
//
// Amounts are integers. Prices are valuation units (or µUSD) per million tokens; a call's charge rounds up.
package ledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// Prices per million tokens, by token class.
type Prices struct {
	Input      int64 `json:"input"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
	Output     int64 `json:"output"`
}

// maxIn is the most expensive input class: what an input bound is reserved at.
func (p Prices) maxIn() int64 { return max(p.Input, p.CacheRead, p.CacheWrite) }

// Route is one route's prices: valuation units (what Cordis settles) and actual money (provider routes only).
type Route struct {
	Units Prices `json:"units"`
	Money Prices `json:"money_micro_usd"`
}

// Valuation is the operator's price table, pinned per attempt.
type Valuation struct {
	Digest string           `json:"digest"`
	Routes map[string]Route `json:"routes"`
}

// Limits of an attempt the broker enforces, each on its own (wall time is yard-ctl's).
type Limits struct {
	Tokens int64 `json:"tokens"`
	Charge int64 `json:"charge"`
	Money  int64 `json:"money_micro_usd"`
}

// Usage of an answered call, by class. Input, CacheRead and CacheWrite are disjoint parts of the prompt.
type Usage struct {
	Input, CacheRead, CacheWrite, Output int64
}

func (u Usage) tokens() int64 { return u.Input + u.CacheRead + u.CacheWrite + u.Output }

const perMillion = 1_000_000

func ceilDiv(a, b int64) int64 { return (a + b - 1) / b }

func (u Usage) cost(p Prices) int64 {
	return ceilDiv(u.Input*p.Input+u.CacheRead*p.CacheRead+u.CacheWrite*p.CacheWrite+u.Output*p.Output, perMillion)
}

// States of a call.
const (
	Reserved   = "reserved"
	Sent       = "sent"
	Settled    = "settled"
	Unresolved = "unresolved"
)

var (
	ErrLimit    = errors.New("ledger: the call does not fit the attempt's limits")
	ErrEnded    = errors.New("ledger: the attempt has ended")
	ErrUnknown  = errors.New("ledger: no such attempt or call")
	ErrState    = errors.New("ledger: the call is not in a state that allows this")
	ErrInFlight = errors.New("ledger: calls are still in flight")
	ErrRoute    = errors.New("ledger: the route is not in the attempt's valuation")
)

// LimitError says which limit refused a call.
type LimitError struct{ Limit string }

func (e *LimitError) Error() string { return "ledger: the call does not fit the " + e.Limit + " limit" }
func (e *LimitError) Unwrap() error { return ErrLimit }

type Ledger struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS attempts (
  attempt TEXT PRIMARY KEY, tokens INTEGER NOT NULL, charge INTEGER NOT NULL, money INTEGER NOT NULL,
  valuation TEXT NOT NULL, ended INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS calls (
  call TEXT PRIMARY KEY, attempt TEXT NOT NULL REFERENCES attempts(attempt), route TEXT NOT NULL,
  state TEXT NOT NULL, max_in INTEGER NOT NULL, max_out INTEGER NOT NULL,
  max_charge INTEGER NOT NULL, max_money INTEGER NOT NULL,
  input INTEGER NOT NULL DEFAULT 0, cache_read INTEGER NOT NULL DEFAULT 0, cache_write INTEGER NOT NULL DEFAULT 0,
  output INTEGER NOT NULL DEFAULT 0, charge INTEGER NOT NULL DEFAULT 0, money INTEGER NOT NULL DEFAULT 0,
  ext TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS calls_attempt ON calls(attempt);`

// Open opens (creating) the ledger at path and recovers it: every reserved or sent row becomes unresolved.
func Open(path string) (*Ledger, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`UPDATE calls SET state = ? WHERE state IN (?, ?)`, Unresolved, Reserved, Sent); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db}, nil
}

func (l *Ledger) Close() error { return l.db.Close() }

// Begin records an attempt, its limits and its pinned valuation. Beginning it again with the same values is a no-op.
func (l *Ledger) Begin(attempt string, lim Limits, v Valuation) error {
	vj, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if lim.Tokens <= 0 || lim.Charge < 0 || lim.Money < 0 {
		return fmt.Errorf("ledger: invalid limits %+v", lim)
	}
	_, err = l.db.Exec(`INSERT INTO attempts(attempt, tokens, charge, money, valuation) VALUES (?, ?, ?, ?, ?)
	  ON CONFLICT(attempt) DO NOTHING`, attempt, lim.Tokens, lim.Charge, lim.Money, string(vj))
	return err
}

type attemptRow struct {
	lim   Limits
	val   Valuation
	ended bool
}

func loadAttempt(ctx context.Context, tx *sql.Tx, attempt string) (attemptRow, error) {
	var a attemptRow
	var vj string
	var ended int
	err := tx.QueryRowContext(ctx, `SELECT tokens, charge, money, valuation, ended FROM attempts WHERE attempt = ?`, attempt).
		Scan(&a.lim.Tokens, &a.lim.Charge, &a.lim.Money, &vj, &ended)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrUnknown
	}
	if err != nil {
		return a, err
	}
	a.ended = ended != 0
	return a, json.Unmarshal([]byte(vj), &a.val)
}

// held is what the attempt holds: settled rows at their confirmed usage, every other row at its maximum.
func held(ctx context.Context, tx *sql.Tx, attempt string) (tokens, charge, money int64, err error) {
	err = tx.QueryRowContext(ctx, `SELECT
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN input + cache_read + cache_write + output ELSE max_in + max_out END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN charge ELSE max_charge END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN money ELSE max_money END), 0)
	  FROM calls WHERE attempt = ?`, attempt).Scan(&tokens, &charge, &money)
	return
}

// fitOut is the largest output count that keeps tokens + charge + money within the limits, given the input bound.
func fitOut(lim Limits, ht, hc, hm, in int64, r Route) (int64, string) {
	out := lim.Tokens - ht - in
	which := "tokens"
	for _, c := range []struct {
		name      string
		lim, h    int64
		pIn, pOut int64
	}{
		{"charge", lim.Charge, hc, r.Units.maxIn(), r.Units.Output},
		{"money", lim.Money, hm, r.Money.maxIn(), r.Money.Output},
	} {
		room := (c.lim-c.h)*perMillion - in*c.pIn // ceil(x / 1e6) <= R  <=>  x <= R * 1e6
		if room < 0 {
			return -1, c.name
		}
		if c.pOut > 0 {
			if o := room / c.pOut; o < out {
				out, which = o, c.name
			}
		}
	}
	return out, which
}

// Reserve reserves a call of attempt on route, with an input bound and the output count it asks for, before it is
// sent. The output is clamped to what the limits leave; a call that cannot get at least minOut is refused with a
// *LimitError naming the limit. It returns the output count the broker must impose (max_tokens).
func (l *Ledger) Reserve(ctx context.Context, attempt, call, route string, in, wantOut, minOut int64) (int64, error) {
	if in < 0 || wantOut < 1 || minOut < 1 || minOut > wantOut {
		return 0, fmt.Errorf("ledger: invalid reservation in=%d want=%d min=%d", in, wantOut, minOut)
	}
	tx, err := l.db.BeginTx(ctx, nil) // immediate: concurrent reservations of an attempt serialize here
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	a, err := loadAttempt(ctx, tx, attempt)
	if err != nil {
		return 0, err
	}
	if a.ended {
		return 0, ErrEnded
	}
	r, ok := a.val.Routes[route]
	if !ok {
		return 0, ErrRoute
	}
	ht, hc, hm, err := held(ctx, tx, attempt)
	if err != nil {
		return 0, err
	}
	out, which := fitOut(a.lim, ht, hc, hm, in, r)
	out = min(out, wantOut)
	if out < minOut {
		return 0, &LimitError{Limit: which}
	}
	u := Usage{Output: out}
	maxCharge := ceilDiv(in*r.Units.maxIn()+u.Output*r.Units.Output, perMillion)
	maxMoney := ceilDiv(in*r.Money.maxIn()+u.Output*r.Money.Output, perMillion)
	if _, err := tx.ExecContext(ctx, `INSERT INTO calls(call, attempt, route, state, max_in, max_out, max_charge, max_money)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, call, attempt, route, Reserved, in, out, maxCharge, maxMoney); err != nil {
		return 0, err
	}
	return out, tx.Commit()
}

func (l *Ledger) transition(ctx context.Context, call string, from []string, to string, ext *string) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var st string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM calls WHERE call = ?`, call).Scan(&st); errors.Is(err, sql.ErrNoRows) {
		return ErrUnknown
	} else if err != nil {
		return err
	}
	ok := false
	for _, f := range from {
		ok = ok || st == f
	}
	if !ok {
		return fmt.Errorf("%w: %s is %s", ErrState, call, st)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE calls SET state = ? WHERE call = ?`, to, call); err != nil {
		return err
	}
	if ext != nil { // in the same transaction: a sent row always carries what resolves it
		if _, err := tx.ExecContext(ctx, `UPDATE calls SET ext = ? WHERE call = ?`, *ext, call); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkSent records that the call is about to leave (after Reserve committed), with what the route needs to resolve
// it later if its answer is lost (for the local route: halo's operation identity and exact submit body).
func (l *Ledger) MarkSent(ctx context.Context, call, ext string) error {
	return l.transition(ctx, call, []string{Reserved}, Sent, &ext)
}

// Unresolve records that the call's answer is lost: it stays charged at its maximum.
func (l *Ledger) Unresolve(ctx context.Context, call string) error {
	return l.transition(ctx, call, []string{Reserved, Sent}, Unresolved, nil)
}

// Settle records the call's confirmed usage (from its answer, or from an authoritative record that resolves an
// unresolved call), priced under the attempt's pinned valuation.
func (l *Ledger) Settle(ctx context.Context, call string, u Usage) error {
	if u.Input < 0 || u.CacheRead < 0 || u.CacheWrite < 0 || u.Output < 0 {
		return fmt.Errorf("ledger: negative usage %+v", u)
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var attempt, route, st string
	err = tx.QueryRowContext(ctx, `SELECT attempt, route, state FROM calls WHERE call = ?`, call).Scan(&attempt, &route, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnknown
	} else if err != nil {
		return err
	}
	if st != Sent && st != Unresolved {
		return fmt.Errorf("%w: settle %s in %s", ErrState, call, st)
	}
	a, err := loadAttempt(ctx, tx, attempt)
	if err != nil {
		return err
	}
	r := a.val.Routes[route]
	if _, err := tx.ExecContext(ctx, `UPDATE calls SET state = ?, input = ?, cache_read = ?, cache_write = ?, output = ?,
	  charge = ?, money = ? WHERE call = ?`, Settled, u.Input, u.CacheRead, u.CacheWrite, u.Output,
		u.cost(r.Units), u.cost(r.Money), call); err != nil {
		return err
	}
	return tx.Commit()
}

// End refuses further reservations for the attempt.
func (l *Ledger) End(ctx context.Context, attempt string) error {
	res, err := l.db.ExecContext(ctx, `UPDATE attempts SET ended = 1 WHERE attempt = ?`, attempt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUnknown
	}
	return nil
}

// Call is a call row, for resolution and evidence.
type Call struct {
	Call, Attempt, Route, State string
	MaxIn, MaxOut               int64
	Ext                         string
}

// Unresolved lists an attempt's unresolved calls.
func (l *Ledger) Unresolved(ctx context.Context, attempt string) ([]Call, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT call, attempt, route, state, max_in, max_out, ext FROM calls
	  WHERE attempt = ? AND state = ? ORDER BY call`, attempt, Unresolved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Call
	for rows.Next() {
		var c Call
		if err := rows.Scan(&c.Call, &c.Attempt, &c.Route, &c.State, &c.MaxIn, &c.MaxOut, &c.Ext); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Pair is a confirmed amount and the maxima of unresolved calls; what is charged is their sum.
type Pair struct {
	Confirmed     int64 `json:"confirmed"`
	UnresolvedMax int64 `json:"unresolved_max"`
}

func (p Pair) Total() int64 { return p.Confirmed + p.UnresolvedMax }

// Spend is the wire's spend object (design/AGENT-OPERATIONS.md section 4), less engine_ms and wall_s, which the
// executor adds.
type Spend struct {
	Valuation string `json:"valuation"`
	Certainty string `json:"certainty"`
	Charge    Pair   `json:"charge"`
	Money     Pair   `json:"money_micro_usd"`
	Tokens    struct {
		Input      Pair `json:"input"`
		CacheRead  Pair `json:"cache_read"`
		CacheWrite Pair `json:"cache_write"`
		Output     Pair `json:"output"`
	} `json:"tokens"`
}

// Report is the attempt's spend. It refuses while any call is reserved or sent; it never waits for an unresolved
// call to become exact (that call is reported at its maximum, and the certainty is bounded).
func (l *Ledger) Report(ctx context.Context, attempt string) (Spend, error) {
	var s Spend
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	a, err := loadAttempt(ctx, tx, attempt)
	if err != nil {
		return s, err
	}
	s.Valuation = a.val.Digest
	var inflight, unresolved int64
	err = tx.QueryRowContext(ctx, `SELECT
	  COALESCE(SUM(state IN ('reserved', 'sent')), 0), COALESCE(SUM(state = 'unresolved'), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN charge END), 0),
	  COALESCE(SUM(CASE WHEN state = 'unresolved' THEN max_charge END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN money END), 0),
	  COALESCE(SUM(CASE WHEN state = 'unresolved' THEN max_money END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN input END), 0),
	  COALESCE(SUM(CASE WHEN state = 'unresolved' THEN max_in END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN cache_read END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN cache_write END), 0),
	  COALESCE(SUM(CASE WHEN state = 'settled' THEN output END), 0),
	  COALESCE(SUM(CASE WHEN state = 'unresolved' THEN max_out END), 0)
	  FROM calls WHERE attempt = ?`, attempt).Scan(&inflight, &unresolved,
		&s.Charge.Confirmed, &s.Charge.UnresolvedMax, &s.Money.Confirmed, &s.Money.UnresolvedMax,
		&s.Tokens.Input.Confirmed, &s.Tokens.Input.UnresolvedMax, &s.Tokens.CacheRead.Confirmed,
		&s.Tokens.CacheWrite.Confirmed, &s.Tokens.Output.Confirmed, &s.Tokens.Output.UnresolvedMax)
	if err != nil {
		return s, err
	}
	if inflight > 0 {
		return s, ErrInFlight
	}
	s.Certainty = "exact"
	if unresolved > 0 {
		s.Certainty = "bounded"
	}
	return s, nil
}
