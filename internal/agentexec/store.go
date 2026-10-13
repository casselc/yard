// Package agentexec is yard-ctl's agent executor (design/AGENT-OPERATIONS.md sections 3 to 8): it serves the
// operation envelope (cordis RFC 0007) for api "agent", keeps each attempt's durable stage and drives it through
// yard-node and the broker route, and keeps artifacts under leases and an append-only corrections log.
package agentexec

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

// Key identifies an attempt: owner (the principal), operation id, attempt.
type Key struct {
	Owner, Op string
	Attempt   uint64
}

func (k Key) String() string { return fmt.Sprintf("%s/%s/%d", k.Owner, k.Op, k.Attempt) }

// Statuses of a record.
const (
	StRunning   = "running"
	StDone      = "done"
	StReleased  = "released"
	StCancelled = "cancelled_before_accept" // a tombstone: never accepted, and no copy will be
)

// Stages of a running attempt (section 5).
const (
	StageAccepted   = "accepted"
	StageAllocating = "allocating"
	StageStarted    = "started"
	StageCapturing  = "capturing"
	StageEnding     = "ending"
	StageEnded      = "ended"
)

// Rec is an attempt's durable record.
type Rec struct {
	Key
	Digest   string
	NotAfter int64
	Body     []byte // the submit body, exact
	Status   string
	Stage    string
	Alloc    string // the current allocation (never reused)
	Reallocs int
	Cancel   bool
	Outcome  json.RawMessage // set at StageEnding (the outcome) and kept
	Fence    string          // an allocation owed a tombstone at yard-node (F4), "" if none
	Created  int64           // Yard-Time
	Ended    int64
	Acked    bool
}

type Store struct {
	db  *sql.DB
	Inc string // the incarnation: this store's epoch
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK (id = 1), incarnation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ops (
  owner TEXT NOT NULL, op TEXT NOT NULL, attempt INTEGER NOT NULL,
  digest TEXT NOT NULL, not_after INTEGER NOT NULL, body BLOB NOT NULL,
  status TEXT NOT NULL, stage TEXT NOT NULL DEFAULT '', alloc TEXT NOT NULL DEFAULT '', reallocs INTEGER NOT NULL DEFAULT 0,
  cancel INTEGER NOT NULL DEFAULT 0, outcome TEXT NOT NULL DEFAULT '', fence TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL, ended INTEGER NOT NULL DEFAULT 0, acked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner, op, attempt));
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, path TEXT NOT NULL,
  owner TEXT NOT NULL, op TEXT NOT NULL, attempt INTEGER NOT NULL,
  floor INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS leases (
  artifact TEXT NOT NULL REFERENCES artifacts(id), holder TEXT NOT NULL, until INTEGER NOT NULL,
  PRIMARY KEY (artifact, holder));
CREATE TABLE IF NOT EXISTS corrections (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, op TEXT NOT NULL, attempt INTEGER NOT NULL,
  kind TEXT NOT NULL, evidence TEXT NOT NULL, at INTEGER NOT NULL);`

// OpenStore opens (creating) the executor's store; the incarnation is minted once, with the store.
func OpenStore(path string) (*Store, error) {
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
	s := &Store{db: db}
	err = db.QueryRow(`SELECT incarnation FROM meta WHERE id = 1`).Scan(&s.Inc)
	if errors.Is(err, sql.ErrNoRows) {
		b := make([]byte, 16)
		rand.Read(b)
		s.Inc = hex.EncodeToString(b)
		_, err = db.Exec(`INSERT INTO meta(id, incarnation) VALUES (1, ?)`, s.Inc)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) Close() error { return s.db.Close() }

const recCols = `owner, op, attempt, digest, not_after, body, status, stage, alloc, reallocs, cancel, outcome, fence,
  created, ended, acked`

func scanRec(row interface{ Scan(...any) error }) (Rec, error) {
	var r Rec
	var cancel, acked int
	var outcome string
	err := row.Scan(&r.Owner, &r.Op, &r.Attempt, &r.Digest, &r.NotAfter, &r.Body, &r.Status, &r.Stage, &r.Alloc,
		&r.Reallocs, &cancel, &outcome, &r.Fence, &r.Created, &r.Ended, &acked)
	r.Cancel, r.Acked = cancel != 0, acked != 0
	if outcome != "" {
		r.Outcome = json.RawMessage(outcome)
	}
	return r, err
}

// Get returns the attempt's record, or sql.ErrNoRows.
func (s *Store) Get(ctx context.Context, k Key) (Rec, error) {
	return scanRec(s.db.QueryRowContext(ctx, `SELECT `+recCols+` FROM ops WHERE owner = ? AND op = ? AND attempt = ?`,
		k.Owner, k.Op, k.Attempt))
}

// Running lists the records still running (to resume after a restart).
func (s *Store) Running(ctx context.Context) ([]Rec, error) {
	return s.list(ctx, `SELECT `+recCols+` FROM ops WHERE status = 'running' ORDER BY created`)
}

// Fenced lists records with an allocation owed a tombstone.
func (s *Store) Fenced(ctx context.Context) ([]Rec, error) {
	return s.list(ctx, `SELECT `+recCols+` FROM ops WHERE fence != '' ORDER BY created`)
}

func (s *Store) list(ctx context.Context, q string, args ...any) ([]Rec, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rec
	for rows.Next() {
		r, err := scanRec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Accept inserts a new running record (stage accepted) unless the attempt has one; it returns the record that is
// there afterwards and whether it was inserted now.
func (s *Store) Accept(ctx context.Context, r Rec) (Rec, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Rec{}, false, err
	}
	defer tx.Rollback()
	cur, err := scanRec(tx.QueryRowContext(ctx, `SELECT `+recCols+` FROM ops WHERE owner = ? AND op = ? AND attempt = ?`,
		r.Owner, r.Op, r.Attempt))
	if err == nil {
		return cur, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Rec{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ops(owner, op, attempt, digest, not_after, body, status, stage, created)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.Owner, r.Op, r.Attempt, r.Digest, r.NotAfter, r.Body, r.Status, r.Stage,
		r.Created); err != nil {
		return Rec{}, false, err
	}
	return r, true, tx.Commit()
}

// Update writes the mutable fields of a record.
func (s *Store) Update(ctx context.Context, r Rec) error {
	out := ""
	if r.Outcome != nil {
		out = string(r.Outcome)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE ops SET status = ?, stage = ?, alloc = ?, reallocs = ?, cancel = ?, outcome = ?,
	  fence = ?, ended = ?, acked = ? WHERE owner = ? AND op = ? AND attempt = ?`,
		r.Status, r.Stage, r.Alloc, r.Reallocs, b2i(r.Cancel), out, r.Fence, r.Ended, b2i(r.Acked), r.Owner, r.Op, r.Attempt)
	return err
}

// SetCancel records a cancel request durably.
func (s *Store) SetCancel(ctx context.Context, k Key) error {
	_, err := s.db.ExecContext(ctx, `UPDATE ops SET cancel = 1 WHERE owner = ? AND op = ? AND attempt = ? AND status = 'running'`,
		k.Owner, k.Op, k.Attempt)
	return err
}

// Prune drops released and cancelled records whose deadline has passed in Yard-Time (a late copy is then refused as
// late, and Yard-Time never returns to that deadline).
func (s *Store) Prune(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ops WHERE status IN ('released', 'cancelled_before_accept') AND not_after < ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Correction is an appended piece of later evidence about an attempt (section 4).
type Correction struct {
	Seq      int64           `json:"seq"`
	Owner    string          `json:"owner"`
	Op       string          `json:"operation_id"`
	Attempt  uint64          `json:"attempt"`
	Kind     string          `json:"kind"`
	Evidence json.RawMessage `json:"evidence"`
	At       int64           `json:"at"`
}

func (s *Store) AppendCorrection(ctx context.Context, k Key, kind string, evidence any, at int64) error {
	ev, _ := json.Marshal(evidence)
	_, err := s.db.ExecContext(ctx, `INSERT INTO corrections(owner, op, attempt, kind, evidence, at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.Owner, k.Op, k.Attempt, kind, string(ev), at)
	return err
}

// Corrections lists an owner's corrections after a sequence number.
func (s *Store) Corrections(ctx context.Context, owner string, after int64, limit int) ([]Correction, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, owner, op, attempt, kind, evidence, at FROM corrections
	  WHERE owner = ? AND seq > ? ORDER BY seq LIMIT ?`, owner, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Correction
	for rows.Next() {
		var c Correction
		var ev string
		if err := rows.Scan(&c.Seq, &c.Owner, &c.Op, &c.Attempt, &c.Kind, &ev, &c.At); err != nil {
			return nil, err
		}
		c.Evidence = json.RawMessage(ev)
		out = append(out, c)
	}
	return out, rows.Err()
}
