package lifecycle

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite (builds for GOOS=freebsd without cgo)
)

// Store keeps the durable half of Ctl in SQLite: the sessions rows, the op
// rows, and the incarnation and id counters. It lives on the encrypted
// dataset (zroot/yard/data), beside the hash-chained mint log but separate
// from it.
type Store struct {
	db   *sql.DB
	lock *os.File // OpenOwned's flock, released by Close
}

// ErrConflict: a row changed under a compare-and-swap commit.
var ErrConflict = errors.New("lifecycle: row changed concurrently")

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, class TEXT NOT NULL, state TEXT NOT NULL, kind TEXT NOT NULL,
  gen INTEGER NOT NULL, phase TEXT NOT NULL, inst INTEGER NOT NULL, ckpt INTEGER NOT NULL,
  op INTEGER NOT NULL, token INTEGER NOT NULL, cred_epoch INTEGER NOT NULL,
  decided_at INTEGER NOT NULL, decided_seq INTEGER NOT NULL, quiesced_at INTEGER NOT NULL,
  suspended_at INTEGER NOT NULL, resumes INTEGER NOT NULL, inbox INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ops (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, sess TEXT NOT NULL, gen INTEGER NOT NULL,
  arg INTEGER NOT NULL, st TEXT NOT NULL, sent_at INTEGER NOT NULL, attempts INTEGER NOT NULL,
  inc INTEGER NOT NULL, bytes INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ops_open ON ops (st) WHERE st IN ('Pending', 'Unknown', 'NotDone');
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
INSERT OR IGNORE INTO meta (k, v) VALUES ('inc', 0), ('next_op', 1), ('next_token', 1);
`

// OpenStore opens (creating if needed) the database at path. Each handle
// is independent; several processes or handles may share one file.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("lifecycle: schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	err := s.db.Close()
	if s.lock != nil {
		s.lock.Close() // releases the flock
		s.lock = nil
	}
	return err
}

const rowCols = `id, class, state, kind, gen, phase, inst, ckpt, op, token, cred_epoch, decided_at,
  decided_seq, quiesced_at, suspended_at, resumes, inbox, consumed_at`

func rowArgs(r Row) []any {
	return []any{r.ID, r.Class, string(r.State), r.Kind, r.Gen, string(r.Phase), r.Inst, r.Ckpt, r.Op,
		r.Token, r.CredEpoch, r.DecidedAt, r.DecidedSeq, r.QuiescedAt, r.SuspendedAt, r.Resumes, r.Inbox, r.ConsumedAt}
}

func scanRow(sc interface{ Scan(...any) error }) (Row, error) {
	var r Row
	var st, ph string
	err := sc.Scan(&r.ID, &r.Class, &st, &r.Kind, &r.Gen, &ph, &r.Inst, &r.Ckpt, &r.Op, &r.Token, &r.CredEpoch,
		&r.DecidedAt, &r.DecidedSeq, &r.QuiescedAt, &r.SuspendedAt, &r.Resumes, &r.Inbox, &r.ConsumedAt)
	r.State, r.Phase = State(st), Phase(ph)
	return r, err
}

const opCols = `id, kind, sess, gen, arg, st, sent_at, attempts, inc, bytes`

func opArgs(o Op) []any {
	return []any{o.ID, string(o.Kind), o.Sess, o.Gen, o.Arg, string(o.St), o.SentAt, o.Attempts, o.Inc, o.Bytes}
}

// Durable is what survives a crash.
type Durable struct {
	Rows      map[string]Row
	Ops       map[int64]Op
	Inc       int64
	NextOp    int64
	NextToken int64
}

// Load reads every row and op and the counters.
func (s *Store) Load() (Durable, error) {
	d := Durable{Rows: map[string]Row{}, Ops: map[int64]Op{}}
	rows, err := s.db.Query(`SELECT ` + rowCols + ` FROM sessions`)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return d, err
		}
		d.Rows[r.ID] = r
	}
	rows.Close()
	ops, err := s.db.Query(`SELECT ` + opCols + ` FROM ops`)
	if err != nil {
		return d, err
	}
	for ops.Next() {
		var o Op
		var k, st string
		if err := ops.Scan(&o.ID, &k, &o.Sess, &o.Gen, &o.Arg, &st, &o.SentAt, &o.Attempts, &o.Inc, &o.Bytes); err != nil {
			ops.Close()
			return d, err
		}
		o.Kind, o.St = OpKind(k), OpSt(st)
		d.Ops[o.ID] = o
	}
	ops.Close()
	for k, p := range map[string]*int64{"inc": &d.Inc, "next_op": &d.NextOp, "next_token": &d.NextToken} {
		if err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(p); err != nil {
			return d, err
		}
	}
	return d, rows.Err()
}

// Restore loads the durable state into a fresh Ctl (yard-ctl start): the
// incarnation is the stored one; call CtlRestart (then persist) to begin a
// new incarnation.
func (s *Store) Restore(cfg Config) (*Ctl, error) {
	d, err := s.Load()
	if err != nil {
		return nil, err
	}
	c := NewCtl(cfg)
	c.Up = false
	c.Rows, c.Ops, c.Inc, c.NextOp, c.NextToken = d.Rows, d.Ops, d.Inc, d.NextOp, d.NextToken
	for id := range c.Rows {
		c.Drivers[id] = map[string]bool{}
		c.Obs[id] = freshObs()
	}
	return c, nil
}

// lifecycle columns a compare-and-swap commit checks
func casWhere(prev Row) (string, []any) {
	return `id = ? AND state = ? AND phase = ? AND gen = ? AND token = ? AND op = ?`,
		[]any{prev.ID, string(prev.State), string(prev.Phase), prev.Gen, prev.Token, prev.Op}
}

// Commit writes next's durable state where it differs from prev, in one
// transaction. A changed row is written only if the stored row still has
// prev's lifecycle columns (else ErrConflict and nothing is written); new
// rows are inserted.
func (s *Store) Commit(prev, next *Ctl) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, r := range next.Rows {
		p, had := prev.Rows[id]
		switch {
		case !had:
			if _, err := tx.Exec(`INSERT INTO sessions (`+rowCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, rowArgs(r)...); err != nil {
				return err
			}
		case p != r:
			if err := casUpdate(tx, p, r); err != nil {
				return err
			}
		}
	}
	for id, o := range next.Ops {
		if p, had := prev.Ops[id]; had && p == o {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO ops (`+opCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, opArgs(o)...); err != nil {
			return err
		}
	}
	if err := writeMeta(tx, next); err != nil {
		return err
	}
	return tx.Commit()
}

func casUpdate(tx *sql.Tx, prev, next Row) error {
	cols := strings.Split(strings.ReplaceAll(rowCols, "\n", ""), ",")
	set := make([]string, 0, len(cols)-1)
	for _, c := range cols[1:] {
		set = append(set, strings.TrimSpace(c)+" = ?")
	}
	where, wargs := casWhere(prev)
	args := append(rowArgs(next)[1:], wargs...)
	res, err := tx.Exec(`UPDATE sessions SET `+strings.Join(set, ", ")+` WHERE `+where, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("session %s: %w", prev.ID, ErrConflict)
	}
	return nil
}

func writeMeta(tx *sql.Tx, c *Ctl) error {
	for k, v := range map[string]int64{"inc": c.Inc, "next_op": c.NextOp, "next_token": c.NextToken} {
		// counters only move forward, whoever commits
		if _, err := tx.Exec(`UPDATE meta SET v = max(v, ?) WHERE k = ?`, v, k); err != nil {
			return err
		}
	}
	return nil
}

// ConsumeToken is the durable half of Quint ResumeConsume: one conditional
// UPDATE that only a single caller can win, plus the restore op row in the
// same transaction. next is the row Ctl.ResumeConsume produced; op the
// restore op. It returns false (and writes nothing) if the row is no longer
// suspended with that token: Quint ResumeReject.
func (s *Store) ConsumeToken(sess string, token int64, next Row, op Op) (bool, error) {
	if token == 0 {
		return false, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE sessions SET state = 'Resuming', phase = 'PRestore', token = 0, op = ?, consumed_at = ?
		WHERE id = ? AND state = 'Suspended' AND token = ?`, next.Op, next.ConsumedAt, sess, token)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if _, err := tx.Exec(`INSERT INTO ops (`+opCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, opArgs(op)...); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE meta SET v = max(v, ?) WHERE k = 'next_op'`, op.ID+1); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Expire is the durable half of Quint Expire: a conditional UPDATE that
// races ConsumeToken (exactly one wins) and never expires a row holding
// messages, with the owed delete op in the same transaction.
func (s *Store) Expire(sess string, token int64, next Row, del *Op) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE sessions SET state = 'Expired', token = 0, ckpt = 0
		WHERE id = ? AND state = 'Suspended' AND token = ? AND inbox = 0`, sess, token)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if del != nil {
		if _, err := tx.Exec(`INSERT INTO ops (`+opCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`, opArgs(*del)...); err != nil {
			return false, err
		}
		if _, err := tx.Exec(`UPDATE meta SET v = max(v, ?) WHERE k = 'next_op'`, del.ID+1); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// durableEqual reports whether two controllers agree on the durable state.
func durableEqual(a, b *Ctl) bool {
	return maps.Equal(a.Rows, b.Rows) && maps.Equal(a.Ops, b.Ops) && a.Inc == b.Inc &&
		a.NextOp == b.NextOp && a.NextToken == b.NextToken
}
