package keysvc

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"

	_ "modernc.org/sqlite" // pure Go (builds for GOOS=freebsd without cgo)
)

// DefaultDB is the key database: SR1's key dataset convention (user
// decision 2026-10-07: the database holding wrapped keys lives on its own
// dataset, zroot/yard/data/keys at /yard/data/keys, never snapshotted and
// never in a backup, so deleting a wrapped key row is a crypto-shred once
// the WAL is truncated). The workspace keys (wskey table wskeys) and the
// spill keys (tables spill_*) share it and the KEK.
const DefaultDB = "/yard/data/keys/wskeys.db"

// Store keeps the durable half of Ctl and the wrapped spill keys. Creating
// a key, wrapping it and inserting it with its op row is one transaction
// (the model's SuspendBegin); deleting the wrapped bytes is the shred's
// first step (secure_delete on, the WAL checkpointed and truncated after).
type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS spill_keys (
  id INTEGER PRIMARY KEY, sess TEXT NOT NULL, ver INTEGER NOT NULL, ckpt INTEGER NOT NULL, entry INTEGER NOT NULL,
  wrapped BLOB, shredding INTEGER NOT NULL, shredded INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS spill_sess (
  sess TEXT PRIMARY KEY, st TEXT NOT NULL, phase TEXT NOT NULL, epoch INTEGER NOT NULL, op INTEGER NOT NULL,
  spill INTEGER NOT NULL, resumes INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS spill_ops (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, subj TEXT NOT NULL, key INTEGER NOT NULL, ver INTEGER NOT NULL,
  tep INTEGER NOT NULL, oid INTEGER NOT NULL, use TEXT NOT NULL, st TEXT NOT NULL, attempts INTEGER NOT NULL, inc INTEGER NOT NULL,
  sent_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS spill_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
INSERT OR IGNORE INTO spill_meta (k, v) VALUES ('inc', 0), ('next_op', 1), ('next_key', 1),
  ('nonce', random() & 9223372036854775807);
`

// OpenStore opens (creating) the spill tables in the key database at path.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)" +
		"&_pragma=secure_delete(ON)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("keysvc: schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Commit writes what changed from prev to next in one transaction. wrap
// returns the wrapped bytes of a key created in this step.
func (s *Store) Commit(prev, next *Ctl, wrap func(id int64) []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	shred := false
	for id, k := range next.Keys {
		p, had := prev.Keys[id]
		switch {
		case !had:
			w := wrap(id)
			if k.Wrapped && w == nil {
				return fmt.Errorf("keysvc: no wrapped bytes for new key %d", id)
			}
			if !k.Wrapped {
				w = nil
			}
			if _, err := tx.Exec(`INSERT INTO spill_keys (id, sess, ver, ckpt, entry, wrapped, shredding, shredded)
				VALUES (?,?,?,?,?,?,?,?)`, id, k.Subj, k.Ver, k.Ckpt, int64(k.Entry), w, b2i(k.Shredding), b2i(k.Shredded)); err != nil {
				return err
			}
		case p != k:
			if p.Wrapped && !k.Wrapped {
				shred = true
				if _, err := tx.Exec(`UPDATE spill_keys SET wrapped = NULL WHERE id = ?`, id); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(`UPDATE spill_keys SET shredding = ?, shredded = ? WHERE id = ?`,
				b2i(k.Shredding), b2i(k.Shredded), id); err != nil {
				return err
			}
		}
	}
	for id, r := range next.Sess {
		if p, had := prev.Sess[id]; had && p == r {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO spill_sess (sess, st, phase, epoch, op, spill, resumes) VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(sess) DO UPDATE SET st=excluded.st, phase=excluded.phase, epoch=excluded.epoch, op=excluded.op,
			spill=excluded.spill, resumes=excluded.resumes`, id, r.St, r.Phase, r.Epoch, r.Op, r.Spill, r.Resumes); err != nil {
			return err
		}
	}
	for id, o := range next.Ops {
		if p, had := prev.Ops[id]; had && p == o {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO spill_ops (id, kind, subj, key, ver, tep, oid, use, st, attempts, inc, sent_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET st=excluded.st, attempts=excluded.attempts,
			inc=excluded.inc, sent_at=excluded.sent_at, tep=excluded.tep, oid=excluded.oid`,
			id, o.Kind, o.Subj, o.Key, o.Ver, o.Tep, o.Oid, o.Use, o.St, o.Attempts, o.Inc, o.SentAt); err != nil {
			return err
		}
	}
	for k, v := range map[string]int64{"inc": next.Inc, "next_op": next.NextOp, "next_key": next.NextKey} {
		if _, err := tx.Exec(`UPDATE spill_meta SET v = ? WHERE k = ?`, v, k); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if shred {
		_, err = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return err
}

// Load reads the durable controller state (Up, the clock not durable).
func (s *Store) Load(cfg Config) (*Ctl, error) {
	c := NewCtl(cfg)
	rows, err := s.db.Query(`SELECT id, sess, ver, ckpt, entry, wrapped IS NOT NULL, shredding, shredded FROM spill_keys`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k Key
		var e int64
		if err := rows.Scan(&k.ID, &k.Subj, &k.Ver, &k.Ckpt, &e, &k.Wrapped, &k.Shredding, &k.Shredded); err != nil {
			rows.Close()
			return nil, err
		}
		k.Entry = uint64(e)
		c.Keys[k.ID] = k
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT sess, st, phase, epoch, op, spill, resumes FROM spill_sess`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var r Sess
		if err := rows.Scan(&id, &r.St, &r.Phase, &r.Epoch, &r.Op, &r.Spill, &r.Resumes); err != nil {
			rows.Close()
			return nil, err
		}
		c.Sess[id] = r
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT id, kind, subj, key, ver, tep, oid, use, st, attempts, inc, sent_at FROM spill_ops`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o Op
		if err := rows.Scan(&o.ID, &o.Kind, &o.Subj, &o.Key, &o.Ver, &o.Tep, &o.Oid, &o.Use, &o.St, &o.Attempts, &o.Inc, &o.SentAt); err != nil {
			rows.Close()
			return nil, err
		}
		c.Ops[o.ID] = o
	}
	rows.Close()
	m := map[string]*int64{"inc": &c.Inc, "next_op": &c.NextOp, "next_key": &c.NextKey}
	for k, p := range m {
		if err := s.db.QueryRow(`SELECT v FROM spill_meta WHERE k = ?`, k).Scan(p); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Nonce is the database's persisted random 63-bit id. Combined with the
// monotonically increasing op row id, it makes reuse across recreated
// databases improbable; a detected collision is a terminal identity conflict.
func (s *Store) Nonce() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT v FROM spill_meta WHERE k = 'nonce'`).Scan(&n)
	return n, err
}

// ErrShredded: the key's wrapped bytes are gone.
var ErrShredded = errors.New("keysvc: spill key shredded")

// Wrapped returns key id's wrapped bytes.
func (s *Store) Wrapped(id int64) ([]byte, error) {
	var w []byte
	err := s.db.QueryRow(`SELECT wrapped FROM spill_keys WHERE id = ?`, id).Scan(&w)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && w == nil) {
		return nil, ErrShredded
	}
	return w, err
}

// equalDurable reports whether two controllers have the same durable state.
func equalDurable(a, b *Ctl) bool {
	return a.Inc == b.Inc && a.NextOp == b.NextOp && a.NextKey == b.NextKey && maps.Equal(a.Keys, b.Keys) &&
		maps.Equal(a.Sess, b.Sess) && maps.Equal(a.Ops, b.Ops)
}
