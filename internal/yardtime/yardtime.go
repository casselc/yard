// Package yardtime is Yard-Time, the deadline clock (design/AGENT-OPERATIONS.md section 3; spec/agentop/clock.qnt).
//
// yard-ctl keeps its incarnation across a restart, so its deadlines cannot be in a process clock that resets. Yard-
// Time is a logical clock in milliseconds that never repeats and never goes backwards across restarts:
//
//   - a ceiling is persisted, durably, ahead of every time handed out (by Ahead), and advanced before Yard-Time would
//     pass it;
//   - after a restart Yard-Time resumes at the persisted ceiling, plus the wall-clock time since the ceiling was
//     written when that is positive (never minus: a clock stepping back only pauses Yard-Time).
//
// So a record pruned once Yard-Time passed its deadline can never see an earlier Yard-Time again, and a late copy of
// its submit is refused as late.
package yardtime

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Ahead is how far beyond the times handed out the ceiling is persisted. A restart resumes at the ceiling, so it
// can move Yard-Time forward by up to Ahead beyond real time: that shortens deadlines and time limits by as much (an
// executor test found a 2 s task limit spent by one restart with 10 s), so it is kept small, at the cost of a durable
// write every Ahead/2 while Yard-Time is read.
const Ahead = time.Second

// Clock is Yard-Time over a store. Now is safe for concurrent use.
type Clock struct {
	mu      sync.Mutex
	db      *sql.DB
	base    int64                // Yard-Time at start
	since   func() time.Duration // monotonic time since start
	ceiling int64                // the persisted ceiling
	wall    func() time.Time
}

const schema = `CREATE TABLE IF NOT EXISTS yard_clock (id INTEGER PRIMARY KEY CHECK (id = 1),
  ceiling_ms INTEGER NOT NULL, written_unix_ms INTEGER NOT NULL)`

// Open resumes Yard-Time from db (creating the clock at 0 the first time).
func Open(db *sql.DB) (*Clock, error) {
	start := time.Now()
	return open(db, time.Now, func() time.Duration { return time.Since(start) })
}

func open(db *sql.DB, wall func() time.Time, since func() time.Duration) (*Clock, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	c := &Clock{db: db, wall: wall, since: since}
	var ceiling, written int64
	err := db.QueryRow(`SELECT ceiling_ms, written_unix_ms FROM yard_clock WHERE id = 1`).Scan(&ceiling, &written)
	switch {
	case err == sql.ErrNoRows:
		c.base = 0
	case err != nil:
		return nil, err
	default:
		c.base = ceiling
		if since := wall().UnixMilli() - written; since > 0 {
			c.base += since
		}
	}
	c.ceiling = c.base
	if err := c.persist(c.base + Ahead.Milliseconds()); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Clock) persist(ceiling int64) error {
	_, err := c.db.Exec(`INSERT INTO yard_clock(id, ceiling_ms, written_unix_ms) VALUES (1, ?, ?)
	  ON CONFLICT(id) DO UPDATE SET ceiling_ms = excluded.ceiling_ms, written_unix_ms = excluded.written_unix_ms`,
		ceiling, c.wall().UnixMilli())
	if err == nil {
		c.ceiling = ceiling
	}
	return err
}

// Now is the current Yard-Time. It never returns a time past the persisted ceiling: it advances the ceiling first,
// and if that write fails it returns the ceiling itself (time pauses rather than run ahead of what is durable).
func (c *Clock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.base + c.since().Milliseconds()
	if t+Ahead.Milliseconds()/2 > c.ceiling {
		if err := c.persist(t + Ahead.Milliseconds()); err != nil && t > c.ceiling {
			return c.ceiling
		}
	}
	return t
}

func (c *Clock) String() string { return fmt.Sprintf("yard-time %d (ceiling %d)", c.Now(), c.ceiling) }
