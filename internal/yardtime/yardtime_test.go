package yardtime

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"hegel.dev/go/hegel"
	_ "modernc.org/sqlite"
)

// world: a wall clock the test steps (forward or back), a monotonic clock per process lifetime, restarts.
type world struct {
	path     string
	db       *sql.DB
	c        *Clock
	wall     time.Time
	mono     time.Duration
	issued   int64 // the highest Yard-Time handed out, across restarts
	restarts int
}

func (w *world) openClock(t hegel.TestCase) {
	db, err := sql.Open("sqlite", "file:"+w.path+"?_pragma=synchronous(FULL)")
	if err != nil {
		t.Errorf("open: %v", err)
	}
	w.db = db
	w.mono = 0
	c, err := open(db, func() time.Time { return w.wall }, func() time.Duration { return w.mono })
	if err != nil {
		t.Errorf("clock: %v", err)
	}
	w.c = c
}

func (w *world) RuleElapse(t hegel.TestCase) {
	d := time.Duration(hegel.Draw(t, hegel.Integers(0, 30000))) * time.Millisecond
	w.mono += d
	w.wall = w.wall.Add(d)
}

// the wall clock steps on its own (NTP, a bad RTC): backwards or forwards
func (w *world) RuleWallStep(t hegel.TestCase) {
	w.wall = w.wall.Add(time.Duration(hegel.Draw(t, hegel.Integers(-120000, 120000))) * time.Millisecond)
}

func (w *world) RuleNow(t hegel.TestCase) {
	n := w.c.Now()
	if n < w.issued {
		t.Errorf("Yard-Time went back: %d after %d (restarts %d)", n, w.issued, w.restarts)
	}
	var ceiling int64
	if err := w.db.QueryRow(`SELECT ceiling_ms FROM yard_clock`).Scan(&ceiling); err != nil {
		t.Errorf("read ceiling: %v", err)
	}
	if n > ceiling {
		t.Errorf("handed out %d past the persisted ceiling %d", n, ceiling)
	}
	w.issued = max(w.issued, n)
}

// the process restarts (possibly after downtime): the store survives, the monotonic clock does not
func (w *world) RuleRestart(t hegel.TestCase) {
	t.Assume(w.restarts < 4)
	w.restarts++
	w.db.Close()
	w.wall = w.wall.Add(time.Duration(hegel.Draw(t, hegel.Integers(0, 600000))) * time.Millisecond)
	w.openClock(t)
}

func TestYardTimeNeverGoesBack(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		w := &world{path: filepath.Join(t.TempDir(), "clock.db"), wall: time.Unix(1_800_000_000, 0)}
		w.openClock(ht)
		defer func() { w.db.Close() }()
		hegel.RunStateful(ht, w)
	})
}

// Downtime counts when the wall clock moved forward: a deadline that passed while yard-ctl was down has passed.
func TestDowntimeCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.db")
	wall := time.Unix(1_800_000_000, 0)
	var mono time.Duration
	db, _ := sql.Open("sqlite", "file:"+path)
	c, err := open(db, func() time.Time { return wall }, func() time.Duration { return mono })
	if err != nil {
		t.Fatal(err)
	}
	mono, wall = 5*time.Second, wall.Add(5*time.Second)
	before := c.Now()
	db.Close()
	wall = wall.Add(time.Hour) // down for an hour
	db, _ = sql.Open("sqlite", "file:"+path)
	defer db.Close()
	c, err = open(db, func() time.Time { return wall }, func() time.Duration { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if after := c.Now(); after < before+time.Hour.Milliseconds()-Ahead.Milliseconds() {
		t.Fatalf("an hour down advanced Yard-Time only %d -> %d", before, after)
	}
}
