package sts

import (
	"sync"
	"time"
)

// Limiter is a per-uid token bucket.
type Limiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	now   func() time.Time
	b     map[uint32]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter returns a limiter allowing rate/s with the given burst.
func NewLimiter(rate float64, burst int, now func() time.Time) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), now: now, b: map[uint32]*bucket{}}
}

// Allow consumes one token for uid if available.
func (l *Limiter) Allow(uid uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	bk, ok := l.b[uid]
	if !ok {
		bk = &bucket{tokens: l.burst, last: t}
		l.b[uid] = bk
	}
	if el := t.Sub(bk.last).Seconds(); el > 0 {
		bk.tokens += el * l.rate
		if bk.tokens > l.burst {
			bk.tokens = l.burst
		}
		bk.last = t
	}
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}
