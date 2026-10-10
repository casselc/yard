package broker

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// quotas are per-principal token buckets (requests, bytes) for proxied
// traffic and daily ceilings for key-injected cloud egress, per principal
// and node-wide. Requests are charged at admission; bytes are taken in
// chunks of at most meterChunk BEFORE they are read, under the lock, so a
// stream stops when its budget is gone and every byte that flowed is paid
// for, whatever happens to the request afterwards (panic, cancellation,
// unknown outcome). Input and output are accounted separately.
//
// Daily counters are in memory: a broker restart resets them (stated in
// spec/broker B12). The day advances only forward: a clock stepped back
// does not reopen a spent day.
type quotas struct {
	mu               sync.Mutex
	lim              Limits
	now              func() time.Time
	m                map[string]*principalQuota
	day              string
	globalCloudReq   int64
	globalCloudBytes int64
}

type principalQuota struct {
	reqTokens  float64
	byteTokens float64
	last       time.Time
	day        string
	cloudReq   int64
	cloudBytes int64
	bytesIn    int64 // totals, for audit/metrics
	bytesOut   int64
}

const meterChunk = 64 << 10

// errQuotaBytes: a stream's byte budget ran out mid-transfer.
var errQuotaBytes = errors.New("byte quota exhausted")

func newQuotas(l Limits, now func() time.Time) *quotas {
	return &quotas{lim: l, now: now, m: map[string]*principalQuota{}}
}

func nextUTCMidnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}

// roll advances the day (caller holds mu); a day key never goes back.
func (q *quotas) roll(now time.Time) {
	day := now.UTC().Format("2006-01-02")
	if day > q.day { // MUTANT:dayRollsBack
		q.day, q.globalCloudReq, q.globalCloudBytes = day, 0, 0
	}
}

func (q *quotas) principal(p string, now time.Time) *principalQuota {
	pq := q.m[p]
	if pq == nil {
		if len(q.m) > 4096 {
			for k, v := range q.m {
				if now.Sub(v.last) > 24*time.Hour {
					delete(q.m, k)
				}
			}
		}
		pq = &principalQuota{reqTokens: float64(q.lim.RequestsPerMin), byteTokens: float64(q.lim.BytesPerMin), last: now}
		q.m[p] = pq
	}
	if el := now.Sub(pq.last).Minutes(); el > 0 {
		pq.reqTokens = min(float64(q.lim.RequestsPerMin), pq.reqTokens+el*float64(q.lim.RequestsPerMin))
		pq.byteTokens = min(float64(q.lim.BytesPerMin), pq.byteTokens+el*float64(q.lim.BytesPerMin))
		pq.last = now
	}
	if pq.day < q.day {
		pq.day, pq.cloudReq, pq.cloudBytes = q.day, 0, 0
	}
	return pq
}

// admit charges one request and reports whether it may proceed, and if not
// why and when to retry. A request is admitted only while its principal
// still has byte budget.
func (q *quotas) admit(principal string, cloud bool) (bool, time.Duration, string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.roll(now)
	pq := q.principal(principal, now)
	perTok := time.Duration(float64(time.Minute) / float64(q.lim.RequestsPerMin))
	switch {
	case pq.reqTokens < 1: // MUTANT:quotaUnchecked
		return false, time.Duration((1 - pq.reqTokens) * float64(perTok)), "rate_requests"
	case pq.byteTokens < 1:
		return false, time.Minute / 4, "rate_bytes"
	case cloud && (pq.cloudReq >= q.lim.CloudDailyRequests || pq.cloudBytes >= q.lim.CloudDailyBytes):
		return false, nextUTCMidnight(now).Sub(now), "daily_cloud"
	case cloud && (q.globalCloudReq >= q.lim.CloudDailyRequestsGlobal || q.globalCloudBytes >= q.lim.CloudDailyBytesGlobal):
		return false, nextUTCMidnight(now).Sub(now), "daily_cloud_global"
	}
	pq.reqTokens--
	if cloud {
		pq.cloudReq++
		q.globalCloudReq++
	}
	return true, 0, ""
}

// take reserves up to want bytes for one transfer step and returns how
// many may move (0: the budget is gone).
func (q *quotas) take(principal string, cloud, out bool, want int) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.roll(now)
	pq := q.principal(principal, now)
	n := int64(want)
	if b := int64(pq.byteTokens); b < n {
		n = b
	}
	if cloud {
		if r := q.lim.CloudDailyBytes - pq.cloudBytes; r < n {
			n = r
		}
		if r := q.lim.CloudDailyBytesGlobal - q.globalCloudBytes; r < n {
			n = r
		}
	}
	if n <= 0 {
		return 0
	}
	q.charge(pq, cloud, out, n)
	return int(n)
}

// give returns the unused part of a reservation.
func (q *quotas) give(principal string, cloud, out bool, n int) {
	if n <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if pq := q.m[principal]; pq != nil {
		q.charge(pq, cloud, out, -int64(n))
	}
}

func (q *quotas) charge(pq *principalQuota, cloud, out bool, n int64) {
	pq.byteTokens -= float64(n)
	if out {
		pq.bytesOut += n
	} else {
		pq.bytesIn += n
	}
	if cloud {
		pq.cloudBytes += n
		q.globalCloudBytes += n
	}
}

// meteredReader moves at most meterChunk per Read, and only bytes the
// quota granted first; a Read with no budget left fails with errQuotaBytes.
// Reservations are settled inside Read, so nothing is outstanding when a
// handler returns or panics.
type meteredReader struct {
	r         io.Reader
	q         *quotas
	principal string
	cloud     bool
	out       bool
	stopped   *atomic.Bool // set when the budget ran out
}

func (m *meteredReader) Read(p []byte) (int, error) {
	if len(p) > meterChunk {
		p = p[:meterChunk]
	}
	if len(p) == 0 {
		return m.r.Read(p)
	}
	k := m.q.take(m.principal, m.cloud, m.out, len(p)) // MUTANT:meterUnchecked
	if k == 0 {
		if m.stopped != nil {
			m.stopped.Store(true)
		}
		return 0, errQuotaBytes
	}
	n, err := m.r.Read(p[:k])
	m.q.give(m.principal, m.cloud, m.out, k-n)
	return n, err
}
