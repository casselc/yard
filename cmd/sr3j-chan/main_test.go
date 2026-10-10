package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"testing"
	"time"
)

func TestLatSummary(t *testing.T) {
	if l := latSummary(nil); l != (lat{}) {
		t.Fatalf("empty: %+v", l)
	}
	xs := make([]float64, 0, 100)
	for i := 100; i >= 1; i-- { // unsorted input
		xs = append(xs, float64(i))
	}
	l := latSummary(xs)
	if l.N != 100 || l.P50 != 50 || l.P90 != 90 || l.P99 != 99 || l.Max != 100 || math.Abs(l.Mean-50.5) > 1e-9 {
		t.Fatalf("1..100: %+v", l)
	}
	if xs[0] != 100 {
		t.Fatal("latSummary sorted its input in place")
	}
	l = latSummary([]float64{7})
	if l.P50 != 7 || l.P99 != 7 || l.Max != 7 {
		t.Fatalf("one: %+v", l)
	}
	l = latSummary([]float64{1, 2, 3})
	if l.P50 != 2 || l.P90 != 3 { // nearest rank: ceil(0.5*3)=2nd, ceil(0.9*3)=3rd
		t.Fatalf("three: %+v", l)
	}
}

// boundedPipe models one direction of the emulated UART: writes never block and bytes beyond cap unread
// bytes are dropped (bhyve ignoring EAGAIN; uart(4) discarding past its 383-byte rx buffer); reads return
// at most readMax bytes after readDelay (a guest draining the FIFO a few bytes per interrupt).
type boundedPipe struct {
	mu        sync.Mutex
	cond      *sync.Cond
	buf       []byte
	cap       int
	readMax   int
	readDelay time.Duration
	dropped   int
	peak      int
	closed    bool
}

func newBoundedPipe(cap, readMax int, delay time.Duration) *boundedPipe {
	p := &boundedPipe{cap: cap, readMax: readMax, readDelay: delay}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *boundedPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	room := p.cap - len(p.buf)
	k := min(room, len(b))
	p.buf = append(p.buf, b[:k]...)
	p.dropped += len(b) - k
	p.peak = max(p.peak, len(p.buf))
	p.cond.Broadcast()
	return len(b), nil
}

func (p *boundedPipe) Read(b []byte) (int, error) {
	if p.readDelay > 0 {
		time.Sleep(p.readDelay)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(b[:min(len(b), p.readMax)], p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *boundedPipe) close() {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

type end struct{ r, w *boundedPipe }

func (e end) Read(b []byte) (int, error)  { return e.r.Read(b) }
func (e end) Write(b []byte) (int, error) { return e.w.Write(b) }
func (e end) Close() error                { e.r.close(); e.w.close(); return nil }

// uartPair: toGuest holds 383 bytes and is drained slowly; toHost holds 1920 bytes and is drained fast.
func uartPair() (host, guest end, toGuest, toHost *boundedPipe) {
	toGuest = newBoundedPipe(383, 16, 20*time.Microsecond)
	toHost = newBoundedPipe(1920, 1<<20, 0)
	return end{r: toHost, w: toGuest}, end{r: toGuest, w: toHost}, toGuest, toHost
}

func runBulkPair(t *testing.T, hostWin uint64, down, up, chunk int, probe, deadline time.Duration) (map[string]any, *boundedPipe, *boundedPipe) {
	t.Helper()
	h, g, toGuest, toHost := uartPair()
	a := &agent{streams: map[string]*stream{}, token: "t"}
	go a.serve(newConn(g, defAgentWin, 2*time.Second), "uart")
	c := newConn(h, hostWin, 2*time.Second)
	w, err := handshake(c, "b", 1, uint64(time.Now().UnixNano()), hostWin, 2*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	res := bulkRun(c, w, down, up, chunk, probe, deadline)
	m := map[string]any{}
	for i := 0; i+1 < len(res); i += 2 {
		m[res[i].(string)] = res[i+1]
	}
	h.Close()
	return m, toGuest, toHost
}

// With the credit window the bounded pipes never overflow, whatever the chunk size, and every byte arrives.
func TestBulkCreditWindowNoLoss(t *testing.T) {
	for _, chunk := range []int{64, 1024, 65536} {
		m, toGuest, toHost := runBulkPair(t, defClientWin, 96<<10, 96<<10, chunk, 5*time.Millisecond, 20*time.Second)
		if m["ok"] != true {
			t.Fatalf("chunk %d: not ok: %v", chunk, m)
		}
		if got := m["down_bytes"].(int64); got != 96<<10 {
			t.Errorf("chunk %d: down_bytes %d", chunk, got)
		}
		if got := m["up_bytes_acked"].(uint64); got != 96<<10 {
			t.Errorf("chunk %d: up_bytes_acked %d", chunk, got)
		}
		if toGuest.dropped != 0 || toHost.dropped != 0 {
			t.Errorf("chunk %d: dropped toGuest %d toHost %d (peaks %d, %d)", chunk, toGuest.dropped, toHost.dropped, toGuest.peak, toHost.peak)
		}
		if toGuest.peak > defAgentWin+3*(ovh+8) {
			t.Errorf("chunk %d: toGuest peak %d above the agent window + credit slack", chunk, toGuest.peak)
		}
		if m["down_probe_n"].(int) == 0 || m["up_probe_n"].(int) == 0 {
			t.Errorf("chunk %d: no probe RTTs: %v", chunk, m)
		}
		t.Logf("chunk %d: peaks toGuest %d toHost %d; down probe p99 %v ms, up probe p99 %v ms", chunk, toGuest.peak, toHost.peak,
			m["down_probe_p99_ms"], m["up_probe_p99_ms"])
	}
}

// Positive control: without the window (-win 0, the old protocol) the same pipes drop bytes, and the client
// reports the failure (ok=false or a short count) by its deadline instead of hanging.
func TestBulkNoWindowLosesAndReports(t *testing.T) {
	t0 := time.Now()
	m, toGuest, _ := runBulkPair(t, 0, 0, 64<<10, 1024, 0, 3*time.Second)
	if time.Since(t0) > 10*time.Second {
		t.Fatalf("took %v: the deadline did not bound it", time.Since(t0))
	}
	if toGuest.dropped == 0 {
		t.Fatalf("no bytes dropped without the window; the model does not reproduce the loss")
	}
	acked, _ := m["up_bytes_acked"].(uint64)
	if m["ok"] == true && acked == 64<<10 {
		t.Fatalf("loss went unreported: %v", m)
	}
	t.Logf("no window: dropped %d, ok=%v acked=%d err=%v", toGuest.dropped, m["ok"], acked, m["err"])
}

func TestFragmentsReassembleAroundOtherFrames(t *testing.T) {
	h, g, _, _ := uartPair()
	a := &agent{streams: map[string]*stream{}, token: "t"}
	go a.serve(newConn(g, defAgentWin, 2*time.Second), "uart")
	c := newConn(h, defClientWin, 2*time.Second)
	if _, err := handshake(c, "x", 1, 1, defClientWin, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// a 40 KiB exec output comes back in fragments of <= defClientWin/2 and reassembles exactly
	c.send(frame{typ: tExec, seq: 9, payload: []byte("head -c 40000 /dev/zero | tr '\\0' x")})
	for {
		f, err := c.recv()
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == tExecOut {
			if len(f.payload) < 40000 || f.seq != 9 {
				t.Fatalf("exec out %d bytes seq %d", len(f.payload), f.seq)
			}
			break
		}
	}
	h.Close()
}

func TestRTTOverUART(t *testing.T) {
	for _, size := range []int{64, 4096} {
		h, g, toGuest, _ := uartPair()
		a := &agent{streams: map[string]*stream{}, token: "t"}
		go a.serve(newConn(g, defAgentWin, 2*time.Second), "uart")
		c := newConn(h, defClientWin, 2*time.Second)
		w, err := handshake(c, "r", 1, uint64(time.Now().UnixNano()), defClientWin, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		res := rttRun(c, w, 20, size, 2*time.Second)
		m := map[string]any{}
		for i := 0; i+1 < len(res); i += 2 {
			m[res[i].(string)] = res[i+1]
		}
		if m["ok"] != true || m["acked"].(int) != 20 || m["rtt_n"].(int) != 20 || toGuest.dropped != 0 {
			t.Fatalf("size %d: %v (dropped %d)", size, m, toGuest.dropped)
		}
		h.Close()
	}
}

// The agent's tty connection outlives host sessions: an UPACK reports the bytes this session skipped after
// its HELLO, and separately what was skipped before it (the host's preamble), not the reader's lifetime total.
func TestUploadSkippedIsPerSession(t *testing.T) {
	_, g, toGuest, toHost := uartPair()
	a := &agent{streams: map[string]*stream{}, token: "t"}
	go a.serve(newConn(g, defAgentWin, 2*time.Second), "uart")
	// each session is a new host process (a new conn and reader) on the same nmdm: one pump feeds the
	// current session's pipe
	var mu sync.Mutex
	var cur *io.PipeWriter
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := toHost.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			w := cur
			mu.Unlock()
			w.Write(b[:n])
		}
	}()
	for i := 1; i <= 3; i++ {
		pr, pw := io.Pipe()
		mu.Lock()
		if cur != nil {
			cur.Close()
		}
		cur = pw
		mu.Unlock()
		toGuest.Write(make([]byte, preambleLen)) // what dial() writes before every HELLO
		c := newConn(sessEnd{pr, toGuest}, defClientWin, 2*time.Second)
		w, err := handshake(c, "s", 1, uint64(i), defClientWin, 2*time.Second)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		res := bulkRun(c, w, 0, 4096, 1024, 0, 10*time.Second)
		m := map[string]any{}
		for j := 0; j+1 < len(res); j += 2 {
			m[res[j].(string)] = res[j+1]
		}
		if m["ok"] != true {
			t.Fatalf("session %d: %v", i, m)
		}
		if m["up_agent_skipped"] != float64(0) || m["up_agent_skipped_pre_hello"] != float64(preambleLen) ||
			m["up_agent_skipped_total"] != float64(i*preambleLen) {
			t.Fatalf("session %d: skipped %v pre_hello %v total %v", i, m["up_agent_skipped"], m["up_agent_skipped_pre_hello"], m["up_agent_skipped_total"])
		}
	}
	toGuest.close()
	toHost.close()
}

type sessEnd struct {
	r *io.PipeReader
	w *boundedPipe
}

func (e sessEnd) Read(b []byte) (int, error)  { return e.r.Read(b) }
func (e sessEnd) Write(b []byte) (int, error) { return e.w.Write(b) }
func (e sessEnd) Close() error                { return e.r.Close() }

type tickW struct {
	failAfter int // writes that succeed before every later one fails (a revoked /dev/console)
	writes    *[]string
	n         int
}

func (w *tickW) Write(b []byte) (int, error) {
	if w.n >= w.failAfter {
		return 0, errors.New("ENXIO (revoked)")
	}
	w.n++
	*w.writes = append(*w.writes, string(b))
	return len(b), nil
}
func (w *tickW) Close() error { return nil }

// A console that goes dead after the first line (rc's exit revokes /dev/console) is reopened at once; no
// tick is lost. An open that fails is retried next tick without stopping the loop.
func TestTickerReopensAfterWriteError(t *testing.T) {
	var lines []string
	fresh := 0
	tk := &ticker{open: func() (io.WriteCloser, error) {
		fresh++
		if fresh == 1 {
			return &tickW{failAfter: 1, writes: &lines}, nil
		}
		return &tickW{failAfter: 1 << 30, writes: &lines}, nil
	}}
	for n := 1; n <= 5; n++ {
		if err := tk.tick(func() string { return fmt.Sprintf("n=%d\n", n) }); err != nil {
			t.Fatalf("tick %d: %v", n, err)
		}
	}
	if len(lines) != 5 || tk.opens != 2 || tk.werrs != 1 {
		t.Fatalf("lines %q opens %d werrs %d", lines, tk.opens, tk.werrs)
	}
	bad := &ticker{open: func() (io.WriteCloser, error) { return nil, errors.New("no console") }}
	for n := 0; n < 3; n++ {
		if bad.tick(func() string { return "x\n" }) == nil {
			t.Fatal("tick without a console reported success")
		}
	}
	if bad.fails != 3 {
		t.Fatalf("fails %d", bad.fails)
	}
}
