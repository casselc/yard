// sr3j-chan -- SR3J spike: a snapshot-safe host<->guest agent channel for bhyve (ops/sr3j/).
//
// One binary, two roles:
//
//	sr3j-chan agent  -tcp :7700 -tty /dev/cuau1 [-console /dev/console] [-stepclock] [-win 320] [-resume-restart svc,...]   (in the guest, as root)
//	sr3j-chan client <ping|exec|bulk|rtt|stream> -addr tcp:IP:PORT|tty:/dev/nmdmXB ...            (host side, unprivileged)
//
// Wire format (identical on TCP and on the emulated UART, so the UART can resynchronise after garbage):
//
//	magic u16 0x594A | type u8 | flags u8 | len u32 | seq u64 | payload[len] | crc32(IEEE) of all before it
//
// flags bit 0 (fMore): more fragments of this logical frame follow (UART only, see below).
//
// Session model: the host opens a connection and sends HELLO{stream, epoch, gen, host time, win}. The agent
// answers WELCOME{gen, prev_epoch, last_seq, win, ...}: last_seq is the highest contiguous MSG seq it has
// delivered on that stream, so after any disconnect (suspend/restore, RST, tty hangup) the host resends from
// last_seq+1 and the agent never delivers a seq twice (exactly-once per stream across reconnects).
// The epoch comes from the host (yard-ctl's resume epoch; here a file the test script bumps after each
// restore), so the agent sees an epoch change exactly when it was restored.
//
// Resume duties (internal/guestagent, docs/guest-resume.md, model spec/guestresume): a new VM generation
// (devd VMGenerationCounter, the sysctl poll, SIGUSR1) or a newer HELLO epoch starts a resume run; the
// agent answers "resuming" in WELCOME and refuses EXEC (rc 75) until it ends. A run asks one live host
// connection (RESUMEREQ {gen, seq}; every host-side reader answers RESUMEANS {its time, epoch, 64 random
// bytes}), steps the clock by the NTP offset (-stepclock; error <= RTT/2; a restored guest's clock lost the
// downtime, SR3), writes the bytes to /dev/random, restarts the -resume-restart services, and sends a
// RESUMEREC to every live host connection (and in every later WELCOME). Until 2026-10-07 -stepclock set
// the clock to the HELLO's host_ns on any HELLO more than 1 s off: a HELLO queued in a restored socket
// buffer carries an old host_ns.
//
// UART flow control (2026-10-07: the first e2e run's 64 KiB UART bulk hung until `timeout 300`). The
// emulated 16550 has no flow control, and both directions drop bytes silently when a buffer is full
// (source: FreeBSD 15.1 /usr/src on the NUC):
//   - host->guest: bhyve refills its 16-byte rx FIFO from the nmdm as fast as the guest drains it
//     (usr.sbin/bhyve/uart_backend.c:138-161 re-enables the read event on each getchar from a full FIFO,
//     :196-216 refills it), so during a burst the guest's ns8250 receive loop
//     (sys/dev/uart/uart_dev_ns8250.c:1042-1065) never sees the FIFO empty. Its software rx buffer
//     (384 entries, uart_core.c:635) is drained only by the swi scheduled after that loop returns
//     (uart_core.c:349-360), so after 383 bytes it marks an overrun and DISCARDS everything still
//     arriving (uart_dev_ns8250.c:1043-1046, 1066-1071). No LSR_OE, so dev.uart.1.rx_overruns stays 0.
//   - guest->host: bhyve writes each THR byte with a non-blocking write(2) to its nmdm side and ignores
//     EAGAIN on a tty (uart_backend.c:126-130, :224-228); LSR always reports THRE (uart_emul.c:384-386),
//     so the guest is never slowed. bhyve's cfmakeraw keeps that side's default 9600 baud, so its out
//     queue is 1920 bytes (sys/kern/tty.c:131-155); a late nmdm swi task (nmdm.c:249-296) means loss.
//
// A lost byte breaks one frame; the reader resyncs on magic+CRC, but nothing retransmits, and when the
// loss hits the last frames (BULKEND/UPEND) or leaves the reader in Peek waiting for a length that never
// completes, the peer waits forever. Fix: on tty transports each receiver advertises a byte window (in
// HELLO/WELCOME: what it can hold unread without loss) and returns CREDIT frames carrying the bytes it has
// consumed; a sender keeps sent - peer_consumed <= window. Logical frames larger than half the peer's window
// go as fMore fragments, so control frames (ACKs) interleave between the fragments of a bulk chunk, and
// the window bounds head-of-line delay whatever the chunk size. CREDIT frames bypass the window (28 bytes,
// a few in flight at most). A send that waits longer than -stall for credit fails with the counters instead
// of hanging. TCP connections run without the window (TCP does flow control).
//
// This is a spike: no authentication (the transport is the security boundary: a pf-guarded /30 or a
// jail-private nmdm), JSON payloads for control frames.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"yard/internal/guestagent"
)

const (
	magic    = 0x594A
	hdrLen   = 16
	ovh      = hdrLen + 4 // framing bytes per wire frame
	maxFrame = 1 << 20

	tHello   = 1
	tWelcome = 2
	tMsg     = 3
	tAck     = 4
	tExec    = 5
	tExecOut = 6
	tBulkReq = 7
	tBulk    = 8
	tBulkEnd = 9
	tUpload  = 10
	tUpEnd   = 11
	tUpAck   = 12
	tCredit  = 13 // seq = bytes consumed since the session's reset; payload = that session's gen (u64)
	// resume (internal/guestagent): the agent asks a live host for its time, epoch and fresh random bytes
	// (REQ payload {gen, seq} = the nonce; ANS echoes it), and sends its RECord of each resume run to every
	// live host. Every host-side conn answers REQ in its reader; all three are flow-controlled frames.
	tResumeReq = 14
	tResumeAns = 15
	tResumeRec = 16 // seq = the agent's run counter n

	fMore = 1

	// The guest's receive window: below uart(4)'s software rx buffer (384 entries, 383 usable), leaving
	// room for the host's CREDIT frames and the reconnect preamble.
	defAgentWin = 320
	// The host's receive window: below bhyve's nmdm side out queue (1920 B; the loss point if the nmdm swi
	// task runs late), and well above the bytes in flight during one credit round trip (~100 B/ms x ~2 ms).
	defClientWin = 1536
	preambleLen  = 16
)

type frame struct {
	typ, flags byte
	seq        uint64
	payload    []byte
	wire       uint64 // receive side: wire bytes this frame took (its last fragment + garbage skipped before it)
	skip       uint64 // receive side: the reader's cumulative skipped bytes when this frame was decoded
	at         time.Time
}

func encode(f frame) []byte {
	b := make([]byte, ovh+len(f.payload))
	binary.BigEndian.PutUint16(b[0:], magic)
	b[2] = f.typ
	b[3] = f.flags
	binary.BigEndian.PutUint32(b[4:], uint32(len(f.payload)))
	binary.BigEndian.PutUint64(b[8:], f.seq)
	copy(b[hdrLen:], f.payload)
	binary.BigEndian.PutUint32(b[hdrLen+len(f.payload):], crc32.ChecksumIEEE(b[:hdrLen+len(f.payload)]))
	return b
}

// reader decodes wire frames from a byte stream, skipping garbage until a valid frame (magic, sane length,
// matching CRC) starts. skipped counts discarded bytes, pos all consumed bytes (frames + skipped), both over
// the reader's whole life (on the agent's tty: every host session since the agent opened /dev/cuau1).
// Reads go straight into the 1 MiB buffer: one read(2) takes whatever the tty has; reads/readBytes count
// those calls (bytes per read(2) sizes the host client's CPU per wire byte).
type reader struct {
	r                *bufio.Reader
	skipped          atomic.Uint64
	pos              atomic.Uint64
	reads, readBytes atomic.Uint64
}

type countReader struct {
	r  io.Reader
	rd *reader
}

func (c countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.rd.reads.Add(1)
		c.rd.readBytes.Add(uint64(n))
	}
	return n, err
}

func newReader(r io.Reader) *reader {
	rd := &reader{}
	rd.r = bufio.NewReaderSize(countReader{r, rd}, maxFrame+ovh)
	return rd
}

func (rd *reader) next() (frame, error) {
	for {
		h, err := rd.r.Peek(hdrLen)
		if err != nil {
			return frame{}, err
		}
		n := binary.BigEndian.Uint32(h[4:])
		if binary.BigEndian.Uint16(h) != magic || n > maxFrame {
			rd.r.Discard(1)
			rd.skipped.Add(1)
			rd.pos.Add(1)
			continue
		}
		all, err := rd.r.Peek(hdrLen + int(n) + 4)
		if err != nil {
			return frame{}, err
		}
		if crc32.ChecksumIEEE(all[:hdrLen+n]) != binary.BigEndian.Uint32(all[hdrLen+n:]) {
			rd.r.Discard(1)
			rd.skipped.Add(1)
			rd.pos.Add(1)
			continue
		}
		f := frame{typ: all[2], flags: all[3], seq: binary.BigEndian.Uint64(all[8:]), payload: append([]byte(nil), all[hdrLen:hdrLen+n]...)}
		rd.r.Discard(len(all))
		rd.pos.Add(uint64(len(all)))
		return f, nil
	}
}

// ---------------------------------------------------------------- flow control (tty transports)

var errStall = errors.New("credit stall")

// flow is one connection's credit state. The tx side may send while sent+n <= peerConsumed+peerWin; the
// rx side counts consumed bytes and returns them in a CREDIT frame once half its window is unreported.
// That alone keeps the sender live, because no wire frame exceeds half the window: a blocked sender has
// more than half the window unreported. (Granting also whenever the queue ran empty flooded the slow
// guest-bound direction with CREDIT frames, which bypass the window: unit test, 2026-10-07.) Both sides
// reset at the handshake; gen tags the session, so a CREDIT from an earlier session is ignored.
type flow struct {
	mu   sync.Mutex
	cond *sync.Cond
	dead bool

	gen                         uint64
	txOn                        bool
	sent, peerConsumed, peerWin uint64
	rxOn                        bool
	consumed, granted, win      uint64

	stall                              time.Duration
	waits, creditsIn, grantsOut, stale uint64
	waitNs                             int64
}

func newFlow(win uint64, stall time.Duration) *flow {
	f := &flow{win: win, stall: stall}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *flow) kill() {
	f.mu.Lock()
	f.dead = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// maxPayload is the largest payload one wire frame may carry (0: unlimited).
func (f *flow) maxPayload() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.txOn {
		return 0
	}
	return max(int(f.peerWin/2)-ovh, 16)
}

// acquire blocks until n more bytes fit in the peer's window (or the window is off).
func (f *flow) acquire(n int) error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.txOn || f.sent+uint64(n) <= f.peerConsumed+f.peerWin {
		f.sent += uint64(n)
		return nil
	}
	f.waits++
	t0 := time.Now()
	tm := time.AfterFunc(f.stall, func() { f.mu.Lock(); f.cond.Broadcast(); f.mu.Unlock() })
	defer tm.Stop()
	for f.txOn && !f.dead && f.sent+uint64(n) > f.peerConsumed+f.peerWin {
		if time.Since(t0) >= f.stall {
			f.waitNs += int64(time.Since(t0))
			return fmt.Errorf("%w: a %d B frame waited %v; sent %d, peer consumed %d, peer window %d (gen %d)",
				errStall, n, f.stall, f.sent, f.peerConsumed, f.peerWin, f.gen)
		}
		f.cond.Wait()
	}
	f.waitNs += int64(time.Since(t0))
	if f.dead {
		return errors.New("connection closed")
	}
	f.sent += uint64(n)
	return nil
}

func (f *flow) credit(gen, consumed uint64) {
	f.mu.Lock()
	switch {
	case gen != f.gen:
		f.stale++
	case consumed > f.peerConsumed:
		f.peerConsumed = consumed
		f.creditsIn++
		f.cond.Broadcast()
	}
	f.mu.Unlock()
}

// rx counts n consumed bytes and says whether a CREDIT is due (gen, value).
func (f *flow) rx(n uint64) (uint64, uint64, bool) {
	if f == nil {
		return 0, 0, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.rxOn {
		return 0, 0, false
	}
	f.consumed += n
	if f.consumed-f.granted >= max(f.win/2, 1) {
		f.granted = f.consumed
		f.grantsOut++
		return f.gen, f.consumed, true
	}
	return 0, 0, false
}

func (f *flow) stats() map[string]any {
	if f == nil {
		return map[string]any{"flow": false}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{"flow": f.txOn, "win": f.win, "peer_win": f.peerWin, "sent": f.sent, "peer_consumed": f.peerConsumed,
		"consumed": f.consumed, "credit_waits": f.waits, "credit_wait_s": float64(f.waitNs) / 1e9, "credits_in": f.creditsIn,
		"credits_out": f.grantsOut, "credits_stale": f.stale}
}

// ---------------------------------------------------------------- connection

type conn struct {
	rw    io.ReadWriteCloser
	rd    *reader
	mu    sync.Mutex // one fragmented logical frame at a time (its fragments stay in order, unfragmented frames interleave)
	wmu   sync.Mutex // one wire frame at a time
	fl    *flow      // nil: no flow control (TCP)
	in    chan frame
	rerr  error
	wrote atomic.Uint64 // all wire bytes written
	sess  atomic.Uint64 // agent: bumped on every accepted HELLO (stops an earlier session's bulk sender)
	// host side: non-nil -> the reader answers the agent's resume requests with this epoch
	epochFn func() uint64
	ansCh   chan frame // agent side: resume answers, for the Resumer's exchange
}

// newConn starts the reader goroutine. win > 0 enables the credit window (tty transports); it takes effect
// at the handshake.
func newConn(rw io.ReadWriteCloser, win uint64, stall time.Duration) *conn {
	return newConnEpoch(rw, win, stall, nil)
}

// newConnEpoch: a host-side connection whose reader answers the agent's resume requests with epochFn().
func newConnEpoch(rw io.ReadWriteCloser, win uint64, stall time.Duration, epochFn func() uint64) *conn {
	c := &conn{rw: rw, rd: newReader(rw), in: make(chan frame, 4096), ansCh: make(chan frame, 16), epochFn: epochFn}
	if win > 0 {
		c.fl = newFlow(win, stall)
	}
	go c.readLoop()
	return c
}

// readLoop applies CREDIT frames as they arrive (never behind the application, which may itself be waiting
// for credit) and reassembles fragments. Fragment bytes count as consumed at once (they sit in the
// reassembly buffer); a frame's last fragment counts when the application takes the frame (recv).
func (c *conn) readLoop() {
	var last uint64
	var asm []byte
	var asmTyp byte
	asmOn := false
	for {
		f, err := c.rd.next()
		if err != nil {
			c.rerr = err
			if c.fl != nil {
				c.fl.kill()
			}
			close(c.in)
			return
		}
		p := c.rd.pos.Load()
		f.skip = c.rd.skipped.Load() // exact: only this goroutine decodes
		f.wire = p - last
		last = p
		if f.typ == tCredit {
			if c.fl != nil && len(f.payload) == 8 {
				c.fl.credit(binary.BigEndian.Uint64(f.payload), f.seq)
			}
			continue
		}
		if f.flags&fMore != 0 {
			if !asmOn || asmTyp != f.typ || len(asm)+len(f.payload) > maxFrame {
				asm, asmTyp, asmOn = asm[:0], f.typ, true
			}
			asm = append(asm, f.payload...)
			c.grant(f.wire)
			continue
		}
		if asmOn && asmTyp == f.typ { // the last fragment; other frames (ACKs, probes) pass between fragments
			f.payload = append(append([]byte(nil), asm...), f.payload...)
			asm, asmOn = asm[:0], false
		}
		switch f.typ {
		case tResumeReq: // host side: answer in the background (the send may wait for credit)
			f.at = time.Now()
			c.take(f)
			if c.epochFn != nil {
				go c.answerResume(f)
			}
			continue
		case tResumeAns: // agent side: to the Resumer's exchange; never blocks the reader
			c.take(f)
			select {
			case c.ansCh <- f:
			default:
			}
			continue
		}
		c.in <- f
	}
}

func (c *conn) grant(n uint64) {
	if gen, v, ok := c.fl.rx(n); ok {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, gen)
		w := encode(frame{typ: tCredit, seq: v, payload: b})
		c.wmu.Lock()
		c.rw.Write(w)
		c.wrote.Add(uint64(len(w)))
		c.wmu.Unlock()
	}
}

// take counts a frame the application took from c.in as consumed (credit window).
func (c *conn) take(f frame) {
	if c.fl != nil {
		c.grant(f.wire)
	}
}

// recv returns the next logical frame.
func (c *conn) recv() (frame, error) {
	f, ok := <-c.in
	if !ok {
		return frame{}, c.rerr
	}
	c.take(f)
	return f, nil
}

func (c *conn) writeWire(w []byte) error {
	if err := c.fl.acquire(len(w)); err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.rw.Write(w)
	c.wrote.Add(uint64(len(w)))
	return err
}

// send writes one logical frame: one wire frame (one write(2) of header+payload+CRC), or, when it exceeds
// half the peer's window, fMore fragments.
func (c *conn) send(f frame) error {
	maxp := c.fl.maxPayload()
	if maxp == 0 || len(f.payload) <= maxp {
		return c.writeWire(encode(f))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := f.payload
	for off := 0; off < len(p); off += maxp {
		end := min(off+maxp, len(p))
		fr := frame{typ: f.typ, seq: f.seq, payload: p[off:end]}
		if end < len(p) {
			fr.flags = fMore
		}
		if err := c.writeWire(encode(fr)); err != nil {
			return err
		}
	}
	return nil
}

func (c *conn) sendJSON(typ byte, seq uint64, v any) error {
	b, _ := json.Marshal(v)
	return c.send(frame{typ: typ, seq: seq, payload: b})
}

// answerResume (host side): the host's wall clock at the request's arrival and just before the answer
// is written, its current resume epoch, and 64 fresh random bytes.
func (c *conn) answerResume(f frame) {
	var q guestagent.Request
	if json.Unmarshal(f.payload, &q) != nil {
		return
	}
	a := guestagent.Answer{Gen: q.Gen, Seq: q.Seq, Epoch: c.epochFn(), HostRxNs: f.at.UnixNano(), Entropy: make([]byte, 64)}
	rand.Read(a.Entropy)
	a.HostTxNs = time.Now().UnixNano()
	c.sendJSON(tResumeAns, q.Seq, a)
}

// connHost is the agent's view of one host connection for the Resumer.
type connHost struct {
	c         *conn
	transport string
	now       func() time.Time // the guest wall clock (the Resumer's)
}

func (h *connHost) Name() string { return h.transport }
func (h *connHost) Rank() int {
	if h.transport == "tcp" {
		return 0
	}
	return 1
}

func (h *connHost) Exchange(ctx context.Context, req guestagent.Request) (guestagent.Sample, error) {
	for drained := false; !drained; { // answers left from earlier requests: dropped here
		select {
		case <-h.c.ansCh:
		default:
			drained = true
		}
	}
	b, _ := json.Marshal(req)
	sent := h.now()
	errc := make(chan error, 1)
	go func() { errc <- h.c.send(frame{typ: tResumeReq, seq: req.Seq, payload: b}) }()
	for {
		select {
		case <-ctx.Done():
			return guestagent.Sample{}, ctx.Err()
		case err := <-errc:
			if err != nil {
				return guestagent.Sample{}, err
			}
		case f := <-h.c.ansCh:
			var a guestagent.Answer
			if json.Unmarshal(f.payload, &a) != nil {
				continue
			}
			return guestagent.Sample{Ans: a, Sent: sent, Recv: h.now()}, nil
		}
	}
}

func (h *connHost) Send(rec guestagent.Record) error { return h.c.sendJSON(tResumeRec, rec.N, rec) }

// dial: a host-side connection; its reader answers resume requests with epoch().
func dial(addr string, timeout time.Duration, win uint64, stall time.Duration, epoch func() uint64) (*conn, error) {
	switch {
	case strings.HasPrefix(addr, "tcp:"):
		c, err := net.DialTimeout("tcp", addr[4:], timeout)
		if err != nil {
			return nil, err
		}
		return newConnEpoch(c, 0, stall, epoch), nil
	case strings.HasPrefix(addr, "tty:"):
		f, err := openTTY(addr[4:])
		if err != nil {
			return nil, err
		}
		// a few non-magic bytes so a half-written frame the peer is still parsing can complete (and fail CRC)
		f.Write(make([]byte, preambleLen))
		return newConnEpoch(f, win, stall, epoch), nil
	}
	return nil, fmt.Errorf("addr must be tcp:HOST:PORT or tty:PATH, got %q", addr)
}

// ---------------------------------------------------------------- agent

type hello struct {
	Stream string `json:"stream"`
	Epoch  uint64 `json:"epoch"`
	Gen    uint64 `json:"gen"`
	HostNs int64  `json:"host_ns"`
	Win    uint64 `json:"win,omitempty"` // host's receive window (tty); 0: no flow control this session
}

type welcome struct {
	Stream       string `json:"stream"`
	Gen          uint64 `json:"gen"` // the HELLO's gen (a host ignores WELCOMEs for its earlier attempts)
	Epoch        uint64 `json:"epoch"`
	PrevEpoch    uint64 `json:"prev_epoch"`
	EpochChanges uint64 `json:"epoch_changes"`
	LastSeq      uint64 `json:"last_seq"`
	Dups         uint64 `json:"dups"`
	Gaps         uint64 `json:"gaps"`
	Stale        uint64 `json:"stale"`      // MSGs that arrived on a superseded connection and were dropped
	Superseded   uint64 `json:"superseded"` // HELLOs refused because a newer one (higher gen) already arrived
	Refused      bool   `json:"refused"`    // this HELLO was one of them
	GuestNs      int64  `json:"guest_ns"`   // guest clock when HELLO arrived, before any step
	SteppedNs    int64  `json:"stepped_ns"` // clock step applied by the latest resume run (0 if none)
	Token        string `json:"token"`
	Pid          int    `json:"pid"`
	Transport    string `json:"transport"`
	Win          uint64 `json:"win,omitempty"` // agent's receive window (tty)
	// resume state (internal/guestagent): "resuming" until the actions of every resume seen have run;
	// exec is refused meanwhile. Resumes = runs since the agent started; Resume = the latest record.
	State   string             `json:"state,omitempty"`
	Resumes uint64             `json:"resumes"`
	Resume  *guestagent.Record `json:"resume,omitempty"`
}

type stream struct {
	last, epoch, epochChanges, dups, gaps, stale, gen, superseded uint64
	owner                                                         *conn // the connection that sent the latest HELLO
}

type agent struct {
	mu      sync.Mutex
	streams map[string]*stream
	token   string
	res     *guestagent.Resumer
	now     func() time.Time // guest wall clock for the resume exchange (time.Now; tests: the fake clock)
}

// welcomeReset resets the credit state and sends WELCOME in one step under the wire lock, so every later
// frame counts in the new session (the host counts from WELCOME, its tx from after HELLO).
func (c *conn) welcomeReset(w welcome, h hello) error {
	b, _ := json.Marshal(w)
	wire := encode(frame{typ: tWelcome, payload: b})
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.fl != nil {
		c.fl.mu.Lock()
		c.fl.gen = h.Gen
		c.fl.txOn, c.fl.rxOn = h.Win > 0, h.Win > 0
		c.fl.peerWin, c.fl.peerConsumed, c.fl.sent = h.Win, 0, uint64(len(wire))
		c.fl.consumed, c.fl.granted = 0, 0
		c.fl.cond.Broadcast()
		c.fl.mu.Unlock()
	}
	_, err := c.rw.Write(wire)
	c.wrote.Add(uint64(len(wire)))
	return err
}

// serve runs one connection. On the tty that is every host session until the agent reopens the device, so
// the reader's skipped count is split at each accepted HELLO: preHello = bytes skipped since the previous
// session's HELLO up to this one (the new host's preamble, preambleLen zero bytes, plus whatever the last
// session left half-written), and an UPACK reports only what this session skipped after its HELLO.
// (Until 2026-10-07 UPACK reported the reader's lifetime total: the sweep's "1309, 1341, 1373, ..." grew by
// 32 per up point = the preambles of the down and the up client in between, not loss.)
func (a *agent) serve(c *conn, transport string) {
	var st *stream
	var upBytes, upFrames uint64
	var skipMark, preHello uint64
	host := &connHost{c: c, transport: transport, now: a.now}
	defer a.res.Remove(host)
	for {
		f, err := c.recv()
		if err != nil {
			return
		}
		switch f.typ {
		case tHello:
			var h hello
			if json.Unmarshal(f.payload, &h) != nil || h.Stream == "" {
				continue
			}
			now := time.Now().UnixNano()
			a.mu.Lock()
			s := a.streams[h.Stream]
			if s == nil {
				s = &stream{}
				a.streams[h.Stream] = s
			}
			if h.Gen <= s.gen {
				// a HELLO older than the current owner's: a connection the host already gave up on
				// (queued in the listen backlog or in a restored guest's socket buffer). Refuse it, or it
				// would steal the stream from the live connection.
				s.superseded++
				a.mu.Unlock()
				b, _ := json.Marshal(welcome{Stream: h.Stream, Gen: h.Gen, Refused: true})
				c.wmu.Lock() // raw: this connection's credit state belongs to the session being refused
				c.rw.Write(encode(frame{typ: tWelcome, payload: b}))
				c.wmu.Unlock()
				return
			}
			st = s
			st.gen = h.Gen
			st.owner = c
			// the epoch first (a HELLO with a newer one starts a resume run), then the state for WELCOME
			a.res.ObserveEpoch(h.Epoch, host)
			rs := a.res.Status()
			w := welcome{Stream: h.Stream, Gen: h.Gen, Epoch: h.Epoch, PrevEpoch: st.epoch, LastSeq: st.last, Dups: st.dups, Gaps: st.gaps, Stale: st.stale,
				Superseded: st.superseded, GuestNs: now, Token: a.token, Pid: os.Getpid(), Transport: transport,
				State: string(rs.Phase), Resumes: rs.Runs, Resume: rs.Last}
			if rs.Last != nil {
				w.SteppedNs = rs.Last.Clock.StepNs
			}
			if c.fl != nil {
				w.Win = c.fl.win
			}
			if st.epoch != 0 && st.epoch != h.Epoch {
				st.epochChanges++
			}
			st.epoch = h.Epoch
			w.EpochChanges = st.epochChanges
			a.mu.Unlock()
			c.sess.Add(1)
			upBytes, upFrames = 0, 0
			preHello, skipMark = f.skip-skipMark, f.skip
			if c.welcomeReset(w, h) != nil {
				return
			}
		case tMsg:
			if st == nil {
				continue
			}
			a.mu.Lock()
			if st.owner != c {
				// a newer connection took this stream over (host reconnected, e.g. after a restore while
				// this one still had buffered data): its WELCOME already told the host what we have.
				st.stale++
				a.mu.Unlock()
				continue
			}
			switch {
			case f.seq == st.last+1:
				st.last = f.seq
			case f.seq <= st.last:
				st.dups++
			default:
				st.gaps++
			}
			last := st.last
			a.mu.Unlock()
			if c.send(frame{typ: tAck, seq: last}) != nil {
				return
			}
		case tExec:
			// privileged work: refused until the resume actions have run (the gate reads the generation)
			if err := a.res.Allow(); err != nil {
				if c.sendJSON(tExecOut, f.seq, map[string]any{"rc": 75, "refused": err.Error(), "out": ""}) != nil {
					return
				}
				continue
			}
			ctx := exec.Command("/bin/sh", "-c", string(f.payload))
			out, err := runTimeout(ctx, 30*time.Second)
			rc := 0
			if err != nil {
				rc = -1
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					rc = ee.ExitCode()
				}
			}
			if len(out) > 65536 {
				out = out[:65536]
			}
			if c.sendJSON(tExecOut, f.seq, map[string]any{"rc": rc, "out": string(out)}) != nil {
				return
			}
		case tBulkReq:
			var q struct{ Bytes, Chunk int }
			if json.Unmarshal(f.payload, &q) != nil || q.Chunk <= 0 || q.Chunk > maxFrame {
				continue
			}
			// a goroutine, so this loop keeps reading while the bulk runs: MSGs (probes) are ACKed at once
			// and the ACKs go out between bulk frames (TCP) or fragments (UART). (Until 2026-10-07 the
			// loop sent the whole bulk inline and read nothing meanwhile.)
			go func(sess uint64) {
				buf := make([]byte, q.Chunk)
				for i := range buf {
					buf[i] = byte(i * 7)
				}
				sent := 0
				for sent < q.Bytes {
					if c.sess.Load() != sess {
						return
					}
					n := min(q.Chunk, q.Bytes-sent)
					if c.send(frame{typ: tBulk, seq: uint64(sent), payload: buf[:n]}) != nil {
						return
					}
					sent += n
				}
				c.send(frame{typ: tBulkEnd, seq: uint64(sent)})
			}(c.sess.Load())
		case tUpload:
			upBytes += uint64(len(f.payload))
			upFrames++
		case tUpEnd:
			r := map[string]any{"bytes": upBytes, "frames": upFrames, "skipped": f.skip - skipMark, "skipped_pre_hello": preHello,
				"skipped_total": f.skip}
			for k, v := range c.fl.stats() {
				r["agent_"+k] = v
			}
			n := upBytes
			upBytes, upFrames = 0, 0
			if c.sendJSON(tUpAck, n, r) != nil {
				return
			}
		}
	}
}

func runTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	t := time.AfterFunc(d, func() { cmd.Process.Kill() })
	err := cmd.Wait()
	t.Stop()
	return []byte(out.String()), err
}

func agentMain(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	tcpAddr := fs.String("tcp", ":7700", "TCP listen address (empty: none)")
	tty := fs.String("tty", "", "serial device to serve (e.g. /dev/cuau1; empty: none)")
	console := fs.String("console", "", "write a once-per-second SR3JTICK line here (e.g. /dev/console)")
	step := fs.Bool("stepclock", false, "resume runs step the guest clock by the host offset (NTP exchange over the channel, error <= RTT/2); off: the clock action is skipped")
	win := fs.Uint64("win", defAgentWin, "tty: receive window advertised to the host (bytes; must stay below uart(4)'s 383-byte rx buffer)")
	stall := fs.Duration("stall", 10*time.Second, "tty: a send waiting this long for credit fails")
	restart := fs.String("resume-restart", "", "comma-separated rc.d services that hold keys: restarted by every resume run (default none)")
	settle := fs.Duration("resume-settle", time.Second, "a resume seen first by its epoch waits this long for the VM-generation notify")
	svcTimeout := fs.Duration("resume-svc-timeout", 30*time.Second, "per service restart; on timeout the old pid is killed (outcome unknown)")
	devdPath := fs.String("devd", "/var/run/devd.seqpacket.pipe", "devd(8) event socket (VMGenerationCounter notifications)")
	genPoll := fs.Duration("genpoll", time.Second, "also poll sysctl dev.vmgenc.0.guid this often (a lost devd event; not a lost ACPI notify)")
	fs.Parse(args)
	tok := make([]byte, 8)
	if f, err := os.Open("/dev/random"); err == nil {
		io.ReadFull(f, tok)
		f.Close()
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "%s sr3j-chan agent: %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), fmt.Sprintf(format, args...))
	}
	cfg := guestagent.Config{Settle: *settle, ServiceTimeout: *svcTimeout}
	for _, n := range strings.Split(*restart, ",") {
		if n = strings.TrimSpace(n); n != "" {
			cfg.Services = append(cfg.Services, n)
		}
	}
	if !*step {
		cfg.StepMin = math.MaxInt64 // every offset is below it: the clock action records "skip"
	}
	gen := guestagent.SysctlGen{}
	res := guestagent.New(cfg, guestagent.Deps{Clock: guestagent.SysClock{}, Gen: gen, Entropy: guestagent.DevRandom{},
		Services: guestagent.RcServices{}, Log: logf})
	ctx := context.Background()
	go res.Run(ctx)
	observe := func(src string) {
		if g, err := gen.ReadGen(); err == nil {
			res.ObserveGen(g, src)
		} else {
			logf("read generation (%s): %v", src, err)
		}
	}
	go guestagent.WatchDevd(ctx, *devdPath, func() { observe("devd") }, logf)
	if *genPoll > 0 {
		go func() {
			for range time.Tick(*genPoll) {
				observe("poll")
			}
		}()
	}
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1) // "re-read the generation now" (a synthetic notify; the e2e's duplicate)
	go func() {
		for range usr1 {
			observe("sigusr1")
		}
	}()
	g0, _ := gen.ReadGen()
	logf("start: pid %d generation %q services %v stepclock %v", os.Getpid(), g0, cfg.Services, *step)
	a := &agent{streams: map[string]*stream{}, token: fmt.Sprintf("%x", tok), res: res, now: time.Now}
	if *tcpAddr != "" {
		ln, err := net.Listen("tcp", *tcpAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sr3j-chan agent:", err)
			os.Exit(1)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(10 * time.Second)
				}
				go func() { a.serve(newConn(c, 0, *stall), "tcp"); c.Close() }()
			}
		}()
	}
	if *tty != "" {
		go func() {
			for {
				f, err := openTTY(*tty)
				if err != nil {
					fmt.Fprintln(os.Stderr, "sr3j-chan agent:", err)
					time.Sleep(time.Second)
					continue
				}
				a.serve(newConn(f, *win, *stall), "uart")
				f.Close()
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	var tk *ticker
	if *console != "" {
		path := *console
		tk = &ticker{open: func() (io.WriteCloser, error) { return os.OpenFile(path, os.O_WRONLY|syscall.O_NOCTTY, 0) }}
	}
	for n := uint64(1); ; n++ {
		if tk != nil {
			if err := tk.tick(func() string {
				return fmt.Sprintf("SR3JTICK n=%d pid=%d tok=%s t=%d opens=%d werr=%d\n", n, os.Getpid(), a.token, time.Now().Unix(), tk.opens, tk.werrs)
			}); err != nil && tk.fails <= 10 {
				fmt.Fprintf(os.Stderr, "sr3j-chan agent: tick %d: %v (opens %d, write errors %d)\n", n, err, tk.opens, tk.werrs)
			}
		}
		time.Sleep(time.Second)
	}
}

// ticker writes the once-a-second SR3JTICK line, reopening the console after any write error.
//
// 2026-10-07 (runs 183613Z and 202014Z): console-boot.log had only n=1 and console-r1.log nothing. Cause:
// rc starts the agent while /etc/rc is still running as the session leader whose controlling terminal is
// /dev/console (init's run_script -> setctty, sbin/init/init.c); when /etc/rc exits, killjobc() revokes that
// tty vnode with REVOKEALL (sys/kern/kern_proc.c:961), which revokes every open of /dev/console, the agent's
// included. Every later write failed and the old loop ignored the error, so the agent ran on, mute (the
// channel answered after the restore). Now: a write error closes the file and reopens it at once (one
// retry per tick); a write deadline (the console fd is kqueue-pollable) keeps a stalled console from blocking
// the loop; opens/werr in the line show it happened (expected after boot: opens=2 werr=1 from n=2 or so).
type ticker struct {
	open                func() (io.WriteCloser, error)
	w                   io.WriteCloser
	opens, werrs, fails uint64
}

func (t *ticker) tick(line func() string) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if t.w == nil {
			w, oerr := t.open()
			if oerr != nil {
				err = fmt.Errorf("open: %w", oerr)
				continue
			}
			t.w = w
			t.opens++
		}
		if d, ok := t.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
			d.SetWriteDeadline(time.Now().Add(2 * time.Second)) // ErrNoDeadline when not pollable: then a plain write
		}
		if _, err = io.WriteString(t.w, line()); err == nil {
			return nil
		}
		t.werrs++
		t.w.Close()
		t.w = nil
	}
	t.fails++
	return err
}

// ---------------------------------------------------------------- client

func readEpoch(path string, def uint64) uint64 {
	if path == "" {
		return def
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return def
	}
	return v
}

// handshake sends HELLO and waits for the WELCOME of this gen (other frames before it are dropped). On a
// tty it starts the credit session: tx counts from after HELLO, rx from the WELCOME frame.
func handshake(c *conn, name string, epoch, gen uint64, win uint64, timeout time.Duration) (welcome, error) {
	var w welcome
	h := hello{Stream: name, Epoch: epoch, Gen: gen, HostNs: time.Now().UnixNano()}
	if c.fl != nil {
		h.Win = win
	}
	b, _ := json.Marshal(h)
	wire := encode(frame{typ: tHello, payload: b})
	c.wmu.Lock()
	_, err := c.rw.Write(wire)
	c.wrote.Add(uint64(len(wire)))
	if c.fl != nil {
		c.fl.mu.Lock()
		c.fl.gen, c.fl.sent, c.fl.peerConsumed = gen, 0, 0
		c.fl.mu.Unlock()
	}
	c.wmu.Unlock()
	if err != nil {
		return w, err
	}
	tm := time.NewTimer(timeout)
	defer tm.Stop()
	for {
		select {
		case f, ok := <-c.in:
			if !ok {
				return w, c.rerr
			}
			if f.typ != tWelcome {
				continue
			}
			var x welcome
			if err := json.Unmarshal(f.payload, &x); err != nil {
				continue
			}
			if x.Gen != 0 && x.Gen != gen {
				continue // the answer to an earlier attempt, still in the byte stream
			}
			if x.Refused {
				return x, errors.New("HELLO refused (superseded)")
			}
			if c.fl != nil {
				on := win > 0 && x.Win > 0
				c.fl.mu.Lock()
				c.fl.txOn, c.fl.rxOn = on, on
				c.fl.peerWin = x.Win
				c.fl.consumed, c.fl.granted = 0, 0
				c.fl.mu.Unlock()
				c.take(f)
			}
			return x, nil
		case <-tm.C:
			c.rw.Close()
			return w, errors.New("no WELCOME")
		}
	}
}

// connect retries dial+handshake until it succeeds or wait elapses (wait 0: one attempt).
func connect(addr, name string, epoch func() uint64, wait time.Duration, win uint64, stall time.Duration) (*conn, welcome, int, error) {
	deadline := time.Now().Add(wait)
	attempts := 0
	for {
		attempts++
		c, err := dial(addr, time.Second, win, stall, epoch)
		if err == nil {
			var w welcome
			// gen orders connection attempts across client restarts too: wall-clock ns of this attempt
			w, err = handshake(c, name, epoch(), uint64(time.Now().UnixNano()), win, time.Second)
			if err == nil {
				return c, w, attempts, nil
			}
			c.rw.Close()
		}
		if !time.Now().Before(deadline) {
			return nil, welcome{}, attempts, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// recKV flattens a resume record for the one-line JSON outputs (the e2e reads flat keys with sed).
func recKV(r *guestagent.Record) []any {
	if r == nil {
		return []any{"rec_n", 0}
	}
	var svc []string
	for _, s := range r.Services {
		x := fmt.Sprintf("%s:%s:%d:%d", s.Name, s.Outcome.Outcome, s.PidOld, s.PidNew)
		if s.Killed {
			x += ":killed"
		}
		svc = append(svc, x)
	}
	return []any{"rec_n", r.N, "rec_trigger", r.Trigger, "rec_gen_old", string(r.GenOld), "rec_gen_new", string(r.GenNew),
		"rec_epoch_old", r.EpochOld, "rec_epoch_new", r.EpochNew, "rec_kr_pre", r.KrPre, "rec_kr_post", r.KrPost,
		"rec_clock", r.Clock.Outcome.Outcome, "rec_step_s", float64(r.Clock.StepNs) / 1e9, "rec_bound_ms", float64(r.Clock.BoundNs) / 1e6,
		"rec_rtt_ms", float64(r.Clock.RttNs) / 1e6, "rec_clock_via", r.Clock.Via, "rec_entropy", r.Entropy.Outcome.Outcome,
		"rec_entropy_bytes", r.Entropy.Bytes, "rec_entropy_writes", r.Entropy.Writes, "rec_entropy_passes", r.Entropy.Passes,
		"rec_entropy_min_pool", r.Entropy.MinPool, "rec_entropy_tick_ms", float64(r.Entropy.TickUs) / 1e3,
		"rec_entropy_need_ms", float64(r.Entropy.NeedUs) / 1e3, "rec_entropy_gap_ms", float64(r.Entropy.GapUs) / 1e3,
		"rec_entropy_ms", r.Entropy.Ms, "rec_services", strings.Join(svc, " "),
		"rec_stale", r.Stale, "rec_reported", r.Reported, "rec_ms", (r.EndNs - r.StartNs) / 1e6}
}

func emit(w io.Writer, kv ...any) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteString(",")
		}
		v, _ := json.Marshal(kv[i+1])
		fmt.Fprintf(&b, "%q:%s", kv[i], v)
	}
	b.WriteString("}\n")
	io.WriteString(w, b.String())
}

func ts() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// lat: nearest-rank percentiles (ms); all zero when empty.
type lat struct{ N, P50, P90, P99, Max, Mean float64 }

func latSummary(xs []float64) lat {
	if len(xs) == 0 {
		return lat{}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	r := func(p float64) float64 { return s[max(int(math.Ceil(p*float64(len(s))))-1, 0)] }
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	return lat{N: float64(len(s)), P50: r(0.50), P90: r(0.90), P99: r(0.99), Max: s[len(s)-1], Mean: sum / float64(len(s))}
}

func (l lat) kv(prefix string) []any {
	r3 := func(x float64) float64 { return math.Round(x*1000) / 1000 }
	return []any{prefix + "n", int(l.N), prefix + "p50_ms", r3(l.P50), prefix + "p90_ms", r3(l.P90), prefix + "p99_ms", r3(l.P99),
		prefix + "max_ms", r3(l.Max), prefix + "mean_ms", r3(l.Mean)}
}

func cpuSeconds() (float64, float64) {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0, 0
	}
	return float64(ru.Utime.Nano()) / 1e9, float64(ru.Stime.Nano()) / 1e9
}

// prober sends small MSG frames on the bulk's stream every interval and matches the agent's ACKs (seq =
// highest contiguous seq delivered). The RTT clock starts before send, so it includes waiting for the
// frame (or fragment) being written: the latency a control message sees on a shared link.
type prober struct {
	mu      sync.Mutex
	next    uint64
	pending map[uint64]probeRec
	rtt     map[string][]float64
}

type probeRec struct {
	t     time.Time
	phase string
}

func newProber(first uint64) *prober {
	return &prober{next: first, pending: map[uint64]probeRec{}, rtt: map[string][]float64{}}
}

func (p *prober) run(c *conn, phase string, every time.Duration, stop chan struct{}, done *sync.WaitGroup) {
	defer done.Done()
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			p.mu.Lock()
			seq := p.next
			p.next++
			p.pending[seq] = probeRec{time.Now(), phase}
			p.mu.Unlock()
			if c.send(frame{typ: tMsg, seq: seq}) != nil {
				return
			}
		}
	}
}

func (p *prober) ack(seq uint64, now time.Time) {
	p.mu.Lock()
	for s, r := range p.pending {
		if s <= seq {
			p.rtt[r.phase] = append(p.rtt[r.phase], float64(now.Sub(r.t))/1e6)
			delete(p.pending, s)
		}
	}
	p.mu.Unlock()
}

func (p *prober) outstanding(phase string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.pending {
		if r.phase == phase {
			n++
		}
	}
	return n
}

// bulkRun: down (guest->host) then up (host->guest), with optional probes. On a failure or the deadline it
// reports what moved so far (ok=false) instead of hanging.
func bulkRun(c *conn, w welcome, down, up, chunk int, probe time.Duration, deadline time.Duration) []any {
	type upAck struct {
		seq uint64
		raw map[string]any
	}
	var got, frames atomic.Int64
	downDone := make(chan uint64, 1)
	upDone := make(chan upAck, 1)
	readErr := make(chan error, 1)
	pr := newProber(w.LastSeq + 1)
	go func() {
		for {
			f, err := c.recv()
			if err != nil {
				readErr <- err
				return
			}
			switch f.typ {
			case tBulk:
				got.Add(int64(len(f.payload)))
				frames.Add(1)
			case tBulkEnd:
				downDone <- f.seq
			case tAck:
				pr.ack(f.seq, time.Now())
			case tUpAck:
				var m map[string]any
				json.Unmarshal(f.payload, &m)
				upDone <- upAck{f.seq, m}
			}
		}
	}()
	t0all := time.Now()
	dl := time.NewTimer(deadline)
	defer dl.Stop()
	res := []any{"chunk", chunk, "down_req", down, "up_req", up, "probe_ms", probe.Milliseconds()}
	errs := ""
	fail := func(what string, err error) {
		if errs == "" {
			errs = fmt.Sprintf("%s: %v (after %.1f s)", what, err, time.Since(t0all).Seconds())
		}
	}
	var wg sync.WaitGroup
	phase := func(name string, body func() bool) {
		stop := make(chan struct{})
		if probe > 0 {
			wg.Add(1)
			go pr.run(c, name, probe, stop, &wg)
		}
		ok := body()
		close(stop)
		wg.Wait()
		if ok && probe > 0 { // let the last probes come back (bounded)
			for end := time.Now().Add(3 * time.Second); pr.outstanding(name) > 0 && time.Now().Before(end); {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	rate := func(b int64, s float64) float64 {
		if s <= 0 {
			return 0
		}
		return float64(b) / 1e6 / s
	}
	if down > 0 {
		var ds float64
		rd0 := c.rd.pos.Load()
		phase("down", func() bool {
			t0 := time.Now()
			defer func() { ds = time.Since(t0).Seconds() }()
			if err := c.sendJSON(tBulkReq, 0, map[string]int{"bytes": down, "chunk": chunk}); err != nil {
				fail("down request", err)
				return false
			}
			select {
			case <-downDone:
				return true
			case err := <-readErr:
				fail("down read", err)
			case <-dl.C:
				fail("down", errors.New("deadline"))
			}
			return false
		})
		wire := int64(c.rd.pos.Load() - rd0)
		res = append(res, "down_bytes", got.Load(), "down_frames", frames.Load(), "down_s", ds, "down_MBps", rate(got.Load(), ds),
			"down_wire_bytes", wire, "down_wire_MBps", rate(wire, ds))
	}
	if up > 0 && errs == "" {
		var us float64
		var sent int
		var ack upAck
		wr0 := c.wrote.Load()
		phase("up", func() bool {
			buf := make([]byte, chunk)
			t0 := time.Now()
			defer func() { us = time.Since(t0).Seconds() }()
			for sent < up {
				select {
				case <-dl.C:
					fail("up", errors.New("deadline"))
					return false
				default:
				}
				n := min(chunk, up-sent)
				if err := c.send(frame{typ: tUpload, payload: buf[:n]}); err != nil {
					fail("up write", err)
					return false
				}
				sent += n
			}
			if err := c.send(frame{typ: tUpEnd}); err != nil {
				fail("up end", err)
				return false
			}
			select {
			case ack = <-upDone:
				return true
			case err := <-readErr:
				fail("up read", err)
			case <-dl.C:
				fail("up ack", errors.New("deadline"))
			}
			return false
		})
		wire := int64(c.wrote.Load() - wr0)
		res = append(res, "up_bytes_sent", sent, "up_bytes_acked", ack.seq, "up_s", us, "up_MBps", rate(int64(ack.seq), us),
			"up_wire_bytes", wire, "up_wire_MBps", rate(wire, us))
		for _, k := range []string{"frames", "skipped", "skipped_pre_hello", "skipped_total", "agent_credit_waits", "agent_credit_wait_s", "agent_credits_out", "agent_credits_stale"} {
			if v, ok := ack.raw[k]; ok {
				res = append(res, "up_agent_"+strings.TrimPrefix(k, "agent_"), v)
			}
		}
	}
	if probe > 0 {
		for _, ph := range []string{"down", "up"} {
			res = append(res, latSummary(pr.rtt[ph]).kv(ph+"_probe_")...)
			res = append(res, ph+"_probe_lost", pr.outstanding(ph))
		}
	}
	u, s := cpuSeconds()
	res = append(res, "skipped", c.rd.skipped.Load(), "reads", c.rd.reads.Load(), "read_bytes", c.rd.readBytes.Load(), "client_cpu_user_s", u, "client_cpu_sys_s", s, "elapsed_s", time.Since(t0all).Seconds())
	for k, v := range c.fl.stats() {
		res = append(res, k, v)
	}
	return append([]any{"ok", errs == "", "err", errs}, res...)
}

// rttRun sends n MSGs of size bytes one at a time, each after the previous one's ACK, and records RTTs.
func rttRun(c *conn, w welcome, n, size int, timeout time.Duration) []any {
	payload := make([]byte, size)
	var rtts []float64
	seq := w.LastSeq
	errs := ""
	t0 := time.Now()
loop:
	for i := 0; i < n; i++ {
		seq++
		ts0 := time.Now()
		if err := c.send(frame{typ: tMsg, seq: seq, payload: payload}); err != nil {
			errs = fmt.Sprintf("send %d: %v", i, err)
			break
		}
		tm := time.NewTimer(timeout)
		for {
			select {
			case f, ok := <-c.in:
				if !ok {
					tm.Stop()
					errs = fmt.Sprintf("read %d: %v", i, c.rerr)
					break loop
				}
				now := time.Now()
				c.take(f)
				if f.typ == tAck && f.seq >= seq {
					tm.Stop()
					rtts = append(rtts, float64(now.Sub(ts0))/1e6)
					continue loop
				}
			case <-tm.C:
				errs = fmt.Sprintf("msg %d: no ACK in %v", i, timeout)
				break loop
			}
		}
	}
	el := time.Since(t0).Seconds()
	u, s := cpuSeconds()
	res := []any{"ok", errs == "" && len(rtts) == n, "err", errs, "n", n, "size", size, "acked", len(rtts), "elapsed_s", el,
		"msgs_per_s", float64(len(rtts)) / el}
	res = append(res, latSummary(rtts).kv("rtt_")...)
	res = append(res, "skipped", c.rd.skipped.Load(), "reads", c.rd.reads.Load(), "read_bytes", c.rd.readBytes.Load(), "client_cpu_user_s", u, "client_cpu_sys_s", s)
	for k, v := range c.fl.stats() {
		res = append(res, k, v)
	}
	return res
}

func clientMain(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sr3j-chan client ping|exec|bulk|rtt|stream [flags]")
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("client "+sub, flag.ExitOnError)
	addr := fs.String("addr", "", "tcp:IP:PORT or tty:/dev/nmdmXB")
	name := fs.String("stream", sub, "stream name")
	epochFile := fs.String("epochfile", "", "file holding the current resume epoch (default epoch 1)")
	wait := fs.Duration("wait", 0, "ping/exec/bulk/rtt: keep retrying the connection this long")
	down := fs.Int("down", 0, "bulk: bytes guest->host")
	up := fs.Int("up", 0, "bulk: bytes host->guest")
	chunk := fs.Int("chunk", 65536, "bulk: frame payload size (logical frame; on a tty, fragments of at most half the peer's window)")
	probe := fs.Duration("probe", 0, "bulk: send a small MSG this often during each direction and report its ACK RTT")
	deadline := fs.Duration("deadline", 600*time.Second, "bulk: give up after this long and report partial progress")
	n := fs.Int("n", 200, "rtt: messages")
	rate := fs.Int("rate", 100, "stream: messages per second")
	size := fs.Int("size", 64, "stream/rtt: payload bytes per message")
	win := fs.Uint64("win", defClientWin, "tty: receive window advertised to the agent; 0 = no credit flow control (the pre-2026-10-07 protocol, diagnostic)")
	stall := fs.Duration("stall", 10*time.Second, "tty: a send waiting this long for credit fails; rtt: per-message ACK timeout")
	silence := fs.Duration("silence", 500*time.Millisecond, "stream: no ACK for this long with messages outstanding = down")
	keep := fs.Bool("keep", false, "stream: on silence keep the connection and wait for ACKs to resume (reconnect only on error or -keepmax)")
	keepMax := fs.Duration("keepmax", 120*time.Second, "stream -keep: give up on the old connection after this long")
	logPath := fs.String("log", "", "stream: JSONL event log (default stdout)")
	showState := fs.Bool("showstate", false, "exec: print the WELCOME's resume state to stderr")
	resumeWait := fs.Duration("resume", 0, "ping: when the agent answers 'resuming', stay connected (this connection answers its resume request) and wait this long for the resume record")
	resumeAfter := fs.Int("resume-after", -1, "ping -resume: the record must have n > this (the agent's runs before the restore): a WELCOME that is 'ready' with an older record waits too; -1: take the WELCOME's record unless 'resuming'")
	fs.Parse(args[1:])
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "-addr required")
		os.Exit(2)
	}
	epoch := func() uint64 { return readEpoch(*epochFile, 1) }
	switch sub {
	case "ping":
		t0 := time.Now()
		c, w, n, err := connect(*addr, *name, epoch, *wait, *win, *stall)
		if err != nil {
			emit(os.Stdout, "ok", false, "err", err.Error(), "attempts", n, "elapsed_s", time.Since(t0).Seconds())
			os.Exit(1)
		}
		el := time.Since(t0).Seconds()
		rec, via, waited := w.Resume, "welcome", 0.0
		minN, wantWait := w.Resumes, w.State == string(guestagent.Resuming)
		if *resumeAfter >= 0 {
			// a 'ready' agent whose last record predates the restore has not noticed it (yet): the old
			// record is not this restore's (run 20261008T012430Z took restore 5's record for 3 clones)
			minN = uint64(*resumeAfter)
			wantWait = wantWait || rec == nil || rec.N <= minN
		}
		if wantWait && *resumeWait > 0 {
			rec, via = nil, "timeout"
			t1 := time.Now()
			tm := time.NewTimer(*resumeWait)
		wait:
			for {
				select {
				case f, ok := <-c.in:
					if !ok {
						via = "closed"
						break wait
					}
					c.take(f)
					if f.typ == tResumeRec {
						var r guestagent.Record
						if json.Unmarshal(f.payload, &r) == nil && r.N > minN {
							rec, via = &r, "frame"
							break wait
						}
					}
				case <-tm.C:
					break wait
				}
			}
			tm.Stop()
			waited = time.Since(t1).Seconds()
		}
		c.rw.Close()
		out := []any{"ok", true, "attempts", n, "elapsed_s", el, "epoch", w.Epoch, "prev_epoch", w.PrevEpoch,
			"token", w.Token, "pid", w.Pid, "skew_s", float64(w.GuestNs-t0.UnixNano()) / 1e9, "stepped_s", float64(w.SteppedNs) / 1e9, "transport", w.Transport,
			"agent_win", w.Win, "state", w.State, "resumes", w.Resumes, "resume_via", via, "resume_wait_s", waited}
		emit(os.Stdout, append(out, recKV(rec)...)...)
	case "exec":
		c, w, _, err := connect(*addr, *name, epoch, *wait, *win, *stall)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connect:", err)
			os.Exit(1)
		}
		if *showState {
			fmt.Fprintf(os.Stderr, "welcome state=%s resumes=%d epoch=%d\n", w.State, w.Resumes, w.Epoch)
		}
		c.send(frame{typ: tExec, seq: 1, payload: []byte(strings.Join(fs.Args(), " "))})
		for {
			f, err := c.recv()
			if err != nil {
				fmt.Fprintln(os.Stderr, "read:", err)
				os.Exit(1)
			}
			if f.typ == tExecOut {
				var r struct {
					Rc      int
					Out     string
					Refused string
				}
				json.Unmarshal(f.payload, &r)
				if r.Refused != "" {
					fmt.Fprintln(os.Stderr, "refused:", r.Refused)
					os.Exit(75) // EX_TEMPFAIL: retry after the resume record
				}
				fmt.Print(r.Out)
				os.Exit(r.Rc & 0xff)
			}
		}
	case "bulk", "rtt":
		c, w, _, err := connect(*addr, *name, epoch, *wait, *win, *stall)
		if err != nil {
			emit(os.Stdout, "ok", false, "err", "connect: "+err.Error())
			os.Exit(1)
		}
		var res []any
		if sub == "bulk" {
			res = bulkRun(c, w, *down, *up, *chunk, *probe, *deadline)
		} else {
			res = rttRun(c, w, *n, *size, *stall)
		}
		emit(os.Stdout, res...)
		if res[1] != true {
			os.Exit(1)
		}
	case "stream":
		out := io.Writer(os.Stdout)
		if *logPath != "" {
			f, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			out = f
		}
		// a send blocked on credit (a suspended guest consumes nothing) must not outlast silence detection
		streamLoop(out, *addr, *name, *epochFile, *rate, *size, *silence, *keep, *keepMax, *win, min(*stall, *silence))
	default:
		fmt.Fprintln(os.Stderr, "unknown client command", sub)
		os.Exit(2)
	}
}

// streamLoop sends numbered messages at a fixed rate forever and records every outage:
// "down" (silence detected: sent/acked counters), "same_conn" (-keep: ACKs resumed on the old
// connection), "up" (new connection: the guest's last_seq tells which in-flight messages were
// delivered-but-unacked and which were lost and are now resent), "final" on SIGTERM.
func streamLoop(out io.Writer, addr, name, epochFile string, rate, size int, silence time.Duration, keep bool, keepMax time.Duration, win uint64, stall time.Duration) {
	var mu sync.Mutex
	var sentMax, ackedMax, nextSeq uint64 = 0, 0, 1
	var gen, downs, ups, sameConns, lostTotal, delUnackedTotal uint64
	recSeen := map[uint64]bool{}
	lastAck := time.Now()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	payload := make([]byte, size)
	final := func() {
		mu.Lock()
		emit(out, "ev", "final", "t", ts(), "sent_max", sentMax, "acked_max", ackedMax, "downs", downs, "ups", ups,
			"same_conn", sameConns, "lost_resent_total", lostTotal, "delivered_unacked_total", delUnackedTotal)
		mu.Unlock()
		os.Exit(0)
	}
	var downAt time.Time
	var downSent, downAcked uint64
	wasDown := false
	for {
		gen++
		var c *conn
		var w welcome
		var attempts int
		for c == nil {
			select {
			case <-sig:
				final()
			default:
			}
			var err error
			c, w, attempts, err = connect(addr, name, func() uint64 { return readEpoch(epochFile, 1) }, 2*time.Second, win, stall)
			if err != nil {
				c = nil
			}
		}
		mu.Lock()
		ups++
		L := w.LastSeq
		var lost, delUnacked uint64
		if wasDown {
			if downSent > L {
				lost = downSent - L
			}
			if L > downAcked {
				delUnacked = L - downAcked
			}
			lostTotal += lost
			delUnackedTotal += delUnacked
		}
		if L > ackedMax {
			ackedMax = L
		}
		nextSeq = L + 1
		lastAck = time.Now()
		ev := []any{"ev", "up", "t", ts(), "gen", gen, "attempts", attempts, "epoch", w.Epoch, "prev_epoch", w.PrevEpoch,
			"epoch_changes", w.EpochChanges, "guest_last_seq", L, "token", w.Token, "pid", w.Pid, "dups", w.Dups, "gaps", w.Gaps, "stale", w.Stale, "superseded", w.Superseded,
			"skew_s", float64(w.GuestNs)/1e9 - ts(), "stepped_s", float64(w.SteppedNs) / 1e9, "state", w.State, "resumes", w.Resumes}
		if wasDown {
			ev = append(ev, "down_for_s", time.Since(downAt).Seconds(), "inflight_at_down", downSent-downAcked,
				"lost_resent", lost, "delivered_unacked", delUnacked)
		}
		emit(out, ev...)
		if r := w.Resume; r != nil && !recSeen[r.N] { // a record whose frame this client missed
			recSeen[r.N] = true
			emit(out, append([]any{"ev", "resume", "t", ts(), "dup", false, "via", "welcome"}, recKV(r)...)...)
		}
		wasDown = false
		mu.Unlock()

		dead := make(chan struct{})
		go func(c *conn) {
			defer close(dead)
			for {
				f, err := c.recv()
				if err != nil {
					return
				}
				switch f.typ {
				case tAck:
					mu.Lock()
					if f.seq > ackedMax {
						ackedMax = f.seq
					}
					lastAck = time.Now()
					mu.Unlock()
				case tResumeRec: // the host side logs every resume record once (dup: already logged)
					var r guestagent.Record
					if json.Unmarshal(f.payload, &r) == nil {
						mu.Lock()
						dup := recSeen[r.N]
						recSeen[r.N] = true
						emit(out, append([]any{"ev", "resume", "t", ts(), "dup", dup}, recKV(&r)...)...)
						mu.Unlock()
					}
				}
			}
		}(c)
		tick := time.NewTicker(time.Second / time.Duration(rate))
		silent := false
		var silentAt time.Time
	run:
		for {
			select {
			case <-sig:
				c.rw.Close()
				final()
			case <-dead:
				mu.Lock()
				if !silent {
					downAt, downSent, downAcked, downs = time.Now(), sentMax, ackedMax, downs+1
					emit(out, "ev", "down", "t", ts(), "why", "conn_error", "sent_max", sentMax, "acked_max", ackedMax, "inflight", sentMax-ackedMax)
				}
				wasDown = true
				mu.Unlock()
				break run
			case <-tick.C:
				mu.Lock()
				outstanding := sentMax > ackedMax
				quiet := time.Since(lastAck)
				if silent && !outstanding {
					sameConns++
					emit(out, "ev", "same_conn", "t", ts(), "silent_for_s", time.Since(silentAt).Seconds(), "acked_max", ackedMax)
					silent = false
				}
				if !silent && outstanding && quiet > silence {
					downAt, downSent, downAcked, downs = time.Now(), sentMax, ackedMax, downs+1
					emit(out, "ev", "down", "t", ts(), "why", "silence", "sent_max", sentMax, "acked_max", ackedMax, "inflight", sentMax-ackedMax, "keep", keep)
					silent, silentAt = true, time.Now()
					if !keep {
						wasDown = true
						mu.Unlock()
						c.rw.Close()
						<-dead
						break run
					}
				}
				if silent && time.Since(silentAt) > keepMax {
					wasDown = true
					mu.Unlock()
					c.rw.Close()
					<-dead
					break run
				}
				if silent {
					mu.Unlock()
					continue
				}
				seq := nextSeq
				nextSeq++
				if seq > sentMax {
					sentMax = seq
				}
				mu.Unlock()
				if c.send(frame{typ: tMsg, seq: seq, payload: payload}) != nil {
					c.rw.Close()
				}
			}
		}
		tick.Stop()
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sr3j-chan agent|client ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "agent":
		agentMain(os.Args[2:])
	case "client":
		clientMain(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: sr3j-chan agent|client ...")
		os.Exit(2)
	}
}
