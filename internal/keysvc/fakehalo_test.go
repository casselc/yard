package keysvc

// A fake halo_serve: the admin routes the key service uses, served over a
// real Unix socket, with halo's rules ported from yard_keys.cpp / serve.cpp
// (halo-flash stream/spill-crypt, round 3, plus the round-4 revoke bound):
// token checks (RS256 against yard's JWKS, aud, iss, exp-iat <= 300, jti,
// yard_sess, yard_epoch, halo_spill), per-session durable epochs (highest,
// fence, last seal, last spill, last restore), slots with deadline
// min(token exp, first registration + TTL), one-shot op records (a repeat
// of a consumed registration answers "consumed"), the incarnation-bound
// entry id, 409s, and revoke bounded by the token epoch. Faults: a request
// dropped before it is applied, an answer lost after it was applied, a
// request held and applied later (late), and a halo restart.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"yard/internal/sts"
)

type fSlot struct {
	epoch         int64
	key           []byte
	hash          string
	name, entry   string
	op            string
	deadline, cap int64 // seconds
	reserved      bool
}

type fOp struct {
	use   string
	epoch int64
	hash  string
	entry string
	op    string
	state string // registered, consumed, expired, revoked
	cap   int64  // first registration + TTL
	keep  int64  // revoked: until when the cancellation is remembered (330 s)
}

type fSess struct {
	high                   int64
	fence, lastSeal        *int64
	lastSpill, lastRestore int64
	seal, open             *fSlot
	ops                    []fOp
}

type fEntry struct {
	key       uint64
	spilled   bool
	session   string
	keyID     string
	yardBound bool
}

// Fault for one request.
type Fault int

const (
	FNone       Fault = iota
	FDrop             // never applied, no answer
	FLoseAnswer       // applied, no answer
	FHold             // no answer now; applied when released (late)
)

type fakeHalo struct {
	t        *testing.T
	mu       sync.Mutex
	now      func() int64 // seconds
	jwks     func() sts.JWKS
	iss      string
	ttl      int64
	inc      string
	incN     int
	sessions map[string]*fSess
	jti      map[string]int64
	entries  map[uint64]*fEntry
	// bounded: round 4 (every revoke effect bounded by the token epoch)
	unbounded bool  // round 3: the default through is the last spill (uncapped), and no-R zeroes every key
	unscoped  bool  // every revoke zeroes every key of the session (spec/keys before round 4)
	fixBound  *bool // tests: overrides unbounded
	// round 5 mutants of halo (tests): weakCancel lets a cancellation lapse on a re-registration
	weakCancel bool
	stopped    bool // the provider stopped: registrations 503, no lease
	// fault picks a fault for a request (path, use); nil none
	fault func(path, use string) Fault
	held  []func()
	// log of applied registrations (use, epoch) per session
	regs []string
	srv  *http.Server
	path string
}

func newFakeHalo(t *testing.T, now func() int64, iss string, jwks func() sts.JWKS) *fakeHalo {
	f := &fakeHalo{t: t, now: now, jwks: jwks, iss: iss, ttl: 600, sessions: map[string]*fSess{},
		jti: map[string]int64{}, entries: map[uint64]*fEntry{}}
	f.restartLocked()
	dir, err := os.MkdirTemp("", "fh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.path = filepath.Join(dir, "admin.sock")
	l, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = &http.Server{Handler: f}
	go f.srv.Serve(l)
	t.Cleanup(func() { f.srv.Close() })
	return f
}

func (f *fakeHalo) restartLocked() {
	f.incN++
	f.inc = fmt.Sprintf("%016x", 0xa0+f.incN)
	f.jti = map[string]int64{}
	f.entries = map[uint64]*fEntry{} // the cache index is memory
	for _, s := range f.sessions {
		s.seal, s.open, s.ops = nil, nil, nil
	}
}

func (f *fakeHalo) setFault(g func(path, use string) Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = g
}

func (f *fakeHalo) set(g func(f *fakeHalo)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g(f)
}

func (f *fakeHalo) setUnscoped(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unscoped = v
}

func (f *fakeHalo) setUnbounded(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbounded = v
}

// Restart: keys, jtis and cache entries are gone; epochs kept.
func (f *fakeHalo) Restart() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restartLocked()
}

func (f *fakeHalo) AddEntry(key uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key] = &fEntry{key: key}
}

// Release applies the held (late) requests.
func (f *fakeHalo) Release() {
	f.mu.Lock()
	h := f.held
	f.held = nil
	f.mu.Unlock()
	for _, g := range h {
		g()
	}
}

func (f *fakeHalo) sess(s string) *fSess {
	x, ok := f.sessions[s]
	if !ok {
		x = &fSess{}
		f.sessions[s] = x
	}
	return x
}

// findOp: with op ids on both sides the op id decides; otherwise (use, epoch, key hash).
func findOp(s *fSess, use string, e int64, h, op string) *fOp {
	for i := range s.ops {
		r := &s.ops[i]
		if r.use != use {
			continue
		}
		if op != "" && r.op != "" {
			if r.op == op {
				return r
			}
		} else if r.epoch == e && r.hash == h {
			return r
		}
	}
	return nil
}

func (f *fakeHalo) record(s *fSess, use string, e int64, h, entry, op, st string) {
	now := f.now()
	r := findOp(s, use, e, h, op)
	if r == nil {
		s.ops = append(s.ops, fOp{use: use, epoch: e, hash: h, entry: entry, op: op, state: st, cap: now + f.ttl})
		return
	}
	if r.state != "consumed" && (r.state != "revoked" || now >= r.keep || f.weakCancel) { // final states never weaken while kept
		r.state = st
	}
	r.entry = entry
	if r.op == "" {
		r.op = op
	}
	if st == "revoked" {
		r.keep = now + 330
	}
}

func (f *fakeHalo) zero(s *fSess, slot **fSlot, use, why string) {
	if *slot == nil {
		return
	}
	f.record(s, use, (*slot).epoch, (*slot).hash, (*slot).entry, (*slot).op, why)
	clear((*slot).key)
	*slot = nil
}

func (f *fakeHalo) sweep() {
	now := f.now()
	for _, s := range f.sessions {
		if s.seal != nil && !s.seal.reserved && now >= s.seal.deadline {
			f.zero(s, &s.seal, "seal", "expired")
		}
		if s.open != nil && !s.open.reserved && now >= s.open.deadline {
			f.zero(s, &s.open, "open", "expired")
		}
	}
}

type ans struct {
	code int
	body string
}

func errAns(code int, msg string) ans {
	b, _ := json.Marshal(map[string]any{"ok": false, "error": msg})
	return ans{code, string(b)}
}

func keyIDEpoch(id string) (int64, bool) {
	if len(id) < 5 {
		return 0, false
	}
	i := strings.Index(id[5:], ":e") // after "yard:" (halo MayOpen: find(":e", 5))
	if i < 0 {
		return 0, false
	}
	i += 5
	j := strings.Index(id[i+2:], ":")
	if j < 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(id[i+2:i+2+j], 10, 64)
	return n, err == nil
}

func (f *fakeHalo) register(session string, body []byte) ans {
	var req struct {
		Token string `json:"token"`
		Use   string `json:"use"`
		Key   string `json:"key"`
	}
	if json.Unmarshal(body, &req) != nil {
		return errAns(400, "body must be a JSON object")
	}
	use := req.Use
	if use != "seal" && use != "open" && use != "revoke" {
		return errAns(400, "use must be seal, open or revoke")
	}
	var key []byte
	var hash string
	if use != "revoke" {
		k, err := b64u.DecodeString(req.Key)
		if err != nil || len(k) != 32 {
			return errAns(400, "key must be 32 bytes, base64url without padding")
		}
		key, hash = k, KeyHash(k)
	}
	now := f.now()
	claims, err := sts.Verify(req.Token, f.jwks(), sts.VerifyOptions{Issuer: f.iss, Audience: HaloAudience,
		MaxTTL: 300 * time.Second, Now: time.Unix(now, 0)})
	refuse := func(why string) ans {
		f.t.Logf("fake halo: token refused: %s", why)
		return errAns(401, "token refused")
	}
	if err != nil {
		return refuse(err.Error())
	}
	num := func(v any) (int64, bool) {
		n, ok := v.(json.Number)
		if !ok {
			return 0, false
		}
		x, err := n.Int64()
		return x, err == nil
	}
	if claims["yard_sess"] != session {
		return refuse("another session")
	}
	E, ok := num(claims["yard_epoch"])
	if !ok || E < 1 {
		return refuse("yard_epoch")
	}
	iat, _ := num(claims["iat"])
	exp, _ := num(claims["exp"])
	if exp-iat <= 0 || exp-iat > 300 {
		return refuse("lifetime")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return refuse("jti")
	}
	hs, _ := claims["halo_spill"].(map[string]any)
	if hs == nil || hs["use"] != use {
		return refuse("use not authorised")
	}
	if use != "revoke" && hs["key_sha256"] != hash {
		return refuse("bound to another key")
	}
	var entry string
	if use == "seal" {
		entry, _ = hs["entry"].(string)
		if entry == "" {
			return refuse("seal without an entry")
		}
	}
	var through *int64
	if use == "revoke" {
		if v, has := hs["through"]; has {
			n, ok := num(v)
			if !ok {
				return refuse("through")
			}
			through = &n
			if n < 1 {
				return refuse("through must be >= 1")
			}
		}
	}
	var op string
	if use != "revoke" {
		if v, has := hs["op"]; has {
			op, _ = v.(string)
			if op == "" || len(op) > 64 {
				return refuse("op")
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fixBound != nil {
		f.unbounded = *f.fixBound
	}
	if through != nil && *through > E && !f.unbounded {
		return refuse("revoke through a later epoch than the token's")
	}
	if f.stopped {
		return errAns(503, "key provider stopped (state durability uncertain): restart halo_serve")
	}
	f.sweep()
	for j, e := range f.jti {
		if e < now {
			delete(f.jti, j)
		}
	}
	if _, seen := f.jti[jti]; seen {
		return errAns(409, "token replayed (jti already used)")
	}
	if use == "seal" {
		pre := f.inc + "."
		if !strings.HasPrefix(entry, pre) {
			return errAns(409, "entry "+entry+" is not of this server incarnation ("+f.inc+"): read GET /admin/sessions again")
		}
	}
	s := f.sess(session)
	if use == "revoke" {
		// round 4/5: R = through, else min(last spill, T), none if nothing spilled; keys zeroed and
		// operations cancelled: registered at an epoch <= T, or whose file epoch is fenced
		T := E
		var R *int64
		switch {
		case through != nil:
			R = through
		case s.lastSpill > 0:
			r := s.lastSpill
			if !f.unbounded && E < r {
				r = E
			}
			R = &r
		}
		if R != nil {
			fence := *R
			if s.fence != nil && *s.fence > fence {
				fence = *s.fence
			}
			s.fence = &fence
			if s.lastSeal != nil && *s.lastSeal <= fence {
				s.lastSeal = nil
			}
			for k, en := range f.entries { // DropRevoked
				if e, ok := keyIDEpoch(en.keyID); ok && en.session == session && e <= fence {
					delete(f.entries, k)
				}
			}
		}
		hit := func(reg, file int64) bool {
			return f.unscoped || (f.unbounded && R == nil) || reg <= T || (s.fence != nil && file <= *s.fence)
		}
		if s.seal != nil && hit(s.seal.epoch, s.seal.epoch) {
			f.zero(s, &s.seal, "seal", "revoked")
		}
		if s.open != nil && hit(s.open.epoch, s.open.epoch-1) {
			f.zero(s, &s.open, "open", "revoked")
		}
		for i := range s.ops {
			r := &s.ops[i]
			file := r.epoch
			if r.use == "open" {
				file--
			}
			if (r.state == "registered" || r.state == "expired") && hit(r.epoch, file) {
				r.state, r.keep = "revoked", now+330
			}
		}
		if E > s.high {
			s.high = E
		}
		f.jti[jti] = exp
		f.regs = append(f.regs, fmt.Sprintf("%s revoke e%d", session, E))
		fe := "null"
		if s.fence != nil {
			fe = itoa(*s.fence)
		}
		return ans{200, `{"ok":true,"use":"revoke","epoch":` + itoa(E) + `,"through":` + fe + `}`}
	}
	fileEpoch := E
	if use == "open" {
		fileEpoch = E - 1
	}
	ok200 := func(state string) ans {
		return ans{200, fmt.Sprintf(`{"ok":true,"session":%q,"use":%q,"epoch":%d,"state":%q}`, session, use, E, state)}
	}
	if s.fence != nil && fileEpoch <= *s.fence {
		return errAns(409, fmt.Sprintf("revoked: epoch %d is fenced", fileEpoch))
	}
	if E < s.high {
		return errAns(409, fmt.Sprintf("stale epoch %d (session at %d)", E, s.high))
	}
	known := findOp(s, use, E, hash, op)
	if known != nil && (known.epoch != E || known.hash != hash) {
		return errAns(409, "operation id "+op+" already names another operation (key or epoch)")
	}
	if known != nil && known.state == "revoked" && now < known.keep && !f.weakCancel {
		return errAns(409, fmt.Sprintf("%s operation at epoch %d was cancelled by a revoke", use, E))
	}
	if known != nil && known.state == "expired" && now >= known.cap {
		return errAns(409, fmt.Sprintf("%s operation at epoch %d outlived its TTL: register a new operation (a new op id)", use, E))
	}
	if known != nil && known.state == "consumed" && (use == "open" || known.entry == entry) {
		f.jti[jti] = exp
		return ok200("consumed")
	}
	slot, other := &s.seal, &s.open
	otherUse := "open"
	if use == "open" {
		slot, other, otherUse = &s.open, &s.seal, "seal"
	}
	used := (use == "seal" && E <= s.lastSpill) || (use == "open" && E <= s.lastRestore)
	deadline := now + min(f.ttl, exp-now)
	if *slot != nil && (*slot).epoch == E && bytes.Equal((*slot).key, key) && (*slot).entry == entry && (*slot).op == op &&
		(!used || (*slot).reserved) {
		(*slot).deadline = min(max((*slot).deadline, deadline), (*slot).cap)
		f.jti[jti] = exp
		return ok200("registered")
	}
	if used {
		return errAns(409, fmt.Sprintf("%s at epoch %d was already used", use, E))
	}
	if use == "open" && (s.lastSeal == nil || E != *s.lastSeal+1) {
		return errAns(409, fmt.Sprintf("open at epoch %d is not right after a seal here", E))
	}
	if (*slot != nil && (*slot).reserved) || (*other != nil && (*other).reserved) {
		return errAns(409, "a spill or restore holds a key this registration would replace; retry")
	}
	if use == "seal" {
		for n, os := range f.sessions {
			if n != session && os.seal != nil && os.seal.entry == entry {
				return errAns(409, "entry "+entry+" has a seal registration of another session")
			}
		}
	}
	s.high = E
	if use == "seal" {
		e := E
		s.lastSeal = &e
	}
	f.zero(s, slot, use, "expired")
	f.zero(s, other, otherUse, "expired")
	cp := now + f.ttl
	if known != nil {
		cp = known.cap // the cap counts from the operation's first registration
	}
	*slot = &fSlot{epoch: E, key: append([]byte(nil), key...), hash: hash, name: KeyName(key), entry: entry, op: op,
		deadline: min(deadline, cp), cap: cp}
	f.record(s, use, E, hash, entry, op, "registered")
	f.jti[jti] = exp
	f.regs = append(f.regs, fmt.Sprintf("%s %s e%d", session, use, E))
	return ok200("registered")
}

func (f *fakeHalo) spill(key uint64) ans {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	if f.stopped {
		return errAns(409, "key provider stopped (state durability uncertain)")
	}
	en, ok := f.entries[key]
	if !ok {
		return errAns(409, "no such entry")
	}
	if en.spilled {
		return ans{200, `{"ok":true}`}
	}
	id := f.inc + "." + strconv.FormatUint(key, 10)
	for name, s := range f.sessions {
		if s.seal == nil || s.seal.entry != id {
			continue
		}
		if s.seal.epoch <= s.lastSpill || (s.fence != nil && s.seal.epoch <= *s.fence) {
			return errAns(409, "the seal registration's epoch was already used or is fenced")
		}
		s.lastSpill = s.seal.epoch
		en.spilled, en.session, en.yardBound = true, name, true
		en.keyID = FileKeyID(s.seal.key, s.seal.epoch, name)
		f.zero(s, &s.seal, "seal", "consumed")
		return ans{200, `{"ok":true}`}
	}
	return errAns(409, "yard-bound entry: a fresh seal registration is needed")
}

func (f *fakeHalo) restore(key uint64) ans {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	if f.stopped {
		return errAns(409, "key provider stopped (state durability uncertain)")
	}
	en, ok := f.entries[key]
	if !ok {
		return errAns(409, "no such entry")
	}
	if !en.spilled {
		return ans{200, `{"ok":true}`}
	}
	s := f.sess(en.session)
	fe, _ := keyIDEpoch(en.keyID)
	mayOpen := !(s.fence != nil && fe <= *s.fence) && fe >= s.lastRestore
	if s.open == nil {
		if !mayOpen {
			delete(f.entries, key)
		}
		return errAns(409, "no yard open key registered")
	}
	if s.open.epoch <= s.lastRestore || (s.fence != nil && s.open.epoch-1 <= *s.fence) ||
		FileKeyID(s.open.key, s.open.epoch-1, en.session) != en.keyID {
		if !mayOpen {
			delete(f.entries, key)
		}
		return errAns(409, "the registered open key is not this file's (key or epoch)")
	}
	s.lastRestore = s.open.epoch
	en.spilled = false
	f.zero(s, &s.open, "open", "consumed")
	return ans{200, `{"ok":true}`}
}

func (f *fakeHalo) keysJSON() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	var ss []map[string]any
	for name, s := range f.sessions {
		slot := func(x *fSlot) any {
			if x == nil {
				return nil
			}
			return map[string]any{"epoch": x.epoch, "key_name": x.name, "entry": x.entry, "in_use": x.reserved}
		}
		ss = append(ss, map[string]any{"session": name, "high_epoch": s.high, "revoked_through": s.fence,
			"sealed_epoch": s.lastSeal, "spilled_epoch": s.lastSpill, "restored_epoch": s.lastRestore,
			"seal": slot(s.seal), "open": slot(s.open)})
	}
	b, _ := json.Marshal(map[string]any{"incarnation": f.inc, "stopped": f.stopped, "sessions": ss})
	return string(b)
}

func (f *fakeHalo) sessionsJSON() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var es []map[string]any
	for k, e := range f.entries {
		es = append(es, map[string]any{"key": k, "spilled": e.spilled, "session": e.session, "key_id": e.keyID,
			"yard_bound": e.yardBound, "entry_id": f.inc + "." + strconv.FormatUint(k, 10), "file_bytes": 4096})
	}
	b, _ := json.Marshal(map[string]any{"sessions": es})
	return string(b)
}

func (f *fakeHalo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var a ans
	apply := func() ans {
		switch {
		case r.Method == "GET" && r.URL.Path == "/admin/keys":
			return ans{200, f.keysJSON()}
		case r.Method == "GET" && r.URL.Path == "/admin/sessions":
			return ans{200, f.sessionsJSON()}
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/admin/keys/"):
			return f.register(strings.TrimPrefix(r.URL.Path, "/admin/keys/"), body)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/admin/sessions/"):
			rest := strings.TrimPrefix(r.URL.Path, "/admin/sessions/")
			k, op, _ := strings.Cut(rest, "/")
			n, err := strconv.ParseUint(k, 10, 64)
			if err != nil {
				return errAns(404, "bad key")
			}
			if op == "spill" {
				return f.spill(n)
			}
			return f.restore(n)
		}
		return errAns(404, "no route")
	}
	fl := FNone
	f.mu.Lock()
	g := f.fault
	f.mu.Unlock()
	if g != nil && r.Method == "POST" {
		var u struct {
			Use string `json:"use"`
		}
		_ = json.Unmarshal(body, &u)
		fl = g(r.URL.Path, u.Use)
	}
	switch fl {
	case FNone:
		a = apply()
	case FLoseAnswer:
		apply()
		fallthrough
	case FDrop:
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
		return
	case FHold:
		f.mu.Lock()
		f.held = append(f.held, func() { apply() })
		f.mu.Unlock()
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.code)
	io.WriteString(w, a.body)
}

// helpers for assertions
func (f *fakeHalo) state(s string) fSess {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	return *f.sess(s)
}

func (f *fakeHalo) entry(k uint64) (fEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[k]
	if !ok {
		return fEntry{}, false
	}
	return *e, true
}

func (f *fakeHalo) holdsKey(k []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweep()
	for _, s := range f.sessions {
		for _, x := range []*fSlot{s.seal, s.open} {
			if x != nil && bytes.Equal(x.key, k) {
				return true
			}
		}
	}
	return false
}

var _ = hex.EncodeToString
var _ = sha256.Sum256
