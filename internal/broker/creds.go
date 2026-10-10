package broker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"yard/internal/issuer"
)

// Credential is a short-lived cloud credential minted for one sandbox.
type Credential struct {
	AccessKeyID     string // not secret (links to CloudTrail)
	SecretAccessKey Secret
	SessionToken    Secret
	Expiration      time.Time // the real expiry
	Epoch           uint64    // the SR0 credential epoch it was minted under
	MintID          string    // the per-mint tag (yard-mint) the broker asked for
	RoleARN         string
}

// MintRequest asks for one credential. MintID is fresh for every attempt
// and is carried as the session's yard-mint tag (WARDEN.md decision 15), so
// the CloudTrail reconciler can match or revoke exactly this mint.
//
// Begin is the store's slot-ownership gate. The minter calls it once,
// after it holds the STS JWT and before anything is sent to the cloud STS,
// with the JWT's exp. If Begin returns false the minter must not send and
// returns ErrNotSent. From a true Begin on, the attempt's outcome is
// unknown until an answer, and the store fences it at exp + skew.
type MintRequest struct {
	Principal string
	Workload  issuer.WorkloadID
	Epoch     uint64
	MintID    string
	Begin     func(jwtExp time.Time) bool
}

// Minter mints credentials: in B1 the yard-ctl STS JWT exchanged by
// AssumeRoleWithWebIdentity (the broker's call, decision 8); a fake in B0.
//
// Contract: honour ctx (the store cancels it when it settles the attempt);
// call Begin before any cloud request and never retry the exchange (SDK
// retries off, D6); return ErrNoGrant, ErrNotSent or a *RetryLaterError
// only when nothing reached the cloud STS.
type Minter interface {
	Mint(ctx context.Context, req MintRequest) (Credential, error)
}

var (
	// ErrNoGrant: no mintable grant for this sandbox (nothing sent).
	ErrNoGrant = errors.New("no mintable grant")
	// ErrNotSent: Begin refused or the minter failed before sending.
	ErrNotSent = errors.New("mint not sent")
)

// RetryLaterError: the control plane refuses this slot (yard-ctl signs at
// most one JWT per (grant, slot); spec/warden D7), so nothing was sent; ask
// again at At.
type RetryLaterError struct{ At time.Time }

func (e *RetryLaterError) Error() string {
	return "mint slot spent; retry at " + e.At.UTC().Format(time.RFC3339)
}

// MetadataConfig holds the credential endpoint's timing rules (WARDEN.md
// §2.3 and §4 step 8, spec/warden).
type MetadataConfig struct {
	RoleName string // IMDS role name the SDK sees (default "yard-task")
	ECSPath  string // AWS_CONTAINER_CREDENTIALS_FULL_URI path on 169.254.170.2 (default "/creds")
	// AdvertiseMax: the advertised Expiration is min(real, now+AdvertiseMax),
	// so cooperative SDKs re-fetch often (default 5m). It does not shorten
	// what AWS accepts.
	AdvertiseMax time.Duration
	// RefreshBefore: start a new mint when the held credential has less than
	// this left (default 5m).
	RefreshBefore time.Duration
	// ServeMargin: never serve a credential with less than this left (default 1m).
	ServeMargin time.Duration
	// MaxCredTTL: a credential expiring later than its Begin time plus this
	// is refused (AWS sessions are 900 s; default 15m + 1m skew).
	MaxCredTTL time.Duration
	// MaxJWTLifetime: Begin refuses a JWT whose exp is later than now plus
	// this plus Skew (the yard-ctl signer forces <= 5 min; default 5m).
	MaxJWTLifetime time.Duration
	// Skew: allowance between our clock and the cloud STS's (default 30s).
	// The fence of a sent attempt is jwtExp + Skew.
	Skew time.Duration
	// PrepareTimeout: an attempt that has not called Begin by then is settled
	// as not done, and a later Begin is refused (default 30s).
	PrepareTimeout time.Duration
	// MintWait: how long a metadata request waits for a mint in flight before
	// answering 503 (the SDK polls again) (default 5s).
	MintWait time.Duration
	// TokenMaxTTL bounds IMDSv2 token lifetimes (AWS: 21600 s).
	TokenMaxTTL time.Duration
	// MaxIdleSlots bounds credential slots of principals no longer linked.
	MaxIdleSlots int
	// MaxWorkers bounds mint goroutines, including settled ones whose minter
	// has not returned (default 16).
	MaxWorkers int
}

func (m *MetadataConfig) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if m.RoleName == "" {
		m.RoleName = "yard-task"
	}
	if m.ECSPath == "" {
		m.ECSPath = "/creds"
	}
	def(&m.AdvertiseMax, 5*time.Minute)
	def(&m.RefreshBefore, 5*time.Minute)
	def(&m.ServeMargin, time.Minute)
	def(&m.MaxCredTTL, 16*time.Minute)
	def(&m.MaxJWTLifetime, 5*time.Minute)
	def(&m.Skew, 30*time.Second)
	def(&m.PrepareTimeout, 30*time.Second)
	def(&m.MintWait, 5*time.Second)
	def(&m.TokenMaxTTL, 6*time.Hour)
	if m.MaxIdleSlots <= 0 {
		m.MaxIdleSlots = 256
	}
	if m.MaxWorkers <= 0 {
		m.MaxWorkers = 16
	}
}

// credStore is the single linearization point for credential state: the
// binding Sync publishes (incarnation, epoch, authorization generation,
// live), the held credential, the mint in flight, revocation, and the
// commit of a credential response all change or are checked under mu.
// Audit callbacks run after mu is released. authOK (the broker's lease
// check for an authorization generation) may be called under mu; it never
// takes mu.
type credStore struct {
	cfg    MetadataConfig
	minter Minter
	now    func() time.Time
	audit  func(AuditEvent)
	count  *Counters
	authOK func(gen uint64) bool

	ctx     context.Context // broker lifetime
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	workers int // mint goroutines still running, settled or not (mu)

	mu     sync.Mutex
	slots  map[string]*credSlot
	closed bool
}

type credSlot struct {
	live      bool   // linked in the current authorization
	inc       string // the allocation it is bound to
	epoch     uint64
	authGen   uint64 // the authorization generation that bound it
	gen       uint64 // bumped by every fence: rebind, unbind, revoke, expiry
	cur       *Credential
	inflight  *mintAttempt
	holdUntil time.Time // no new mint before this (unknown outcome, retry-later)
}

type mintAttempt struct {
	done    chan struct{}
	gen     uint64
	epoch   uint64
	inc     string
	start   time.Time
	mintID  string
	began   bool
	beganAt time.Time
	fence   time.Time // jwtExp + Skew once begun
	settled bool
	cancel  context.CancelFunc
	timer   *time.Timer
}

// deadline is the attempt's authoritative bound (the timer is only a wake-up).
func (a *mintAttempt) deadline(cfg MetadataConfig) time.Time {
	if a.began {
		return a.fence
	}
	return a.start.Add(cfg.PrepareTimeout)
}

// testHookBeforeCommit runs (outside mu) between credential selection and
// the commit of the response (tests).
var testHookBeforeCommit atomic.Pointer[func()]

// maxCredResponse bounds a rendered credential response.
const maxCredResponse = 16 << 10

func newCredStore(cfg MetadataConfig, m Minter, now func() time.Time, audit func(AuditEvent), count *Counters) *credStore {
	ctx, cancel := context.WithCancel(context.Background())
	return &credStore{cfg: cfg, minter: m, now: now, audit: audit, count: count, ctx: ctx, cancel: cancel,
		slots: map[string]*credSlot{}, authOK: func(uint64) bool { return true }}
}

func newMintID() string {
	var b [12]byte
	randBytes(b[:])
	return "m-" + hex.EncodeToString(b[:])
}

func (s *credStore) emit(evs []AuditEvent) {
	for _, e := range evs {
		s.audit(e)
	}
}

// slot returns the principal's slot (caller holds mu), evicting quiescent
// unlinked slots beyond the bound. A slot with a mint in flight, a held
// credential or an unexpired hold is never evicted (its fence would go).
func (s *credStore) slot(p string) *credSlot {
	sl := s.slots[p]
	if sl != nil {
		return sl
	}
	if len(s.slots) >= s.cfg.MaxIdleSlots {
		now := s.now()
		for k, v := range s.slots {
			if !v.live && v.inflight == nil && v.cur == nil && !now.Before(v.holdUntil) { // MUTANT:evictBusySlot
				delete(s.slots, k)
				s.count.Add("cred_slot_evicted")
			}
		}
	}
	sl = &credSlot{}
	s.slots[p] = sl
	return sl
}

// fence drops the held credential and fences every mint in flight (caller holds mu).
func (s *credStore) fence(sl *credSlot, why string) {
	sl.gen++
	if sl.cur != nil {
		s.count.Add("cred_dropped_" + why)
	}
	sl.cur = nil // MUTANT:revokeKeepsCred
}

// bind publishes the principal's allocation and epoch under authorization
// generation authGen. A change of allocation or epoch fences the slot; a
// new generation alone re-labels it. Called by Sync BEFORE the new links
// are published (the new generation is not valid until then).
func (s *credStore) bind(principal, inc string, epoch, authGen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl := s.slot(principal)
	if !sl.live || sl.inc != inc || sl.epoch != epoch {
		why := "epoch"
		if sl.inc != inc {
			why = "incarnation"
		}
		s.fence(sl, why)
		sl.inc, sl.epoch = inc, epoch
	}
	sl.live, sl.authGen = true, authGen
}

// unbind: the principal is no longer linked.
func (s *credStore) unbind(principal, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl := s.slots[principal]; sl != nil && sl.live {
		sl.live = false
		s.fence(sl, why)
	}
}

// expireGen fences only the slots bound under authorization generation gen
// (a lease that expired); slots already rebound under a newer generation
// are not touched.
func (s *credStore) expireGen(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sl := range s.slots {
		if sl.live && sl.authGen == gen { // MUTANT:expiryFencesAll
			sl.live = false
			s.fence(sl, "lease_expired")
		}
	}
}

// revoke fences the principal's slot. Once it returns, no credential
// response of an older generation is committed (rendered for writing); a
// response committed before it may still be written to the sandbox, and a
// credential already delivered stays valid at AWS until its real expiry
// (spec/broker B7).
func (s *credStore) revoke(principal string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl := s.slots[principal]; sl != nil {
		s.fence(sl, "revoke")
	}
}

var (
	errCredUnavailable = errors.New("credential not available yet")
	errStale           = errors.New("request's link incarnation, epoch or authorization is no longer current")
)

type credTicket struct {
	gen uint64
	c   *Credential
	// retryAt is when asking again may help (a hold); zero: soon.
	retryAt time.Time
}

// current: the slot is bound to this allocation and epoch under a valid
// authorization generation (caller holds mu).
func (s *credStore) current(sl *credSlot, inc string, epoch uint64) bool {
	return sl.live && sl.inc == inc && sl.epoch == epoch && s.authOK(sl.authGen) // MUTANT:staleRequestServed
}

// get returns a credential for the request's allocation and epoch, starting
// a mint if none is held or the held one needs refreshing. A request whose
// allocation, epoch or authorization is no longer current fails without
// touching the slot.
func (s *credStore) get(ctx context.Context, l Link, principal string) (credTicket, error) {
	deadline := time.NewTimer(s.cfg.MintWait)
	defer deadline.Stop()
	for waited := false; ; waited = true {
		var evs []AuditEvent
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return credTicket{}, errCredUnavailable
		}
		sl := s.slot(principal)
		if !s.current(sl, l.Incarnation, l.Epoch) {
			s.mu.Unlock()
			return credTicket{}, errStale
		}
		now := s.now()
		var have *Credential
		if sl.cur != nil && now.Before(sl.cur.Expiration.Add(-s.cfg.ServeMargin)) {
			have = sl.cur
		}
		needMint := have == nil || sl.cur.Expiration.Sub(now) < s.cfg.RefreshBefore
		if needMint && sl.inflight == nil && !now.Before(sl.holdUntil) && !waited {
			evs = s.start(sl, l, principal, now)
		}
		var wait chan struct{}
		if sl.inflight != nil {
			wait = sl.inflight.done
		}
		t := credTicket{gen: sl.gen, c: have, retryAt: sl.holdUntil}
		s.mu.Unlock()
		s.emit(evs)
		if have != nil {
			return t, nil
		}
		if wait == nil || waited {
			return t, errCredUnavailable
		}
		select {
		case <-wait:
		case <-deadline.C:
			return t, errCredUnavailable
		case <-ctx.Done():
			return credTicket{}, ctx.Err()
		}
	}
}

// commit is the linearization point of a credential response: it renders
// the response into a request-local buffer only if the allocation, the
// epoch, the authorization, the generation and the held credential are all
// still the ones selected and the credential is still servable. The caller
// writes the buffer after commit returns (no I/O under mu): a revoke fences
// the commit, not the delivery of an already committed response.
func (s *credStore) commit(l Link, principal string, t credTicket, render func(Credential) ([]byte, error)) ([]byte, string) {
	if h := testHookBeforeCommit.Load(); h != nil {
		(*h)()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sl := s.slots[principal]
	if sl == nil || !s.current(sl, l.Incarnation, l.Epoch) || sl.gen != t.gen || sl.cur != t.c || // MUTANT:commitUnchecked
		!s.now().Before(t.c.Expiration.Add(-s.cfg.ServeMargin)) {
		s.count.Add("cred_commit_fenced")
		return nil, "credential_fenced"
	}
	b, err := render(*t.c)
	if err != nil || len(b) > maxCredResponse { // MUTANT:renderUnbounded
		s.count.Add("cred_commit_oversize")
		return nil, "credential_oversize"
	}
	return b, ""
}

// start launches one mint (caller holds mu). The store owns the attempt's
// deadline: PrepareTimeout until Begin, then the fence jwtExp + Skew.
// finish and begin check that deadline themselves under mu; the timer only
// wakes the store when the minter is silent. At most MaxWorkers mint
// goroutines may exist (settled-but-unreturned ones included).
func (s *credStore) start(sl *credSlot, l Link, principal string, now time.Time) []AuditEvent {
	if s.workers >= s.cfg.MaxWorkers { // MUTANT:workersUnbounded
		s.count.Add("mint_workers_exhausted")
		return nil
	}
	s.workers++
	ctx, cancel := context.WithCancel(s.ctx)
	a := &mintAttempt{done: make(chan struct{}), gen: sl.gen, epoch: l.Epoch, inc: l.Incarnation, start: now,
		mintID: newMintID(), cancel: cancel}
	sl.inflight = a
	req := MintRequest{Principal: principal, Workload: l.Workload, Epoch: l.Epoch, MintID: a.mintID,
		Begin: func(exp time.Time) bool { return s.begin(sl, a, exp) }}
	a.timer = time.AfterFunc(s.cfg.PrepareTimeout, func() { s.deadlineFired(sl, a, principal) })
	s.count.Add("mint_started")
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		c, err := s.minter.Mint(ctx, req)
		s.finish(sl, a, principal, c, err)
	}()
	return nil
}

func (s *credStore) begin(sl *credSlot, a *mintAttempt, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	switch {
	case a.settled || a.began || a.gen != sl.gen || s.closed || !s.authOK(sl.authGen):
		return false
	case !now.Before(a.start.Add(s.cfg.PrepareTimeout)): // MUTANT:prepareDeadlineUnchecked
		return false
	case !exp.After(now) || exp.After(now.Add(s.cfg.MaxJWTLifetime+s.cfg.Skew)):
		s.count.Add("mint_begin_bad_exp")
		return false
	}
	a.began, a.beganAt = true, now
	a.fence = exp.Add(s.cfg.Skew) // MUTANT:fenceIgnoresJWT
	a.timer.Reset(a.fence.Sub(now))
	s.count.Add("mint_sent")
	return true
}

// timeout settles an attempt past its deadline (caller holds mu).
func (s *credStore) timeout(sl *credSlot, a *mintAttempt, principal string) AuditEvent {
	ev := s.settle(sl, a, principal)
	if a.began {
		ev.Outcome, ev.Reason, ev.Detail = "unknown", "mint_unknown", "no_answer_by_fence"
		s.count.Add("mint_unknown")
		if a.fence.After(sl.holdUntil) {
			sl.holdUntil = a.fence
		}
	} else {
		ev.Outcome, ev.Reason, ev.Detail = "not_done", "mint_not_sent", "prepare_timeout"
		s.count.Add("mint_not_done")
	}
	return ev
}

// deadlineFired is the timer's wake-up.
func (s *credStore) deadlineFired(sl *credSlot, a *mintAttempt, principal string) {
	s.mu.Lock()
	if a.settled {
		s.mu.Unlock()
		return
	}
	if now := s.now(); now.Before(a.deadline(s.cfg)) {
		a.timer.Reset(a.deadline(s.cfg).Sub(now)) // armed for an older bound before Begin moved it
		s.mu.Unlock()
		return
	}
	ev := s.timeout(sl, a, principal)
	s.mu.Unlock()
	s.audit(ev)
}

// settle marks the attempt finished (caller holds mu).
func (s *credStore) settle(sl *credSlot, a *mintAttempt, principal string) AuditEvent {
	a.settled = true
	a.timer.Stop()
	a.cancel()
	if sl.inflight == a {
		sl.inflight = nil
	}
	close(a.done)
	now := s.now()
	return AuditEvent{Time: now, Kind: "mint", Decision: "deny", Principal: principal, MintID: a.mintID, Epoch: a.epoch,
		Millis: now.Sub(a.start).Milliseconds()}
}

func (s *credStore) finish(sl *credSlot, a *mintAttempt, principal string, c Credential, err error) {
	s.mu.Lock()
	s.workers--
	var evs []AuditEvent
	if !a.settled && !s.now().Before(a.deadline(s.cfg)) { // MUTANT:finishTrustsTimer
		// the deadline passed before this answer took the lock: the timer
		// has not run yet, but the attempt is over all the same
		evs = append(evs, s.timeout(sl, a, principal))
	}
	if a.settled {
		// past the attempt's deadline: never adopted. A credential minted
		// this late is an orphan for the CloudTrail reconciler (yard-mint tag).
		s.count.Add("mint_late_discarded")
		s.mu.Unlock()
		s.emit(evs)
		s.audit(AuditEvent{Time: s.now(), Kind: "mint", Decision: "deny", Principal: principal, MintID: a.mintID,
			Epoch: a.epoch, Outcome: "unknown", Reason: "late_answer_discarded", AccessKey: c.AccessKeyID})
		return
	}
	ev := s.settle(sl, a, principal)
	var rl *RetryLaterError
	switch {
	case err == nil:
		ev.AccessKey = c.AccessKeyID
		if reason := s.refuse(sl, a, c); reason != "" {
			ev.Outcome, ev.Reason = "done", reason
			s.count.Add("mint_refused_" + reason)
			break
		}
		ev.Decision, ev.Outcome = "allow", "done"
		s.count.Add("mint_done")
		if sl.cur == nil || c.Expiration.After(sl.cur.Expiration) {
			cc := c
			sl.cur = &cc
		}
	case errors.As(err, &rl):
		ev.Outcome, ev.Reason = "not_done", "slot_spent"
		if rl.At.After(sl.holdUntil) {
			sl.holdUntil = rl.At
		}
		s.count.Add("mint_not_done")
	case !a.began || errors.Is(err, ErrNoGrant) || errors.Is(err, ErrNotSent):
		// nothing reached the cloud STS
		ev.Outcome, ev.Reason = "not_done", "no_grant"
		if !errors.Is(err, ErrNoGrant) {
			ev.Reason = "mint_not_sent"
		}
		s.count.Add("mint_not_done")
	default:
		// Unknown: the JWT may have been exchanged and the answer lost. Never
		// re-send; no new mint before the fence (jwtExp + skew), after which
		// the cloud refuses the JWT. An exchange accepted just before exp may
		// still have minted: that orphan is the reconciler's (yard-mint tag).
		ev.Outcome, ev.Reason, ev.Detail = "unknown", "mint_unknown", "error"
		s.count.Add("mint_unknown")
		if a.fence.After(sl.holdUntil) {
			sl.holdUntil = a.fence // MUTANT:blindRetry
		}
	}
	s.mu.Unlock()
	s.audit(ev)
}

// refuse checks a minted credential against the rules (caller holds mu).
func (s *credStore) refuse(sl *credSlot, a *mintAttempt, c Credential) string {
	switch {
	case a.gen != sl.gen:
		return "fenced" // revoked, rebound, unbound or expired while in flight
	case !sl.live || sl.inc != a.inc:
		return "link_gone"
	case !s.authOK(sl.authGen):
		return "auth_expired"
	case c.Epoch != a.epoch || c.Epoch != sl.epoch: // MUTANT:staleEpoch
		return "stale_epoch"
	case !a.began:
		return "not_begun"
	case c.MintID != a.mintID:
		return "mint_tag"
	case c.AccessKeyID == "" || c.SecretAccessKey.Empty() || c.SessionToken.Empty():
		return "incomplete"
	case c.Expiration.After(a.beganAt.Add(s.cfg.MaxCredTTL)): // MUTANT:ttlUnbounded
		return "ttl_bound"
	case !s.now().Before(c.Expiration.Add(-s.cfg.ServeMargin)):
		return "expired"
	}
	return ""
}

// advertised is the Expiration handed to the SDK.
func (s *credStore) advertised(c Credential) time.Time {
	adv := s.now().Add(s.cfg.AdvertiseMax)
	if c.Expiration.Before(adv) {
		adv = c.Expiration
	}
	return adv.UTC().Truncate(time.Second) // MUTANT:advertiseReal
}

// close settles every attempt, cancels the minters and waits for them (at
// most bound); a minter that ignores cancellation is reported.
func (s *credStore) close(bound time.Duration) error {
	s.mu.Lock()
	s.closed = true
	var evs []AuditEvent
	for p, sl := range s.slots {
		if a := sl.inflight; a != nil && !a.settled {
			ev := s.settle(sl, a, p)
			ev.Outcome, ev.Reason = "unknown", "broker_closed"
			if !a.began {
				ev.Outcome = "not_done"
			}
			evs = append(evs, ev)
		}
	}
	s.mu.Unlock()
	s.cancel()
	s.emit(evs)
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(bound):
		return fmt.Errorf("mint workers still running %v after close (a minter ignores cancellation)", bound)
	}
}

// imdsTokens are IMDSv2 session tokens, each bound to the link allocation
// (incarnation) it was issued on.
type imdsTokens struct {
	mu  sync.Mutex
	m   map[string]imdsToken
	now func() time.Time
}

type imdsToken struct {
	inc string
	exp time.Time
}

const maxTokensPerLink = 64

func (t *imdsTokens) issue(inc string, ttl time.Duration) string {
	var b [24]byte
	randBytes(b[:])
	tok := hex.EncodeToString(b[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	n := 0
	var oldest string
	var oldestExp time.Time
	for k, v := range t.m {
		if !now.Before(v.exp) {
			delete(t.m, k)
			continue
		}
		if v.inc == inc {
			n++
			if oldest == "" || v.exp.Before(oldestExp) {
				oldest, oldestExp = k, v.exp
			}
		}
	}
	if n >= maxTokensPerLink {
		delete(t.m, oldest)
	}
	t.m[tok] = imdsToken{inc: inc, exp: now.Add(ttl)}
	return tok
}

func (t *imdsTokens) valid(inc, tok string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tok]
	if !ok || !t.now().Before(v.exp) {
		return false
	}
	if v.inc != inc { // MUTANT:imdsTokenUnbound
		return false
	}
	return true
}

// retire forgets every token of an allocation.
func (t *imdsTokens) retire(inc string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if v.inc == inc {
			delete(t.m, k)
		}
	}
}
