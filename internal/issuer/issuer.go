package issuer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"sync"
	"time"

	"yard/internal/keyring"
	"yard/internal/sts"
)

// Kind selects the token shape.
type Kind string

const (
	External Kind = "external"
	Internal Kind = "internal"
)

// Config is the issuer policy.
type Config struct {
	Issuer      string // iss, e.g. https://id.example.org/yard
	TrustDomain string // SPIFFE trust domain, e.g. home.arpa
	// ExternalAudiences / InternalAudiences are the aud allowlists per kind.
	ExternalAudiences []string
	InternalAudiences []string
	MaxTTL            time.Duration // capped at sts.HardMaxTTL
	DefaultTTL        time.Duration
	RatePerSecond     float64 // per caller
	Burst             int
	// AWSSessionTags adds the https://aws.amazon.com/tags claim to external tokens.
	AWSSessionTags bool
}

// Request is a mint request after the frontend has authenticated the caller.
type Request struct {
	Kind     Kind           `json:"kind"`
	Audience string         `json:"aud"`
	Workload WorkloadID     `json:"workload"`
	User     string         `json:"user"`               // the human (tailnet login)
	Approval string         `json:"approval,omitempty"` // apv: approval grant id for elevated classes
	TTL      int            `json:"ttl_s,omitempty"`
	Extra    map[string]any `json:"claims,omitempty"` // non-reserved extra claims
}

// Caller is who asked (from the frontend, never from the request body).
type Caller struct {
	Name string // e.g. "uid:1001" or a tailnet node name
}

// Token is a minted token plus its audit facts.
type Token struct {
	Token string `json:"token"`
	Kid   string `json:"kid"`
	Seq   uint64 `json:"seq"`
	Jti   string `json:"jti"`
	Sub   string `json:"sub"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// PolicyError is a refusal (as opposed to an internal failure).
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "policy: " + e.Reason }

func deny(f string, a ...any) error { return &PolicyError{fmt.Sprintf(f, a...)} }

// Issuer mints tokens. It is safe for concurrent use.
type Issuer struct {
	cfg    Config
	ext    map[string]bool
	int_   map[string]bool
	ring   *keyring.Ring
	seq    *sts.SeqLog
	lim    *sts.Limiter
	now    func() time.Time
	mu     sync.Mutex // serialises seq reservation + signing
	broken error
}

var (
	userRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)
	apvRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// New validates cfg and builds an issuer.
func New(cfg Config, ring *keyring.Ring, seq *sts.SeqLog, now func() time.Time) (*Issuer, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.Issuer == "" {
		return nil, errors.New("issuer: Issuer is required")
	}
	if !ValidTrustDomain(cfg.TrustDomain) {
		return nil, fmt.Errorf("issuer: bad trust domain %q", cfg.TrustDomain)
	}
	if cfg.MaxTTL <= 0 || cfg.MaxTTL > sts.HardMaxTTL {
		cfg.MaxTTL = sts.HardMaxTTL
	}
	if cfg.DefaultTTL <= 0 || cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if cfg.RatePerSecond <= 0 {
		cfg.RatePerSecond = 2
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 20
	}
	is := &Issuer{cfg: cfg, ext: map[string]bool{}, int_: map[string]bool{}, ring: ring, seq: seq,
		lim: sts.NewLimiter(cfg.RatePerSecond, cfg.Burst, now), now: now}
	for _, a := range cfg.ExternalAudiences {
		is.ext[a] = true
	}
	for _, a := range cfg.InternalAudiences {
		if is.ext[a] {
			return nil, fmt.Errorf("issuer: audience %q is both external and internal", a)
		}
		is.int_[a] = true
	}
	if len(is.ext)+len(is.int_) == 0 {
		return nil, errors.New("issuer: no audiences allowed")
	}
	return is, nil
}

// Config returns the effective configuration.
func (is *Issuer) Config() Config { return is.cfg }

// ErrBroken means the sequence log failed; minting stays off until restart.
var ErrBroken = errors.New("issuer: sequence log failed earlier; refusing to mint")

func (is *Issuer) check(r *Request) (time.Duration, error) {
	switch r.Kind {
	case External:
		if !is.ext[r.Audience] {
			return 0, deny("aud %q not an allowed external audience", r.Audience)
		}
	case Internal:
		if !is.int_[r.Audience] {
			return 0, deny("aud %q not an allowed internal audience", r.Audience)
		}
	default:
		return 0, deny("kind %q (want external|internal)", r.Kind)
	}
	if err := r.Workload.Validate(); err != nil {
		return 0, deny("%v", err)
	}
	if !userRe.MatchString(r.User) {
		return 0, deny("user %q", r.User)
	}
	if r.Approval != "" && !apvRe.MatchString(r.Approval) {
		return 0, deny("approval %q", r.Approval)
	}
	ttl := time.Duration(r.TTL) * time.Second
	switch {
	case r.TTL < 0:
		return 0, deny("negative ttl")
	case r.TTL == 0:
		ttl = is.cfg.DefaultTTL
	case ttl > is.cfg.MaxTTL:
		return 0, deny("ttl %s exceeds max %s", ttl, is.cfg.MaxTTL)
	}
	for k := range r.Extra {
		if sts.ReservedClaims[k] || reserved[k] {
			return 0, deny("claim %q is reserved", k)
		}
	}
	return ttl, nil
}

var reserved = map[string]bool{"act": true, "apv": true, "yard_wid": true, "yard_user": true, "yard_kind": true,
	"https://aws.amazon.com/tags": true}

// Claims builds the claim set for r (without iat/exp/jti/seq).
func (is *Issuer) Claims(r *Request) map[string]any {
	c := make(map[string]any, len(r.Extra)+12)
	for k, v := range r.Extra {
		c[k] = v
	}
	wid := r.Workload.SPIFFE(is.cfg.TrustDomain)
	c["iss"] = is.cfg.Issuer
	c["aud"] = r.Audience
	c["yard_kind"] = string(r.Kind)
	switch r.Kind {
	case External:
		c["sub"] = r.Workload.PolicySubject(is.cfg.TrustDomain)
		c["yard_wid"] = wid
		c["yard_user"] = r.User
		if is.cfg.AWSSessionTags {
			c["https://aws.amazon.com/tags"] = map[string]any{
				"principal_tags": map[string][]string{
					"yard-user":    {r.User},
					"yard-harness": {r.Workload.Harness},
					"yard-policy":  {r.Workload.Policy},
					"yard-node":    {r.Workload.Node},
					"yard-sandbox": {r.Workload.Sandbox},
					"yard-run":     {r.Workload.Run},
				},
				"transitive_tag_keys": []string{"yard-user", "yard-sandbox", "yard-run"},
			}
		}
	case Internal:
		c["sub"] = r.User
		c["act"] = map[string]any{"sub": wid}
	}
	if r.Approval != "" {
		c["apv"] = r.Approval
	}
	return c
}

func callerKey(c Caller) uint32 {
	h := fnv.New32a()
	h.Write([]byte(c.Name))
	return h.Sum32()
}

// Mint checks policy, reserves a sequence number (write-ahead, fsynced) and
// signs with the active key.
func (is *Issuer) Mint(c Caller, r *Request) (*Token, error) {
	ttl, err := is.check(r)
	if err != nil {
		return nil, err
	}
	if !is.lim.Allow(callerKey(c)) {
		return nil, deny("rate limit for %s", c.Name)
	}
	var jb [16]byte
	if _, err := rand.Read(jb[:]); err != nil {
		return nil, err
	}
	jti := hex.EncodeToString(jb[:])
	claims := is.Claims(r)

	is.mu.Lock()
	defer is.mu.Unlock()
	if is.broken != nil {
		return nil, ErrBroken
	}
	var out *Token
	err = is.ring.WithActive(func(k sts.KeySigner, kid string) error {
		now := is.now()
		iat, exp := now.Unix(), now.Add(ttl).Unix()
		sub := claims["sub"].(string)
		seq, err := is.seq.Reserve(sts.SeqRecord{Iat: iat, Exp: exp, Aud: r.Audience, Sub: sub, Jti: jti, Kid: kid})
		if err != nil {
			is.broken = err
			return fmt.Errorf("%w: %v", ErrBroken, err)
		}
		claims["iat"], claims["nbf"], claims["exp"], claims["jti"], claims["yard_seq"] = iat, iat, exp, jti, seq
		tok, err := sts.SignJWT(k, kid, claims)
		if err != nil {
			if e2 := is.seq.MarkFailed(seq, 0); e2 != nil {
				is.broken = e2
			}
			return err
		}
		out = &Token{Token: tok, Kid: kid, Seq: seq, Jti: jti, Sub: sub, Iat: iat, Exp: exp}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
