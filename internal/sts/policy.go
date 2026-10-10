// Package sts implements the yard signer's claim policy, JWT minting and
// verification, and the write-ahead sequence log (CONTROL-PLANE §3.1).
//
// The signer takes structured claims only. It forces iss, caps exp-iat at
// 5 minutes, checks aud against an allowlist and sub against anchored
// patterns, checks the caller's uid, rate-limits per uid, and stamps a
// monotonic sequence number that yard must record in its hash chain.
package sts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

// HardMaxTTL is the absolute ceiling on exp-iat, whatever the policy file says.
const HardMaxTTL = 5 * time.Minute

// ReservedClaims may never be supplied by the caller.
var ReservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"nbf": true, "jti": true, "yard_seq": true,
}

// Policy is the on-disk policy (JSON). It is read before cap_enter.
type Policy struct {
	Issuer             string   `json:"iss"`
	Audiences          []string `json:"aud_allow"`
	SubPatterns        []string `json:"sub_patterns"`
	MaxTTLSeconds      int      `json:"max_ttl_s"`
	DefaultTTLSeconds  int      `json:"default_ttl_s"`
	AllowedUIDs        []uint32 `json:"allowed_uids"`
	RatePerSecond      float64  `json:"rate_per_s"`
	Burst              int      `json:"burst"`
	MaxExtraClaimBytes int      `json:"max_extra_claim_bytes"`
}

// Compiled is a validated policy ready for use.
type Compiled struct {
	P        Policy
	aud      map[string]bool
	subs     []*regexp.Regexp
	uids     map[uint32]bool
	maxTTL   time.Duration
	defTTL   time.Duration
	maxExtra int
}

// DefaultSubPattern is the SPIFFE shape from IDENTITY.md, authorizing parts first.
const DefaultSubPattern = `spiffe://home\.arpa/harness/[a-z0-9-]{1,63}/policy/[a-z0-9-]{1,63}/node/[a-z0-9-]{1,63}/sandbox/[a-z0-9-]{1,63}/run/[a-z0-9-]{1,63}`

// LoadPolicy reads and compiles a JSON policy file.
func LoadPolicy(path string) (*Compiled, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return Compile(p)
}

// Compile validates a policy. It refuses anything weaker than the hard limits.
func Compile(p Policy) (*Compiled, error) {
	if p.Issuer == "" {
		return nil, errors.New("policy: iss is required")
	}
	if len(p.Audiences) == 0 {
		return nil, errors.New("policy: aud_allow must not be empty")
	}
	if len(p.SubPatterns) == 0 {
		return nil, errors.New("policy: sub_patterns must not be empty")
	}
	if len(p.AllowedUIDs) == 0 {
		return nil, errors.New("policy: allowed_uids must not be empty")
	}
	c := &Compiled{P: p, aud: map[string]bool{}, uids: map[uint32]bool{}}
	for _, a := range p.Audiences {
		if a == "" {
			return nil, errors.New("policy: empty audience")
		}
		c.aud[a] = true
	}
	for _, s := range p.SubPatterns {
		re, err := regexp.Compile(`^(?:` + s + `)$`)
		if err != nil {
			return nil, fmt.Errorf("policy: sub pattern %q: %w", s, err)
		}
		c.subs = append(c.subs, re)
	}
	for _, u := range p.AllowedUIDs {
		c.uids[u] = true
	}
	c.maxTTL = time.Duration(p.MaxTTLSeconds) * time.Second
	if c.maxTTL <= 0 || c.maxTTL > HardMaxTTL {
		c.maxTTL = HardMaxTTL
	}
	c.defTTL = time.Duration(p.DefaultTTLSeconds) * time.Second
	if c.defTTL <= 0 || c.defTTL > c.maxTTL {
		c.defTTL = c.maxTTL
	}
	if p.RatePerSecond <= 0 {
		c.P.RatePerSecond = 2
	}
	if p.Burst <= 0 {
		c.P.Burst = 20
	}
	c.maxExtra = p.MaxExtraClaimBytes
	if c.maxExtra <= 0 {
		c.maxExtra = 4096
	}
	return c, nil
}

// Request is the only input the signer accepts: structured claims, never a
// pre-built payload.
type Request struct {
	Aud        string         `json:"aud"`
	Sub        string         `json:"sub"`
	TTLSeconds int            `json:"ttl_s,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
}

// Response is returned to the caller.
type Response struct {
	Token string `json:"token,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	Kid   string `json:"kid,omitempty"`
	Iat   int64  `json:"iat,omitempty"`
	Exp   int64  `json:"exp,omitempty"`
	Error string `json:"error,omitempty"`
}

// PolicyError is a refusal by policy (as opposed to an internal failure).
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "policy: " + e.Reason }

func deny(format string, a ...any) error { return &PolicyError{Reason: fmt.Sprintf(format, a...)} }

// Check validates a request for a given caller uid and returns the TTL to use.
func (c *Compiled) Check(uid uint32, r *Request) (time.Duration, error) {
	if !c.uids[uid] {
		return 0, deny("uid %d not allowed", uid)
	}
	if !c.aud[r.Aud] {
		return 0, deny("aud %q not in allowlist", r.Aud)
	}
	ok := false
	for _, re := range c.subs {
		if re.MatchString(r.Sub) {
			ok = true
			break
		}
	}
	if !ok {
		return 0, deny("sub %q matches no pattern", r.Sub)
	}
	ttl := time.Duration(r.TTLSeconds) * time.Second
	switch {
	case r.TTLSeconds < 0:
		return 0, deny("negative ttl")
	case r.TTLSeconds == 0:
		ttl = c.defTTL
	case ttl > c.maxTTL:
		return 0, deny("ttl %s exceeds max %s", ttl, c.maxTTL)
	}
	for k := range r.Claims {
		if ReservedClaims[k] {
			return 0, deny("claim %q is reserved", k)
		}
	}
	if len(r.Claims) > 0 {
		b, err := json.Marshal(r.Claims)
		if err != nil {
			return 0, deny("claims not serialisable: %v", err)
		}
		if len(b) > c.maxExtra {
			return 0, deny("extra claims %d bytes > %d", len(b), c.maxExtra)
		}
	}
	return ttl, nil
}
