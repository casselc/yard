package sts

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Minter applies the policy, reserves a sequence number and signs.
type Minter struct {
	mu     sync.Mutex
	pol    *Compiled
	key    KeySigner
	kid    string
	seq    *SeqLog
	lim    *Limiter
	now    func() time.Time
	broken error // set when the seq log fails: mint fails closed forever
}

// NewMinter builds a minter. now may be nil (time.Now).
func NewMinter(pol *Compiled, key KeySigner, seq *SeqLog, now func() time.Time) *Minter {
	if now == nil {
		now = time.Now
	}
	return &Minter{pol: pol, key: key, kid: Thumbprint(key.Public()), seq: seq,
		lim: NewLimiter(pol.P.RatePerSecond, pol.P.Burst, now), now: now}
}

// Kid returns the key id (RFC 7638 thumbprint).
func (m *Minter) Kid() string { return m.kid }

// ErrBroken means the sequence log failed earlier; the signer refuses to mint.
var ErrBroken = errors.New("signer: sequence log failed earlier; refusing to mint (restart after inspection)")

// Mint issues one token for caller uid.
func (m *Minter) Mint(uid uint32, r *Request) (*Response, error) {
	ttl, err := m.pol.Check(uid, r)
	if err != nil {
		return nil, err
	}
	if !m.lim.Allow(uid) {
		return nil, deny("rate limit for uid %d", uid)
	}
	var jb [16]byte
	if _, err := rand.Read(jb[:]); err != nil {
		return nil, err
	}
	jti := hex.EncodeToString(jb[:])

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.broken != nil {
		return nil, ErrBroken
	}
	now := m.now()
	iat := now.Unix()
	exp := now.Add(ttl).Unix()
	seq, err := m.seq.Reserve(SeqRecord{Iat: iat, Exp: exp, Aud: r.Aud, Sub: r.Sub, Jti: jti, Kid: m.kid, UID: uid})
	if err != nil {
		m.broken = err
		return nil, fmt.Errorf("%w: %v", ErrBroken, err)
	}
	claims := make(map[string]any, len(r.Claims)+8)
	for k, v := range r.Claims {
		claims[k] = v
	}
	claims["iss"] = m.pol.P.Issuer
	claims["sub"] = r.Sub
	claims["aud"] = r.Aud
	claims["iat"] = iat
	claims["nbf"] = iat
	claims["exp"] = exp
	claims["jti"] = jti
	claims["yard_seq"] = seq
	tok, err := SignJWT(m.key, m.kid, claims)
	if err != nil {
		if e2 := m.seq.MarkFailed(seq, uid); e2 != nil {
			m.broken = e2
		}
		return nil, err
	}
	return &Response{Token: tok, Seq: seq, Kid: m.kid, Iat: iat, Exp: exp}, nil
}

// JWKS returns the public key set for this minter's key plus any extras
// (e.g. the standby key).
func (m *Minter) JWKS(extra ...KeySigner) JWKS {
	set := JWKS{Keys: []JWK{PublicJWK(m.key.Public())}}
	for _, k := range extra {
		set.Keys = append(set.Keys, PublicJWK(k.Public()))
	}
	return set
}
