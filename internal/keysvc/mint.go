package keysvc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"yard/internal/issuer"
)

// SpillClaim is the halo_spill claim (IDENTITY.md "Spill keys"; halo
// yard_keys.cpp Register): use, the key's SHA-256 (seal, open), the cache
// entry id "<incarnation>.<key>" (seal), and `through` (revoke; always
// explicit: halo's default is never relied on).
type SpillClaim struct {
	Use       Use
	KeySHA256 string // base64url (no padding) of SHA-256(K)
	Entry     string
	Through   int64
	Op        string // the operation id (seal, open; round 5): unique per checkpoint operation
}

// Map is the claim as JSON members.
func (c SpillClaim) Map() map[string]any {
	m := map[string]any{"use": strings.ToLower(string(c.Use))}
	switch c.Use {
	case Seal:
		m["key_sha256"], m["entry"] = c.KeySHA256, c.Entry
	case Open:
		m["key_sha256"] = c.KeySHA256
	}
	if c.Op != "" && c.Use != Revoke {
		m["op"] = c.Op
	}
	switch c.Use {
	case Revoke:
		if c.Through > 0 { // epochs start at 1: 0 is "none" (never sent by the design)
			m["through"] = c.Through
		}
	}
	return m
}

// Minter mints a halo_spill token for a session at an epoch.
type Minter interface {
	MintSpill(sess string, epoch int64, c SpillClaim) (token string, err error)
}

// HaloAudience is halo_serve's audience (an InternalAudiences entry).
const HaloAudience = "halo_serve"

// IssuerMinter mints through yard's issuer: an internal RS256 token, aud
// halo_serve, iss yard's, iat/nbf/exp integers, exp-iat = TTL (<= 300 s),
// a random jti, yard_sess/yard_epoch (the issuer refuses an epoch other than
// the session's current one), and the halo_spill claim.
type IssuerMinter struct {
	Is       *issuer.Issuer
	Caller   issuer.Caller
	Workload issuer.WorkloadID // yard-ctl's own workload id (act.sub)
	User     string            // sub
	TTL      int               // seconds; 0: the issuer's default (capped at 300)
}

func (m *IssuerMinter) MintSpill(sess string, epoch int64, c SpillClaim) (string, error) {
	t, err := m.Is.Mint(m.Caller, &issuer.Request{Kind: issuer.Internal, Audience: HaloAudience, Workload: m.Workload,
		User: m.User, TTL: m.TTL, Extra: map[string]any{"halo_spill": c.Map()}, Session: sess, Epoch: epoch})
	if err != nil {
		return "", err
	}
	return t.Token, nil
}

// KeyName is halo's display name of a key: the first 8 bytes of
// HMAC-SHA256(K, "halo-spill-master-id"), hex (spill_crypt.cpp KeyName).
func KeyName(k []byte) string {
	h := hmac.New(sha256.New, k)
	h.Write([]byte("halo-spill-master-id"))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// KeyHash is the claim's key_sha256.
func KeyHash(k []byte) string {
	d := sha256.Sum256(k)
	return b64u.EncodeToString(d[:])
}

// FileKeyID is the key id a spill file sealed under k at epoch e carries.
func FileKeyID(k []byte, e int64, sess string) string {
	return "yard:" + KeyName(k) + ":e" + itoa(e) + ":" + sess
}
