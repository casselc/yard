package sts

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	iss     = "https://issuer.yard.example"
	goodSub = "spiffe://home.arpa/harness/h1/policy/own-code/node/nuc/sandbox/s1/run/r1"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key(t testing.TB) SoftSigner {
	keyOnce.Do(func() {
		var err error
		testKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	})
	return SoftSigner{K: testKey}
}

func pol(t testing.TB, mod func(*Policy)) *Compiled {
	p := Policy{Issuer: iss, Audiences: []string{"sts.amazonaws.com", "yard-internal"},
		SubPatterns: []string{DefaultSubPattern}, AllowedUIDs: []uint32{1001}, RatePerSecond: 1000, Burst: 1000}
	if mod != nil {
		mod(&p)
	}
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type memLog struct {
	bytes.Buffer
	failWrite, failSync bool
}

func (m *memLog) Write(p []byte) (int, error) {
	if m.failWrite {
		return 0, errors.New("disk full")
	}
	return m.Buffer.Write(p)
}
func (m *memLog) Sync() error {
	if m.failSync {
		return errors.New("fsync EIO")
	}
	return nil
}

func TestCompileRejectsWeakPolicies(t *testing.T) {
	base := Policy{Issuer: iss, Audiences: []string{"a"}, SubPatterns: []string{"x"}, AllowedUIDs: []uint32{1}}
	cases := map[string]func(*Policy){
		"no iss":    func(p *Policy) { p.Issuer = "" },
		"no aud":    func(p *Policy) { p.Audiences = nil },
		"empty aud": func(p *Policy) { p.Audiences = []string{""} },
		"no subs":   func(p *Policy) { p.SubPatterns = nil },
		"bad re":    func(p *Policy) { p.SubPatterns = []string{"("} },
		"no uids":   func(p *Policy) { p.AllowedUIDs = nil },
	}
	for name, mod := range cases {
		p := base
		mod(&p)
		if _, err := Compile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A policy asking for a 1h TTL is clamped to the hard 5 min.
	p := base
	p.MaxTTLSeconds = 3600
	c, err := Compile(p)
	if err != nil || c.maxTTL != HardMaxTTL {
		t.Fatalf("max ttl not clamped: %v %v", c.maxTTL, err)
	}
}

func TestCheck(t *testing.T) {
	c := pol(t, nil)
	cases := []struct {
		name string
		uid  uint32
		r    Request
		ok   bool
	}{
		{"good", 1001, Request{Aud: "sts.amazonaws.com", Sub: goodSub, TTLSeconds: 300}, true},
		{"default ttl", 1001, Request{Aud: "yard-internal", Sub: goodSub}, true},
		{"uid denied", 0, Request{Aud: "yard-internal", Sub: goodSub}, false},
		{"aud not allowed", 1001, Request{Aud: "evil", Sub: goodSub}, false},
		{"aud case", 1001, Request{Aud: "STS.amazonaws.com", Sub: goodSub}, false},
		{"ttl 301", 1001, Request{Aud: "yard-internal", Sub: goodSub, TTLSeconds: 301}, false},
		{"ttl negative", 1001, Request{Aud: "yard-internal", Sub: goodSub, TTLSeconds: -1}, false},
		{"sub prefix only", 1001, Request{Aud: "yard-internal", Sub: goodSub + "/extra"}, false},
		{"sub suffix trick", 1001, Request{Aud: "yard-internal", Sub: "x" + goodSub}, false},
		{"sub newline", 1001, Request{Aud: "yard-internal", Sub: goodSub + "\n"}, false},
		{"sub uppercase", 1001, Request{Aud: "yard-internal", Sub: strings.ToUpper(goodSub)}, false},
		{"sub empty segment", 1001, Request{Aud: "yard-internal", Sub: "spiffe://home.arpa/harness//policy/p/node/n/sandbox/s/run/r"}, false},
		{"forced iss", 1001, Request{Aud: "yard-internal", Sub: goodSub, Claims: map[string]any{"iss": "evil"}}, false},
		{"exp override", 1001, Request{Aud: "yard-internal", Sub: goodSub, Claims: map[string]any{"exp": 9999999999}}, false},
		{"seq override", 1001, Request{Aud: "yard-internal", Sub: goodSub, Claims: map[string]any{"yard_seq": 1}}, false},
		{"extra ok", 1001, Request{Aud: "yard-internal", Sub: goodSub, Claims: map[string]any{"act": map[string]any{"sub": "user"}}}, true},
		{"extra too big", 1001, Request{Aud: "yard-internal", Sub: goodSub, Claims: map[string]any{"x": strings.Repeat("a", 5000)}}, false},
	}
	for _, tc := range cases {
		_, err := c.Check(tc.uid, &tc.r)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v want ok=%v", tc.name, err, tc.ok)
		}
		var pe *PolicyError
		if err != nil && !errors.As(err, &pe) {
			t.Errorf("%s: not a PolicyError: %v", tc.name, err)
		}
	}
}

func TestMintVerifyAndClaims(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	lg := &memLog{}
	m := NewMinter(pol(t, nil), key(t), NewSeqLog(lg, 0, ""), func() time.Time { return now })
	r, err := m.Mint(1001, &Request{Aud: "sts.amazonaws.com", Sub: goodSub, TTLSeconds: 120,
		Claims: map[string]any{"act": map[string]any{"sub": "chuck"}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(r.Token, m.JWKS(), VerifyOptions{Issuer: iss, Audience: "sts.amazonaws.com", MaxTTL: HardMaxTTL, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if c["iss"] != iss || c["sub"] != goodSub || fmt.Sprint(c["yard_seq"]) != "1" {
		t.Fatalf("claims %v", c)
	}
	if r.Exp-r.Iat != 120 {
		t.Fatalf("ttl %d", r.Exp-r.Iat)
	}
	// Tampering breaks the signature.
	parts := strings.Split(r.Token, ".")
	bad := parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"`+iss+`","iat":1,"exp":2}`)) + "." + parts[2]
	if _, err := Verify(bad, m.JWKS(), VerifyOptions{}); err == nil {
		t.Fatal("tampered token verified")
	}
	// A different key's JWKS does not verify it.
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	other := JWKS{Keys: []JWK{PublicJWK(&k2.PublicKey)}}
	other.Keys[0].Kid = m.Kid()
	if _, err := Verify(r.Token, other, VerifyOptions{}); err == nil {
		t.Fatal("verified with wrong key")
	}
	// Expired at exp.
	if _, err := Verify(r.Token, m.JWKS(), VerifyOptions{Now: now.Add(120 * time.Second)}); err == nil {
		t.Fatal("expired token accepted")
	}
	// The log has exactly one reserved record and scans cleanly.
	last, _, err := ScanLog(bytes.NewReader(lg.Bytes()))
	if err != nil || last != 1 {
		t.Fatalf("scan: last=%d err=%v", last, err)
	}
}

func TestThumbprintRFC7638(t *testing.T) {
	// RFC 7638 §3.1 example key and thumbprint.
	j := JWK{Kty: "RSA", E: "AQAB", N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	pub, err := j.RSAPublic()
	if err != nil {
		t.Fatal(err)
	}
	if got := Thumbprint(pub); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
}

func TestSeqMonotonicAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seq.log")
	var last uint64
	for run := 0; run < 3; run++ {
		lg, f, err := OpenSeqLogFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if lg.Last() != last {
			t.Fatalf("run %d: restart saw last=%d want %d", run, lg.Last(), last)
		}
		m := NewMinter(pol(t, nil), key(t), lg, nil)
		for i := 0; i < 5; i++ {
			r, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub})
			if err != nil {
				t.Fatal(err)
			}
			if r.Seq != last+1 {
				t.Fatalf("seq %d after %d", r.Seq, last)
			}
			last = r.Seq
		}
		f.Close()
	}
	if last != 15 {
		t.Fatalf("last %d", last)
	}
}

func TestSeqLogTamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seq.log")
	lg, f, _ := OpenSeqLogFile(path)
	m := NewMinter(pol(t, nil), key(t), lg, nil)
	for i := 0; i < 3; i++ {
		if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	mutations := map[string]string{
		"drop middle": lines[0] + "\n" + lines[2] + "\n",
		"edit aud":    strings.Replace(string(b), `"aud":"yard-internal"`, `"aud":"yard-internaL"`, 1),
		"reorder":     lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n",
		"truncated":   lines[0] + "\n" + lines[1][:20] + "\n",
	}
	for name, content := range mutations {
		if _, _, err := ScanLog(strings.NewReader(content)); err == nil {
			t.Errorf("%s: tamper not detected", name)
		}
	}
	if _, _, err := ScanLog(bytes.NewReader(b)); err != nil {
		t.Fatalf("pristine log rejected: %v", err)
	}
}

func TestFailClosedOnLogFailure(t *testing.T) {
	lg := &memLog{}
	m := NewMinter(pol(t, nil), key(t), NewSeqLog(lg, 0, ""), nil)
	if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); err != nil {
		t.Fatal(err)
	}
	lg.failSync = true
	if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); !errors.Is(err, ErrBroken) {
		t.Fatalf("want ErrBroken, got %v", err)
	}
	lg.failSync = false // even after the disk "recovers", stay closed
	if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); !errors.Is(err, ErrBroken) {
		t.Fatalf("recovered without restart: %v", err)
	}
}

type failSigner struct{ SoftSigner }

func (failSigner) SignPKCS1v15SHA256([]byte) ([]byte, error) {
	return nil, errors.New("TPM_RC_FAILURE")
}

func TestSignFailureRecorded(t *testing.T) {
	lg := &memLog{}
	m := NewMinter(pol(t, nil), failSigner{key(t)}, NewSeqLog(lg, 0, ""), nil)
	if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); err == nil {
		t.Fatal("sign failure not surfaced")
	}
	if !strings.Contains(lg.String(), `"status":"sign_failed"`) {
		t.Fatalf("no sign_failed record: %s", lg.String())
	}
	last, _, err := ScanLog(bytes.NewReader(lg.Bytes()))
	if err != nil || last != 1 {
		t.Fatalf("scan after sign failure: %d %v", last, err)
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	clock := func() time.Time { return now }
	m := NewMinter(pol(t, func(p *Policy) { p.RatePerSecond = 1; p.Burst = 3; p.AllowedUIDs = []uint32{1001, 1002} }), key(t), NewSeqLog(&memLog{}, 0, ""), clock)
	ok := 0
	for i := 0; i < 10; i++ {
		if _, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub}); err == nil {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("burst allowed %d, want 3", ok)
	}
	if _, err := m.Mint(1002, &Request{Aud: "yard-internal", Sub: goodSub}); err != nil {
		t.Fatalf("uid 1002 throttled by uid 1001's bucket: %v", err)
	}
	now = now.Add(2 * time.Second)
	r, err := m.Mint(1001, &Request{Aud: "yard-internal", Sub: goodSub})
	if err != nil {
		t.Fatalf("not refilled: %v", err)
	}
	// 3 (burst) + 1 (uid 1002) issued before; 7 throttled requests consumed no seqs.
	if r.Seq != 5 {
		t.Fatalf("seq after throttling = %d, want 5", r.Seq)
	}
}

// Randomised invariant check: whatever the caller sends, every token that is
// issued satisfies the policy, and issued seqs are dense and increasing.
func TestRandomRequestsInvariants(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	auds := []string{"sts.amazonaws.com", "yard-internal", "evil", "", "STS.AMAZONAWS.COM"}
	subs := []string{goodSub, goodSub + "/x", "spiffe://home.arpa/harness/a/policy/b/node/c/sandbox/d/run/e", "", "spiffe://evil/x"}
	keys := []string{"act", "apv", "iss", "exp", "nbf", "jti", "yard_seq", "aws_tags"}
	lg := &memLog{}
	m := NewMinter(pol(t, nil), key(t), NewSeqLog(lg, 0, ""), nil)
	jwks := m.JWKS()
	var last uint64
	issued := 0
	pick := func(good []string, bad []string) string {
		if rng.IntN(10) < 7 {
			return good[rng.IntN(len(good))]
		}
		return bad[rng.IntN(len(bad))]
	}
	for i := 0; i < 400; i++ {
		r := Request{Aud: pick(auds[:2], auds[2:]), Sub: pick(subs[:1], subs[1:]), TTLSeconds: rng.IntN(301)}
		if rng.IntN(10) >= 7 {
			r.TTLSeconds = []int{-1, 301, 600, 3600}[rng.IntN(4)]
		}
		if rng.IntN(2) == 0 {
			r.Claims = map[string]any{keys[rng.IntN(len(keys))]: rng.IntN(1 << 30)}
		}
		uid := uint32(1001)
		if rng.IntN(10) >= 7 {
			uid = []uint32{0, 65534}[rng.IntN(2)]
		}
		resp, err := m.Mint(uid, &r)
		if err != nil {
			continue
		}
		issued++
		c, err := Verify(resp.Token, jwks, VerifyOptions{Issuer: iss, Audience: r.Aud, MaxTTL: HardMaxTTL, Now: time.Now()})
		if err != nil {
			t.Fatalf("issued token fails verification: %v (req %+v)", err, r)
		}
		if uid != 1001 || (r.Aud != "sts.amazonaws.com" && r.Aud != "yard-internal") || c["sub"] != r.Sub {
			t.Fatalf("policy violated: uid=%d req=%+v", uid, r)
		}
		if resp.Exp-resp.Iat > 300 || resp.Exp-resp.Iat <= 0 {
			t.Fatalf("ttl %d", resp.Exp-resp.Iat)
		}
		if resp.Seq != last+1 {
			t.Fatalf("seq %d after %d", resp.Seq, last)
		}
		last = resp.Seq
	}
	if issued < 40 || issued > 360 {
		t.Fatalf("generator unbalanced: issued %d/400 (want both paths well exercised)", issued)
	}
	n, _, err := ScanLog(bytes.NewReader(lg.Bytes()))
	if err != nil || n != last {
		t.Fatalf("log last=%d tokens last=%d err=%v", n, last, err)
	}
	t.Logf("issued %d/400", issued)
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.json")
	b, _ := json.Marshal(map[string]any{"iss": iss, "aud_allow": []string{"a"}, "sub_patterns": []string{"x"},
		"allowed_uids": []int{1}, "max_ttl": 3600})
	os.WriteFile(p, b, 0o600)
	if _, err := LoadPolicy(p); err == nil {
		t.Fatal("typo'd field accepted")
	}
}
