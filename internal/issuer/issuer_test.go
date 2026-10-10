package issuer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yard/internal/keyring"
	"yard/internal/sts"
)

type syncBuf struct {
	bytes.Buffer
	fail error
}

func (b *syncBuf) Sync() error { return b.fail }

var wl = WorkloadID{Harness: "opencode", Policy: "aws-ro", Node: "nuc", Sandbox: "s1", Run: "r1"}

func setup(t *testing.T) (*Issuer, *keyring.Ring, *syncBuf) {
	t.Helper()
	st := keyring.NewMemStore()
	st.Bits = 1024
	ring, err := keyring.Init(st, filepath.Join(t.TempDir(), "k.json"), 0x81010010, 0x81010011, keyring.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := &syncBuf{}
	is, err := New(Config{Issuer: "https://id.example.org/yard", TrustDomain: "home.arpa",
		ExternalAudiences: []string{"sts.amazonaws.com", "api://AzureADTokenExchange"},
		InternalAudiences: []string{"yard"}, AWSSessionTags: true, RatePerSecond: 1000, Burst: 1000},
		ring, sts.NewSeqLog(buf, 0, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	return is, ring, buf
}

func verify(t *testing.T, ring *keyring.Ring, tok, aud string) map[string]any {
	t.Helper()
	c, err := sts.Verify(tok, ring.JWKS(), sts.VerifyOptions{Issuer: "https://id.example.org/yard", Audience: aud, MaxTTL: 5 * time.Minute, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSPIFFERoundTrip(t *testing.T) {
	id := wl.SPIFFE("home.arpa")
	if id != "spiffe://home.arpa/harness/opencode/policy/aws-ro/node/nuc/sandbox/s1/run/r1" {
		t.Fatal(id)
	}
	if !strings.HasPrefix(id, wl.PolicySubject("home.arpa")+"/") {
		t.Fatal("policy subject is not a prefix of the workload id")
	}
	back, err := ParseSPIFFE("home.arpa", id)
	if err != nil || back != wl {
		t.Fatalf("%v %+v", err, back)
	}
	for _, bad := range []string{
		"spiffe://evil.example/harness/a/policy/b/node/c/sandbox/d/run/e",
		"spiffe://home.arpa/harness/a/policy/b/node/c/sandbox/d",
		"spiffe://home.arpa/harness/A/policy/b/node/c/sandbox/d/run/e",
		"spiffe://home.arpa/policy/b/harness/a/node/c/sandbox/d/run/e",
	} {
		if _, err := ParseSPIFFE("home.arpa", bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if (WorkloadID{Harness: "a/b", Policy: "p", Node: "n", Sandbox: "s", Run: "r"}).Validate() == nil {
		t.Fatal("slash in a segment accepted")
	}
}

func TestExternalTokenShape(t *testing.T) {
	is, ring, _ := setup(t)
	tok, err := is.Mint(Caller{Name: "brk"}, &Request{Kind: External, Audience: "sts.amazonaws.com", Workload: wl, User: "chuck@github", TTL: 120})
	if err != nil {
		t.Fatal(err)
	}
	c := verify(t, ring, tok.Token, "sts.amazonaws.com")
	if c["sub"] != "spiffe://home.arpa/harness/opencode/policy/aws-ro" {
		t.Fatalf("sub %v", c["sub"])
	}
	if c["yard_wid"] != wl.SPIFFE("home.arpa") || c["yard_user"] != "chuck@github" || c["yard_kind"] != "external" {
		t.Fatalf("claims %v", c)
	}
	if _, ok := c["act"]; ok {
		t.Fatal("external token must not carry act")
	}
	tags, ok := c["https://aws.amazon.com/tags"].(map[string]any)
	if !ok {
		t.Fatalf("no aws tags: %v", c)
	}
	pt := tags["principal_tags"].(map[string]any)
	if v := pt["yard-sandbox"].([]any); len(v) != 1 || v[0] != "s1" {
		t.Fatalf("sandbox tag %v", v)
	}
	exp, _ := c["exp"].(json.Number).Int64()
	iat, _ := c["iat"].(json.Number).Int64()
	if exp-iat != 120 {
		t.Fatalf("ttl %d", exp-iat)
	}
	if s, _ := c["yard_seq"].(json.Number).Int64(); uint64(s) != tok.Seq || tok.Seq != 1 {
		t.Fatalf("seq %v %d", c["yard_seq"], tok.Seq)
	}
}

func TestInternalTokenShape(t *testing.T) {
	is, ring, _ := setup(t)
	tok, err := is.Mint(Caller{Name: "x"}, &Request{Kind: Internal, Audience: "yard", Workload: wl, User: "chuck@github", Approval: "apv-42"})
	if err != nil {
		t.Fatal(err)
	}
	c := verify(t, ring, tok.Token, "yard")
	if c["sub"] != "chuck@github" {
		t.Fatalf("sub %v", c["sub"])
	}
	act, _ := c["act"].(map[string]any)
	if act["sub"] != wl.SPIFFE("home.arpa") {
		t.Fatalf("act %v", c["act"])
	}
	if c["apv"] != "apv-42" {
		t.Fatal("apv missing")
	}
	if _, ok := c["https://aws.amazon.com/tags"]; ok {
		t.Fatal("internal token carries aws tags")
	}
	exp, _ := c["exp"].(json.Number).Int64()
	iat, _ := c["iat"].(json.Number).Int64()
	if exp-iat != 300 {
		t.Fatalf("default ttl %d", exp-iat)
	}
}

func TestPolicyDenials(t *testing.T) {
	is, _, _ := setup(t)
	base := Request{Kind: External, Audience: "sts.amazonaws.com", Workload: wl, User: "u"}
	cases := map[string]func(r *Request){
		"internal aud on external": func(r *Request) { r.Audience = "yard" },
		"external aud on internal": func(r *Request) { r.Kind = Internal },
		"unknown aud":              func(r *Request) { r.Audience = "https://evil" },
		"bad kind":                 func(r *Request) { r.Kind = "other" },
		"ttl over 5m":              func(r *Request) { r.TTL = 301 },
		"negative ttl":             func(r *Request) { r.TTL = -1 },
		"bad workload":             func(r *Request) { r.Workload.Run = "" },
		"bad user":                 func(r *Request) { r.User = "a b" },
		"empty user":               func(r *Request) { r.User = "" },
		"reserved claim sub":       func(r *Request) { r.Extra = map[string]any{"sub": "x"} },
		"reserved claim act":       func(r *Request) { r.Extra = map[string]any{"act": "x"} },
		"reserved claim aws tags":  func(r *Request) { r.Extra = map[string]any{"https://aws.amazon.com/tags": 1} },
		"reserved claim yard_seq":  func(r *Request) { r.Extra = map[string]any{"yard_seq": 1} },
		"bad approval":             func(r *Request) { r.Approval = "x y" },
	}
	for name, mut := range cases {
		r := base
		mut(&r)
		_, err := is.Mint(Caller{Name: "c"}, &r)
		var pe *PolicyError
		if !errors.As(err, &pe) {
			t.Errorf("%s: got %v, want PolicyError", name, err)
		}
	}
}

func TestConfigRejectsOverlappingAudiences(t *testing.T) {
	_, err := New(Config{Issuer: "i", TrustDomain: "home.arpa", ExternalAudiences: []string{"a"}, InternalAudiences: []string{"a"}}, nil, nil, nil)
	if err == nil {
		t.Fatal("overlap accepted")
	}
	if _, err := New(Config{Issuer: "i", TrustDomain: "Bad_TD", ExternalAudiences: []string{"a"}}, nil, nil, nil); err == nil {
		t.Fatal("bad trust domain accepted")
	}
}

func TestSeqLogFailureFailsClosed(t *testing.T) {
	is, _, buf := setup(t)
	r := Request{Kind: Internal, Audience: "yard", Workload: wl, User: "u"}
	if _, err := is.Mint(Caller{}, &r); err != nil {
		t.Fatal(err)
	}
	buf.fail = errors.New("disk gone")
	if _, err := is.Mint(Caller{}, &r); !errors.Is(err, ErrBroken) {
		t.Fatalf("got %v", err)
	}
	buf.fail = nil
	if _, err := is.Mint(Caller{}, &r); !errors.Is(err, ErrBroken) {
		t.Fatal("issuer recovered by itself; it must stay closed until restart")
	}
}

func TestSeqLogIsChainedAndContiguousUnderConcurrency(t *testing.T) {
	is, _, buf := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := is.Mint(Caller{Name: "c"}, &Request{Kind: Internal, Audience: "yard", Workload: wl, User: "u"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	last, _, err := sts.ScanLog(bytes.NewReader(buf.Bytes()))
	if err != nil || last != 40 {
		t.Fatalf("scan: last=%d err=%v", last, err)
	}
	if strings.Contains(buf.String(), "eyJ") {
		t.Fatal("seq log contains a token")
	}
}

func TestRotationDuringMintingKeepsKidConsistent(t *testing.T) {
	is, ring, _ := setup(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if ring.Rotate() == nil {
				ring.Retire()
			}
		}
	}()
	for i := 0; i < 30; i++ {
		tok, err := is.Mint(Caller{Name: "c"}, &Request{Kind: Internal, Audience: "yard", Workload: wl, User: "u"})
		if err != nil {
			t.Fatal(err)
		}
		// header kid must match the key that signed: verify against the token's own kid only
		var hdr struct{ Kid string }
		hb, _ := jsonB64(strings.Split(tok.Token, ".")[0])
		json.Unmarshal(hb, &hdr)
		if hdr.Kid != tok.Kid {
			t.Fatalf("header kid %s != reported kid %s", hdr.Kid, tok.Kid)
		}
		set := ring.JWKS()
		if _, err := sts.Verify(tok.Token, set, sts.VerifyOptions{Issuer: "https://id.example.org/yard"}); err != nil {
			// the signing key may have been retired since; it must at least have been the active one
			if !strings.Contains(err.Error(), "not in jwks") {
				t.Fatal(err)
			}
		}
	}
	close(stop)
	wg.Wait()
}

func jsonB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
