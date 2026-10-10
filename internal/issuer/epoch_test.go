package issuer

import (
	"errors"
	"sync"
	"testing"
)

type epochMap struct {
	mu sync.Mutex
	m  map[string]int64
}

func (e *epochMap) Epoch(s string) (int64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[s]
	return v, ok
}

func (e *epochMap) bump(s string) {
	e.mu.Lock()
	e.m[s]++
	e.mu.Unlock()
}

func sessReq(sess string, epoch int64) *Request {
	return &Request{Kind: Internal, Audience: "yard", Workload: wl, User: "chuck", Session: sess, Epoch: epoch}
}

func TestEpochClaimsStamped(t *testing.T) {
	is, ring, _ := setup(t)
	ep := &epochMap{m: map[string]int64{"s1": 3}}
	is.SetEpochs(ep)
	tok, err := is.Mint(Caller{Name: "uid:1"}, sessReq("s1", 3))
	if err != nil {
		t.Fatal(err)
	}
	c := verify(t, ring, tok.Token, "yard")
	if e, err := claimInt(c[ClaimEpoch]); c[ClaimSession] != "s1" || err != nil || e != 3 {
		t.Fatalf("claims %v", c)
	}
	if err := VerifyEpoch(c, ep, true); err != nil {
		t.Fatal(err)
	}
}

func TestEpochMintRefusals(t *testing.T) {
	is, _, _ := setup(t)
	if _, err := is.Mint(Caller{Name: "uid:1"}, sessReq("s1", 1)); err == nil {
		t.Fatal("minted a session token without an epoch source")
	}
	ep := &epochMap{m: map[string]int64{"s1": 2}}
	is.SetEpochs(ep)
	for _, r := range []*Request{sessReq("s1", 1), sessReq("s1", 3), sessReq("nope", 1), sessReq("bad/id", 2),
		{Kind: Internal, Audience: "yard", Workload: wl, User: "chuck", Epoch: 2}} {
		_, err := is.Mint(Caller{Name: "uid:1"}, r)
		var pe *PolicyError
		if !errors.As(err, &pe) {
			t.Fatalf("%+v: want a policy refusal, got %v", r, err)
		}
	}
	if _, err := is.Mint(Caller{Name: "uid:1"}, sessReq("s1", 1)); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale epoch: %v", err)
	}
	r := sessReq("s1", 2)
	r.Extra = map[string]any{ClaimEpoch: 9}
	if _, err := is.Mint(Caller{Name: "uid:1"}, r); err == nil {
		t.Fatal("epoch claim accepted from the request body")
	}
}

func TestVerifyEpoch(t *testing.T) {
	ep := &epochMap{m: map[string]int64{"s1": 2}}
	for _, tc := range []struct {
		claims  map[string]any
		require bool
		ok      bool
	}{
		{map[string]any{ClaimSession: "s1", ClaimEpoch: float64(2)}, true, true},
		{map[string]any{ClaimSession: "s1", ClaimEpoch: float64(1)}, true, false},
		{map[string]any{ClaimSession: "s1", ClaimEpoch: float64(3)}, true, false},
		{map[string]any{ClaimSession: "s1"}, true, false},
		{map[string]any{ClaimSession: "s9", ClaimEpoch: float64(1)}, true, false},
		{map[string]any{ClaimSession: "s1", ClaimEpoch: 2.5}, true, false},
		{map[string]any{}, true, false},
		{map[string]any{}, false, true},
	} {
		if err := VerifyEpoch(tc.claims, ep, tc.require); (err == nil) != tc.ok {
			t.Errorf("%v require=%v: %v", tc.claims, tc.require, err)
		}
	}
}

// i3Run is the Go-level counterpart of the model's noCredEpoch
// counterexample (spec/sr0 lifecycle_test.qnt lateMint): a refresh is
// requested before the suspend (stamped with that epoch) and answered after
// the resume. It returns whether I3 holds afterwards: every token of the
// resumed session that the broker honours was requested after the suspend.
// check=false is the mutant: no epoch check at the issuer nor the broker
// (the broker honours by exp alone).
func i3Run(t *testing.T, check bool) bool {
	t.Helper()
	is, ring, _ := setup(t)
	ep := &epochMap{m: map[string]int64{"s1": 1}}
	is.SetEpochs(ep)
	is.noEpochCheck = !check
	type held struct {
		tok       string
		afterSusp bool
	}
	var hs []held
	mint := func(epoch int64, after bool) {
		tok, err := is.Mint(Caller{Name: "uid:1"}, sessReq("s1", epoch))
		if err == nil {
			hs = append(hs, held{tok.Token, after})
		} else if !errors.Is(err, ErrStaleEpoch) {
			t.Fatal(err)
		}
	}
	mint(1, false)    // held in the VM's memory, snapshotted with it
	late := int64(1)  // a refresh requested now, stamped epoch 1
	ep.bump("s1")     // SuspendCommit: CredEpoch 1 -> 2
	mint(2, true)     // ResumeMint at the new epoch
	mint(late, false) // the late refresh is answered after the resume
	honoured := func(tok string) bool {
		c := verify(t, ring, tok, "yard") // signature, iss, aud, exp
		return !check || VerifyEpoch(c, ep, true) == nil
	}
	for _, h := range hs {
		if honoured(h.tok) && !h.afterSusp {
			return false
		}
	}
	return true
}

func TestI3EpochDesignHolds(t *testing.T) {
	if !i3Run(t, true) {
		t.Fatal("a pre-suspend credential is honoured after the resume")
	}
}

func TestI3NoEpochMutantBreaks(t *testing.T) {
	if i3Run(t, false) {
		t.Fatal("mutant without the epoch check should honour a pre-suspend credential")
	}
}
