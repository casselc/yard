//go:build tpmhw

// Real-TPM integration test. Root only; run by ops/tests/t10-ctl-tpm.sh:
//
//	YARD_TPM=/dev/tpm0 ./keyring.tpmhw.test -test.v
//
// Part 1 (always): opens the PRODUCTION keys at 0x81010010/0x81010011 read-only
// (ReadPublic + Sign) -- never creates, evicts or rotates them.
// Part 2 (YARD_TPM_SCRATCH=1): a full init -> mint -> rotate -> retire cycle on
// SCRATCH handles 0x81010020/0x81010021, which must be empty at the start and
// are evicted again at the end. The test refuses to touch an occupied scratch
// handle.
//
// Exactly one TPM client may run at a time (tpm20(4) wedge rule): do not run
// this while yard-signer or yard-ctl serve is using the TPM.
package keyring

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"yard/internal/sts"
	"yard/internal/tpmkey"
)

const scratchA, scratchB Handle = 0x81010020, 0x81010021

func openDev(t *testing.T) *tpmkey.Dev {
	t.Helper()
	p := os.Getenv("YARD_TPM")
	if p == "" {
		p = "/dev/tpm0"
	}
	d, err := tpmkey.OpenDev(p)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func handles(t *testing.T, s TPMStore) []string {
	t.Helper()
	hs, err := tpmkey.ListPersistent(s.T)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, h := range hs {
		out = append(out, Handle(h).String())
	}
	sort.Strings(out)
	return out
}

func TestTPMProductionKeysReadOnly(t *testing.T) {
	s := TPMStore{T: openDev(t)}
	t.Logf("persistent handles: %v", handles(t, s))
	for _, h := range []Handle{0x81010010, 0x81010011} {
		ok, err := s.Exists(h)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Logf("%s: absent (skipped)", h)
			continue
		}
		k, err := s.Open(h)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		kid := sts.Thumbprint(k.Public())
		var lat []time.Duration
		for i := 0; i < 10; i++ {
			t0 := time.Now()
			tok, err := sts.SignJWT(k, kid, map[string]any{"iss": "t", "iat": 1, "exp": 2})
			lat = append(lat, time.Since(t0))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sts.Verify(tok, sts.JWKS{Keys: []sts.JWK{sts.PublicJWK(k.Public())}}, sts.VerifyOptions{Issuer: "t"}); err != nil {
				t.Fatal(err)
			}
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		t.Logf("RESULT %s kid=%s sign p50=%s max=%s (n=10)", h, kid, lat[5].Round(10*time.Microsecond), lat[9].Round(10*time.Microsecond))
	}
}

func TestTPMRotationCycleOnScratchHandles(t *testing.T) {
	if os.Getenv("YARD_TPM_SCRATCH") != "1" {
		t.Skip("set YARD_TPM_SCRATCH=1 to create/evict keys at 0x81010020/0x81010021")
	}
	s := TPMStore{T: openDev(t)}
	before := handles(t, s)
	for _, h := range []Handle{scratchA, scratchB} {
		if ok, _ := s.Exists(h); ok {
			t.Fatalf("scratch handle %s is occupied; refusing to touch it (evict it yourself if it is a leftover)", h)
		}
	}
	t.Cleanup(func() {
		for _, h := range []Handle{scratchA, scratchB} {
			if ok, _ := s.Exists(h); ok {
				if err := s.Evict(h); err != nil {
					t.Errorf("cleanup evict %s: %v", h, err)
				}
			}
		}
		after := handles(t, s)
		if len(after) != len(before) {
			t.Errorf("persistent handles before %v, after %v", before, after)
		}
		t.Logf("persistent handles after cleanup: %v", after)
	})
	c := &clock{t: time.Now()}
	cfg := Config{PublishDelay: time.Minute, RetireGrace: time.Minute}
	p := filepath.Join(t.TempDir(), "keyring.json")

	t0 := time.Now()
	r, err := Init(s, p, scratchA, scratchB, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT init (2 TPM key creates) %s", time.Since(t0).Round(time.Millisecond))
	set0 := r.JWKS()
	tokA, err := signVerify(t, r, set0)
	if err != nil {
		t.Fatal(err)
	}

	c.add(cfg.PublishDelay)
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	set1 := r.JWKS()
	if _, kid := r.Active(); kid != set0.Keys[1].Kid {
		t.Fatal("standby did not become active")
	}
	if _, err := sts.Verify(tokA, set1, sts.VerifyOptions{Issuer: "i"}); err != nil {
		t.Fatalf("old token during grace: %v", err)
	}
	if _, err := signVerify(t, r, set1); err != nil {
		t.Fatal(err)
	}

	// reopen from the state file (as a restart would) before retiring
	r, err = Open(s, p, cfg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	c.add(cfg.RetireGrace)
	t0 = time.Now()
	if err := r.Retire(); err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT retire (evict + 1 TPM key create) %s", time.Since(t0).Round(time.Millisecond))
	set2 := r.JWKS()
	if len(set2.Keys) != 2 || set2.Keys[0].Kid != set0.Keys[1].Kid || set2.Keys[1].Kid == set0.Keys[0].Kid {
		t.Fatalf("jwks after retire: %v", kids(set2))
	}
	if _, err := sts.Verify(tokA, set2, sts.VerifyOptions{Issuer: "i"}); err == nil {
		t.Fatal("retired key still verifies")
	}
	if _, err := signVerify(t, r, set2); err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT kids: init=%v rotated=%v retired=%v", kids(set0), kids(set1), kids(set2))
}
