//go:build simulator

// Run with: CGO_ENABLED=1 go test -tags simulator ./tpmkey (needs OpenSSL headers).
package tpmkey

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"yard/internal/sts"
)

func TestSimLifecycle(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	before, err := ListPersistent(tpm)
	if err != nil {
		t.Fatal(err)
	}
	pubA, tm, err := CreatePersistent(tpm, ActiveHandle)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("create timings: %+v", tm)
	pubS, _, err := CreatePersistent(tpm, StandbyHandle)
	if err != nil {
		t.Fatal(err)
	}
	if pubA.N.Cmp(pubS.N) == 0 {
		t.Fatal("active and standby keys are identical")
	}
	if _, _, err := CreatePersistent(tpm, ActiveHandle); !errors.Is(err, ErrHandleInUse) {
		t.Fatalf("overwrite not refused: %v", err)
	}
	after, _ := ListPersistent(tpm)
	if len(after) != len(before)+2 {
		t.Fatalf("persistent handles %v -> %v", before, after)
	}

	// Re-open from the handle only (as after a restart) and sign.
	k, err := Open(tpm, ActiveHandle)
	if err != nil {
		t.Fatal(err)
	}
	if k.Public().N.Cmp(pubA.N) != 0 {
		t.Fatal("re-opened key differs")
	}
	d := sha256.Sum256([]byte("payload"))
	sig, err := k.SignPKCS1v15SHA256(d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(pubA, crypto.SHA256, d[:], sig); err != nil {
		t.Fatal(err)
	}

	// Full mint path through the TPM key, verified by the stdlib verifier.
	pol, _ := sts.Compile(sts.Policy{Issuer: "https://yard.example/sts", Audiences: []string{"sts.amazonaws.com"},
		SubPatterns: []string{sts.DefaultSubPattern}, AllowedUIDs: []uint32{1001}})
	m := sts.NewMinter(pol, k, sts.NewSeqLog(nopSync{}, 0, ""), nil)
	sb, _ := Open(tpm, StandbyHandle)
	jwks := m.JWKS(sb)
	start := time.Now()
	for i := 0; i < 20; i++ {
		r, err := m.Mint(1001, &sts.Request{Aud: "sts.amazonaws.com", Sub: "spiffe://home.arpa/harness/h/policy/p/node/n/sandbox/s/run/r"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sts.Verify(r.Token, jwks, sts.VerifyOptions{Issuer: "https://yard.example/sts", MaxTTL: sts.HardMaxTTL, Now: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("20 sim mints+verifies in %s", time.Since(start))

	if err := Evict(tpm, ActiveHandle); err != nil {
		t.Fatal(err)
	}
	if err := Evict(tpm, StandbyHandle); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(tpm, ActiveHandle); err == nil {
		t.Fatal("key still present after evict")
	}
	final, _ := ListPersistent(tpm)
	if len(final) != len(before) {
		t.Fatalf("evict left handles: %v", final)
	}
}

type nopSync struct{}

func (nopSync) Write(p []byte) (int, error) { return len(p), nil }
func (nopSync) Sync() error                 { return nil }
