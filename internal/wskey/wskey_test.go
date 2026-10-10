package wskey

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"yard/internal/sts"
)

func testKEK(t *testing.T) *KEK {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	k := make([]byte, 32)
	rand.Read(k)
	if err := os.WriteFile(p, k, 0o400); err != nil {
		t.Fatal(err)
	}
	kek, err := KEKFromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func TestKEKFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kek")
	os.WriteFile(p, make([]byte, 32), 0o644)
	if _, err := KEKFromFile(p); err == nil {
		t.Fatal("a world-readable KEK file was accepted")
	}
	os.Chmod(p, 0o600)
	os.WriteFile(p, make([]byte, 31), 0o600)
	if _, err := KEKFromFile(p); err == nil {
		t.Fatal("a 31-byte KEK was accepted")
	}
}

func TestWrapBindsIdentity(t *testing.T) {
	kek := testKEK(t)
	key := bytes.Repeat([]byte{7}, 32)
	w, err := kek.Wrap(ConsumerZFS, "proj", 1, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kek.Unwrap(ConsumerZFS, "proj", 1, w)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap: %v", err)
	}
	for _, c := range []struct {
		cons, subj string
		v          int64
	}{{ConsumerSpill, "proj", 1}, {ConsumerZFS, "other", 1}, {ConsumerZFS, "proj", 2}} {
		if _, err := kek.Unwrap(c.cons, c.subj, c.v, w); err == nil {
			t.Fatalf("unwrapped as %v", c)
		}
	}
	if _, err := testKEK(t).Unwrap(ConsumerZFS, "proj", 1, w); err == nil {
		t.Fatal("unwrapped under another KEK")
	}
}

func TestKEKFromSignerDeterministic(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	a, err := KEKFromSigner(sts.SoftSigner{K: rk})
	if err != nil {
		t.Fatal(err)
	}
	b, err := KEKFromSigner(sts.SoftSigner{K: rk})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.Wrap(ConsumerZFS, "p", 1, make([]byte, 32))
	if _, err := b.Unwrap(ConsumerZFS, "p", 1, w); err != nil {
		t.Fatal("the same signer gave another KEK")
	}
	rk2, _ := rsa.GenerateKey(rand.Reader, 2048)
	c, _ := KEKFromSigner(sts.SoftSigner{K: rk2})
	if _, err := c.Unwrap(ConsumerZFS, "p", 1, w); err == nil {
		t.Fatal("another signer opened the key")
	}
}

func TestCreateKeyShred(t *testing.T) {
	db := filepath.Join(t.TempDir(), "yard.db")
	st, err := Open(db, testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	k1, v1, err := st.Create(ConsumerZFS, "proj", 10)
	if err != nil || v1 != 1 {
		t.Fatalf("create: v%d %v", v1, err)
	}
	if _, _, err := st.Create(ConsumerZFS, "proj", 11); !errors.Is(err, ErrExists) {
		t.Fatalf("second live key: %v", err)
	}
	got, v, err := st.Key(ConsumerZFS, "proj")
	if err != nil || v != 1 || !bytes.Equal(got, k1) {
		t.Fatalf("key: %v", err)
	}
	var wrapped []byte
	st.db.QueryRow(`SELECT wrapped FROM wskeys WHERE subject = 'proj'`).Scan(&wrapped)
	if err := st.Shred(ConsumerZFS, "proj", 12); err != nil {
		t.Fatal(err)
	}
	if err := st.Shred(ConsumerZFS, "proj", 13); err != nil {
		t.Fatalf("shred is not idempotent: %v", err)
	}
	if _, _, err := st.Key(ConsumerZFS, "proj"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("key after shred: %v", err)
	}
	// the wrapped bytes are gone from the database file and its WAL
	for _, f := range []string{db, db + "-wal"} {
		b, _ := os.ReadFile(f)
		if len(wrapped) > 0 && bytes.Contains(b, wrapped) {
			t.Fatalf("wrapped key still in %s after shred", f)
		}
	}
	k2, v2, err := st.Create(ConsumerZFS, "proj", 14)
	if err != nil || v2 != 2 || bytes.Equal(k1, k2) {
		t.Fatalf("re-create after shred: v%d %v", v2, err)
	}
	rows, _ := st.List(ConsumerZFS)
	if len(rows) != 2 || rows[0].State != Shredded || rows[1].State != Live {
		t.Fatalf("rows %+v", rows)
	}
	if _, _, err := st.Create(ConsumerZFS, "../x", 1); err == nil {
		t.Fatal("bad subject accepted")
	}
}
