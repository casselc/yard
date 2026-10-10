package keyring

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"yard/internal/sts"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// ErrOccupied is returned by Create when the handle already holds a key.
var ErrOccupied = errors.New("keyring: handle occupied")

// MemStore is an in-memory software key store: the fake used by tests.
// Bits defaults to 2048. FailNext, if set, makes the next named operation
// fail once (crash/fault injection in tests).
type MemStore struct {
	mu       sync.Mutex
	Bits     int
	keys     map[Handle]*rsa.PrivateKey
	FailNext map[string]error // "create", "evict", "open"
	Calls    []string
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{keys: map[Handle]*rsa.PrivateKey{}, FailNext: map[string]error{}}
}

func (m *MemStore) fail(op string, h Handle) error {
	m.Calls = append(m.Calls, op+" "+h.String())
	if err, ok := m.FailNext[op]; ok {
		delete(m.FailNext, op)
		return err
	}
	return nil
}

func (m *MemStore) Exists(h Handle) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.keys[h]
	return ok, nil
}

func (m *MemStore) Open(h Handle) (sts.KeySigner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("open", h); err != nil {
		return nil, err
	}
	k, ok := m.keys[h]
	if !ok {
		return nil, fmt.Errorf("memstore: no key at %s", h)
	}
	return sts.SoftSigner{K: k}, nil
}

func (m *MemStore) Create(h Handle) (sts.KeySigner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("create", h); err != nil {
		return nil, err
	}
	if _, ok := m.keys[h]; ok {
		return nil, fmt.Errorf("%w: %s", ErrOccupied, h)
	}
	bits := m.Bits
	if bits == 0 {
		bits = 2048
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	m.keys[h] = k
	return sts.SoftSigner{K: k}, nil
}

func (m *MemStore) Evict(h Handle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("evict", h); err != nil {
		return err
	}
	if _, ok := m.keys[h]; !ok {
		return fmt.Errorf("memstore: no key at %s", h)
	}
	delete(m.keys, h)
	return nil
}

// DirStore keeps software keys as PEM files (one per handle) in a directory.
// For development on hosts without a TPM only: the private key is on disk.
type DirStore struct{ Dir string }

func (d DirStore) file(h Handle) string {
	return filepath.Join(d.Dir, fmt.Sprintf("key-%08x.pem", uint32(h)))
}

func (d DirStore) Exists(h Handle) (bool, error) {
	_, err := os.Stat(d.file(h))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (d DirStore) Open(h Handle) (sts.KeySigner, error) {
	b, err := os.ReadFile(d.file(h))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("dirstore: %s: no PEM block", d.file(h))
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return sts.SoftSigner{K: k}, nil
}

func (d DirStore) Create(h Handle) (sts.KeySigner, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(d.file(h), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrOccupied, h)
		}
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return sts.SoftSigner{K: k}, f.Close()
}

func (d DirStore) Evict(h Handle) error { return os.Remove(d.file(h)) }
