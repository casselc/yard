// Package tpmkey creates, opens, uses and evicts persistent non-exportable
// RSA-2048 RS256 signing keys in a TPM 2.0 via google/go-tpm (pure Go).
//
// Key shape: a child of a transient ECC SRK under the owner hierarchy,
// attributes fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign|noDA,
// RSASSA-SHA256 scheme, empty auth, no PCR policy (CONTROL-PLANE §3.1),
// made persistent with EvictControl. The SRK is flushed afterwards; a
// persistent object does not need its parent loaded to sign.
package tpmkey

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Default handles in the owner persistent range (0x81000000-0x817FFFFF).
const (
	ActiveHandle  tpm2.TPMHandle = 0x81010010
	StandbyHandle tpm2.TPMHandle = 0x81010011
)

func signTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			KeyBits: 2048,
		}),
	}
}

// ListPersistent returns all persistent handles currently defined.
func ListPersistent(t transport.TPM) ([]tpm2.TPMHandle, error) {
	var out []tpm2.TPMHandle
	prop := uint32(tpm2.TPMHTPersistent) << 24
	for {
		rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: prop, PropertyCount: 64}.Execute(t)
		if err != nil {
			return nil, err
		}
		hs, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return nil, err
		}
		out = append(out, hs.Handle...)
		if !rsp.MoreData || len(hs.Handle) == 0 {
			return out, nil
		}
		prop = uint32(hs.Handle[len(hs.Handle)-1]) + 1
	}
}

// Timings records how long each TPM step took.
type Timings struct {
	SRK, Create, Load, Evict time.Duration
}

// ErrHandleInUse is returned when the target persistent handle is occupied.
var ErrHandleInUse = errors.New("tpmkey: persistent handle already in use")

// CreatePersistent creates a new key and persists it at handle. It refuses
// to overwrite an existing persistent object.
func CreatePersistent(t transport.TPM, handle tpm2.TPMHandle) (*rsa.PublicKey, Timings, error) {
	var tm Timings
	hs, err := ListPersistent(t)
	if err != nil {
		return nil, tm, fmt.Errorf("list persistent: %w", err)
	}
	for _, h := range hs {
		if h == handle {
			return nil, tm, fmt.Errorf("%w: 0x%08x", ErrHandleInUse, uint32(handle))
		}
	}
	t0 := time.Now()
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, tm, fmt.Errorf("create SRK (owner auth set?): %w", err)
	}
	tm.SRK = time.Since(t0)
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(t)
	parent := tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)}

	t0 = time.Now()
	cr, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(signTemplate())}.Execute(t)
	if err != nil {
		return nil, tm, fmt.Errorf("create key: %w", err)
	}
	tm.Create = time.Since(t0)

	t0 = time.Now()
	ld, err := tpm2.Load{ParentHandle: parent, InPrivate: cr.OutPrivate, InPublic: cr.OutPublic}.Execute(t)
	if err != nil {
		return nil, tm, fmt.Errorf("load key: %w", err)
	}
	tm.Load = time.Since(t0)
	defer tpm2.FlushContext{FlushHandle: ld.ObjectHandle}.Execute(t)

	t0 = time.Now()
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: ld.ObjectHandle, Name: ld.Name},
		PersistentHandle: handle,
	}).Execute(t); err != nil {
		return nil, tm, fmt.Errorf("evictcontrol persist: %w", err)
	}
	tm.Evict = time.Since(t0)
	k, err := Open(t, handle)
	if err != nil {
		return nil, tm, err
	}
	return k.pub, tm, nil
}

// Key is an opened persistent signing key. It implements sts.KeySigner.
type Key struct {
	mu     sync.Mutex
	t      transport.TPM
	Handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    *rsa.PublicKey
}

// Open reads the public area of a persistent key and checks that it is a
// non-exportable RSA-2048 RSASSA-SHA256 signing key.
func Open(t transport.TPM, handle tpm2.TPMHandle) (*Key, error) {
	rp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("readpublic 0x%08x: %w", uint32(handle), err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	if pub.Type != tpm2.TPMAlgRSA {
		return nil, errors.New("tpmkey: not an RSA key")
	}
	a := pub.ObjectAttributes
	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.SignEncrypt || a.Decrypt || a.Restricted {
		return nil, fmt.Errorf("tpmkey: unexpected attributes %+v (want fixedTPM, fixedParent, sensitiveDataOrigin, sign, !decrypt, !restricted)", a)
	}
	det, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, err
	}
	if det.KeyBits != 2048 {
		return nil, fmt.Errorf("tpmkey: %d-bit key", det.KeyBits)
	}
	uniq, err := pub.Unique.RSA()
	if err != nil {
		return nil, err
	}
	rpub, err := tpm2.RSAPub(det, uniq)
	if err != nil {
		return nil, err
	}
	return &Key{t: t, Handle: handle, name: rp.Name, pub: rpub}, nil
}

// Public returns the RSA public key.
func (k *Key) Public() *rsa.PublicKey { return k.pub }

// SignPKCS1v15SHA256 signs a SHA-256 digest inside the TPM.
func (k *Key) SignPKCS1v15SHA256(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("tpmkey: digest must be 32 bytes")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: k.Handle, Name: k.name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(k.t)
	if err != nil {
		return nil, err
	}
	s, err := rsp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, err
	}
	return s.Sig.Buffer, nil
}

// Evict removes the persistent key at handle (owner auth, assumed empty).
func Evict(t transport.TPM, handle tpm2.TPMHandle) error {
	rp, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(t)
	if err != nil {
		return fmt.Errorf("readpublic 0x%08x: %w", uint32(handle), err)
	}
	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: handle, Name: rp.Name},
		PersistentHandle: handle,
	}.Execute(t)
	return err
}
