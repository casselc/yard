package keyring

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"yard/internal/sts"
	"yard/internal/tpmkey"
)

// TPMStore keeps keys as persistent, non-exportable RSA-2048 objects in a
// TPM 2.0. T must be the thread-locked transport (tpmkey.Dev on FreeBSD):
// the tpm20(4) driver wedges until reboot if a response is read from a
// different OS thread than the one that wrote the command (CONTROL-PLANE,
// "FreeBSD tpm20(4) wedge").
type TPMStore struct{ T transport.TPM }

func checkHandle(h Handle) error {
	if h < 0x81000000 || h > 0x817FFFFF {
		return fmt.Errorf("tpmstore: handle %s outside the owner persistent range", h)
	}
	return nil
}

func (s TPMStore) Exists(h Handle) (bool, error) {
	if err := checkHandle(h); err != nil {
		return false, err
	}
	hs, err := tpmkey.ListPersistent(s.T)
	if err != nil {
		return false, err
	}
	for _, x := range hs {
		if uint32(x) == uint32(h) {
			return true, nil
		}
	}
	return false, nil
}

func (s TPMStore) Open(h Handle) (sts.KeySigner, error) {
	if err := checkHandle(h); err != nil {
		return nil, err
	}
	return tpmkey.Open(s.T, tpm2.TPMHandle(h))
}

func (s TPMStore) Create(h Handle) (sts.KeySigner, error) {
	if err := checkHandle(h); err != nil {
		return nil, err
	}
	if _, _, err := tpmkey.CreatePersistent(s.T, tpm2.TPMHandle(h)); err != nil {
		return nil, err
	}
	return tpmkey.Open(s.T, tpm2.TPMHandle(h))
}

func (s TPMStore) Evict(h Handle) error {
	if err := checkHandle(h); err != nil {
		return err
	}
	return tpmkey.Evict(s.T, tpm2.TPMHandle(h))
}
