// Package wskey is yard-ctl's key service for data keys it hands to
// consumers that encrypt with them: ZFS workspace encryption roots (SR1
// layout D, one raw key per project, ws/<project>) and, by the same
// hierarchy, halo_serve's per-checkpoint spill keys (IDENTITY.md "Spill
// keys", "Workspace and spill keys"). The model is spec/keys.
//
// Hierarchy:
//
//	KEK   32 bytes, never stored: HKDF-SHA256 of an RSASSA-PKCS1-v1_5
//	      signature by a dedicated non-exportable TPM key (deterministic,
//	      so the TPM recomputes it at every start; KEKFromSigner), or, for
//	      tests and the SR1 e2e, a 32-byte file (KEKFromFile).
//	data  32 random bytes per (consumer, subject, version), wrapped with
//	key   AES-256-GCM under the KEK, AAD = consumer|subject|version, in
//	      yard-ctl's SQLite (table wskeys). Unwrapped only to hand to the
//	      consumer (zfs load-key on stdin; a halo registration).
//
// Crypto-shred of a subject: Shred overwrites and deletes the wrapped key
// with secure_delete on and checkpoints the WAL. It is complete only when
// no other copy of the wrapped key survives: no snapshot of the dataset
// holding the database, no backup of it within its retention, and the KEK
// still never left the TPM (decisions in STATE.md SR1).
package wskey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	_ "modernc.org/sqlite"

	"yard/internal/sts"
)

// Consumers.
const (
	ConsumerZFS   = "zfs"   // a workspace project's encryption root
	ConsumerSpill = "spill" // a halo_serve session spill (per checkpoint)
)

// KEK wraps and unwraps data keys.
type KEK struct{ aead cipher.AEAD }

func newKEK(k []byte) (*KEK, error) {
	if len(k) != 32 {
		return nil, fmt.Errorf("wskey: KEK must be 32 bytes, got %d", len(k))
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &KEK{aead: a}, nil
}

// KEKFromFile reads a 32-byte raw KEK (tests, the SR1 e2e). The file must
// not be readable by group or others.
func KEKFromFile(path string) (*KEK, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("wskey: KEK file %s is mode %v; want 0400 or 0600", path, fi.Mode().Perm())
	}
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return newKEK(k)
}

// KEKLabel is what the TPM key signs to derive the KEK. Changing it
// changes the KEK (every wrapped key would become unreadable).
const KEKLabel = "yard wskey KEK v1"

// KEKFromSigner derives the KEK from a deterministic signature: RSASSA-
// PKCS1-v1_5 gives the same signature for the same key and message, so a
// non-exportable TPM key recomputes the same KEK at every start, and
// nothing else can. The signing key must be dedicated to this (not one of
// the rotating STS keys: a rotation would lose every wrapped key).
func KEKFromSigner(s sts.KeySigner) (*KEK, error) {
	d := sha256.Sum256([]byte(KEKLabel))
	sig, err := s.SignPKCS1v15SHA256(d[:])
	if err != nil {
		return nil, fmt.Errorf("wskey: KEK signature: %w", err)
	}
	sig2, err := s.SignPKCS1v15SHA256(d[:])
	if err != nil {
		return nil, fmt.Errorf("wskey: KEK signature: %w", err)
	}
	if string(sig) != string(sig2) {
		return nil, errors.New("wskey: the signer is not deterministic (want RSASSA-PKCS1-v1_5)")
	}
	k, err := hkdf.Key(sha256.New, sig, []byte("yard-wskey"), "kek", 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return newKEK(k)
}

func aad(consumer, subject string, version int64) []byte {
	return []byte(consumer + "|" + subject + "|" + strconv.FormatInt(version, 10))
}

// Wrap seals key for (consumer, subject, version).
func (k *KEK) Wrap(consumer, subject string, version int64, key []byte) ([]byte, error) {
	n := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, err
	}
	return k.aead.Seal(n, n, key, aad(consumer, subject, version)), nil
}

// Unwrap opens a wrapped key; it fails for any other (consumer, subject,
// version) or KEK.
func (k *KEK) Unwrap(consumer, subject string, version int64, blob []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("wskey: wrapped key too short")
	}
	key, err := k.aead.Open(nil, blob[:ns], blob[ns:], aad(consumer, subject, version))
	if err != nil {
		return nil, errors.New("wskey: wrapped key does not open under this KEK and identity")
	}
	return key, nil
}

// Store keeps wrapped keys in yard-ctl's SQLite database (its own table;
// the lifecycle store may share the file).
type Store struct {
	db  *sql.DB
	kek *KEK
}

// State of a key row.
const (
	Live     = "live"
	Shredded = "shredded"
)

var (
	ErrNoKey    = errors.New("wskey: no live key")
	ErrExists   = errors.New("wskey: a live key exists")
	subjectRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	consumersOK = map[string]bool{ConsumerZFS: true, ConsumerSpill: true}
)

const schema = `
CREATE TABLE IF NOT EXISTS wskeys (
  consumer TEXT NOT NULL, subject TEXT NOT NULL, version INTEGER NOT NULL,
  wrapped BLOB, state TEXT NOT NULL, created_at INTEGER NOT NULL, shredded_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (consumer, subject, version));`

// Open opens the key table in the SQLite database at path.
func Open(path string, kek *KEK) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)" +
		"&_pragma=secure_delete(ON)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("wskey: schema: %w", err)
	}
	return &Store{db: db, kek: kek}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func check(consumer, subject string) error {
	if !consumersOK[consumer] {
		return fmt.Errorf("wskey: consumer %q", consumer)
	}
	if !subjectRe.MatchString(subject) {
		return fmt.Errorf("wskey: subject %q", subject)
	}
	return nil
}

// Create draws a fresh random key for (consumer, subject), wraps it and
// stores it as version 1 (or the next version after shredded ones). It
// refuses while a live key exists. The caller hands the returned key to
// the consumer and clears it.
func (s *Store) Create(consumer, subject string, now int64) (key []byte, version int64, err error) {
	if err := check(consumer, subject); err != nil {
		return nil, 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var live int
	if err := tx.QueryRow(`SELECT count(*) FROM wskeys WHERE consumer = ? AND subject = ? AND state = ?`,
		consumer, subject, Live).Scan(&live); err != nil {
		return nil, 0, err
	}
	if live > 0 {
		return nil, 0, fmt.Errorf("%w for %s/%s", ErrExists, consumer, subject)
	}
	if err := tx.QueryRow(`SELECT coalesce(max(version), 0) + 1 FROM wskeys WHERE consumer = ? AND subject = ?`,
		consumer, subject).Scan(&version); err != nil {
		return nil, 0, err
	}
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, 0, err
	}
	w, err := s.kek.Wrap(consumer, subject, version, key)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`INSERT INTO wskeys (consumer, subject, version, wrapped, state, created_at) VALUES (?,?,?,?,?,?)`,
		consumer, subject, version, w, Live, now); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return key, version, nil
}

// Key unwraps the live key of (consumer, subject). The caller clears it
// after use.
func (s *Store) Key(consumer, subject string) (key []byte, version int64, err error) {
	if err := check(consumer, subject); err != nil {
		return nil, 0, err
	}
	var w []byte
	err = s.db.QueryRow(`SELECT version, wrapped FROM wskeys WHERE consumer = ? AND subject = ? AND state = ?`,
		consumer, subject, Live).Scan(&version, &w)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, fmt.Errorf("%w for %s/%s", ErrNoKey, consumer, subject)
	}
	if err != nil {
		return nil, 0, err
	}
	key, err = s.kek.Unwrap(consumer, subject, version, w)
	return key, version, err
}

// Shred deletes the live key of (consumer, subject): the row keeps its
// identity and times (state shredded, wrapped NULL); secure_delete zeroes
// the freed bytes and the WAL is checkpointed and truncated. Idempotent.
// The caller must first make sure no consumer holds the key and no copy of
// a load can still install it (spec/keys: shred after settle).
func (s *Store) Shred(consumer, subject string, now int64) error {
	if err := check(consumer, subject); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE wskeys SET wrapped = NULL, state = ?, shredded_at = ? WHERE consumer = ? AND subject = ? AND state = ?`,
		Shredded, now, consumer, subject, Live); err != nil {
		return err
	}
	_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Row is a key's metadata (never the key).
type Row struct {
	Consumer, Subject, State string
	Version                  int64
	CreatedAt, ShreddedAt    int64
}

// List returns every key row of a consumer.
func (s *Store) List(consumer string) ([]Row, error) {
	rows, err := s.db.Query(`SELECT consumer, subject, version, state, created_at, shredded_at FROM wskeys
		WHERE consumer = ? ORDER BY subject, version`, consumer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Consumer, &r.Subject, &r.Version, &r.State, &r.CreatedAt, &r.ShreddedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
