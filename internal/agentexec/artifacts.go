package agentexec

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
)

// Artifact is what a receipt references (section 8).
type Artifact struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ErrUnavailable: the artifact was removed (its leases ended and its floor passed); its tombstone remains.
var ErrUnavailable = errors.New("artifact_unavailable")

// Forever is the "until" of a lease held until it is released (the operation's, until the ack).
const Forever = math.MaxInt64

// PutArtifact stores data under its digest (content-addressed: the same bytes are one artifact), records who
// produced it and its retention floor, and leases it to holder until `until`.
func (s *Store) PutArtifact(ctx context.Context, dir string, k Key, kind string, data []byte, floor int64, holder string, until int64) (Artifact, error) {
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	a := Artifact{ID: h[:32], Kind: kind, SHA256: h, Size: int64(len(data))}
	p := filepath.Join(dir, a.ID)
	if _, err := os.Stat(p); err != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return a, err
		}
		if err := writeFileSync(p, data); err != nil {
			return a, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return a, err
	}
	defer tx.Rollback()
	// a re-put of removed content revives it
	if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts(id, kind, sha256, size, path, owner, op, attempt, floor)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET deleted = 0, floor = MAX(floor, excluded.floor)`,
		a.ID, kind, h, a.Size, p, k.Owner, k.Op, k.Attempt, floor); err != nil {
		return a, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO leases(artifact, holder, until) VALUES (?, ?, ?)
	  ON CONFLICT(artifact, holder) DO UPDATE SET until = MAX(until, excluded.until)`, a.ID, holder, until); err != nil {
		return a, err
	}
	return a, tx.Commit()
}

// Lease extends (or takes) holder's lease on an artifact; a removed artifact cannot be leased.
func (s *Store) Lease(ctx context.Context, id, holder string, until int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deleted int
	err = tx.QueryRowContext(ctx, `SELECT deleted FROM artifacts WHERE id = ?`, id).Scan(&deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnavailable
	} else if err != nil {
		return err
	}
	if deleted != 0 {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO leases(artifact, holder, until) VALUES (?, ?, ?)
	  ON CONFLICT(artifact, holder) DO UPDATE SET until = excluded.until`, id, holder, until); err != nil {
		return err
	}
	return tx.Commit()
}

// Release drops holder's lease (the ack drops only the operation's own).
func (s *Store) Release(ctx context.Context, id, holder string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM leases WHERE artifact = ? AND holder = ?`, id, holder)
	return err
}

// ReleaseHolder drops every lease a holder has.
func (s *Store) ReleaseHolder(ctx context.Context, holder string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM leases WHERE holder = ?`, holder)
	return err
}

// OpenArtifact returns an artifact's path, or ErrUnavailable with its tombstone.
func (s *Store) OpenArtifact(ctx context.Context, id string) (string, Artifact, error) {
	var a Artifact
	var path string
	var deleted int
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, sha256, size, path, deleted FROM artifacts WHERE id = ?`, id).
		Scan(&a.ID, &a.Kind, &a.SHA256, &a.Size, &path, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", a, ErrUnavailable
	}
	if err != nil {
		return "", a, err
	}
	if deleted != 0 {
		return "", a, ErrUnavailable
	}
	return path, a, nil
}

// GC removes artifacts that no live lease holds and whose floor has passed; each keeps a tombstone row.
func (s *Store) GC(ctx context.Context, now int64) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, path FROM artifacts a WHERE deleted = 0 AND floor < ?
	  AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.artifact = a.id AND l.until >= ?)`, now, now)
	if err != nil {
		return 0, err
	}
	type victim struct{ id, path string }
	var vs []victim
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.id, &v.path); err != nil {
			rows.Close()
			return 0, err
		}
		vs = append(vs, v)
	}
	rows.Close()
	n := 0
	for _, v := range vs {
		// mark first, then remove the bytes: a crash between leaves a tombstone over a stray file, never a row that
		// says available over missing bytes
		res, err := s.db.ExecContext(ctx, `UPDATE artifacts SET deleted = 1 WHERE id = ? AND deleted = 0
		  AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.artifact = ? AND l.until >= ?)`, v.id, v.id, now)
		if err != nil {
			return n, err
		}
		if k, _ := res.RowsAffected(); k == 1 {
			os.Remove(v.path)
			n++
		}
	}
	return n, nil
}

func writeFileSync(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, p)
}
