package sts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// SeqRecord is one line of the signer's append-only log. A record is written
// and fsynced BEFORE the token is signed (write-ahead), so a sequence number
// is never reused, even across a crash. A sign failure appends a second
// record with Status "sign_failed" for the same seq.
type SeqRecord struct {
	Seq    uint64 `json:"seq"`
	Status string `json:"status"` // "reserved" | "sign_failed"
	Iat    int64  `json:"iat,omitempty"`
	Exp    int64  `json:"exp,omitempty"`
	Aud    string `json:"aud,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Jti    string `json:"jti,omitempty"`
	Kid    string `json:"kid,omitempty"`
	UID    uint32 `json:"uid"`
	Prev   string `json:"prev"` // sha256 of the previous line (hash chain)
}

// SyncWriter is what the log needs from its file: append + fsync.
type SyncWriter interface {
	io.Writer
	Sync() error
}

// SeqLog hands out strictly increasing sequence numbers.
type SeqLog struct {
	w    SyncWriter
	last uint64
	prev string
}

// ScanLog reads an existing log and returns the last seq and the hash of the
// last line. It is called before cap_enter. A malformed line is an error
// (fail closed): the operator must inspect the log.
func ScanLog(r io.Reader) (last uint64, prev string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	prev = "genesis"
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var rec SeqRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return 0, "", fmt.Errorf("seqlog line %d: %w", line, err)
		}
		if rec.Prev != prev {
			return 0, "", fmt.Errorf("seqlog line %d: hash chain broken", line)
		}
		switch rec.Status {
		case "reserved":
			if rec.Seq != last+1 {
				return 0, "", fmt.Errorf("seqlog line %d: reserved seq %d, want %d (gap or reuse)", line, rec.Seq, last+1)
			}
		case "sign_failed":
			if rec.Seq != last {
				return 0, "", fmt.Errorf("seqlog line %d: sign_failed seq %d, want %d", line, rec.Seq, last)
			}
		default:
			return 0, "", fmt.Errorf("seqlog line %d: unknown status %q", line, rec.Status)
		}
		last = rec.Seq
		h := sha256.Sum256(b)
		prev = hex.EncodeToString(h[:])
	}
	return last, prev, sc.Err()
}

// OpenSeqLogFile opens (creating) an append-only log file and scans it.
// The returned *os.File is the descriptor that is rights-limited later.
func OpenSeqLogFile(path string) (*SeqLog, *os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, err
	}
	last, prev, err := ScanLog(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return &SeqLog{w: f, last: last, prev: prev}, f, nil
}

// NewSeqLog wraps an arbitrary writer (tests).
func NewSeqLog(w SyncWriter, last uint64, prev string) *SeqLog {
	if prev == "" {
		prev = "genesis"
	}
	return &SeqLog{w: w, last: last, prev: prev}
}

// Last returns the last sequence number handed out.
func (l *SeqLog) Last() uint64 { return l.last }

func (l *SeqLog) append(rec SeqRecord) error {
	rec.Prev = l.prev
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("seqlog write: %w", err)
	}
	if err := l.w.Sync(); err != nil {
		return fmt.Errorf("seqlog fsync: %w", err)
	}
	h := sha256.Sum256(b)
	l.prev = hex.EncodeToString(h[:])
	return nil
}

// Reserve durably records the next seq. Callers must hold the minter lock.
func (l *SeqLog) Reserve(rec SeqRecord) (uint64, error) {
	rec.Seq = l.last + 1
	rec.Status = "reserved"
	if err := l.append(rec); err != nil {
		// Do not advance: nothing was durably reserved. But the writer may be
		// in an unknown state, so the minter fails closed from now on.
		return 0, err
	}
	l.last = rec.Seq
	return rec.Seq, nil
}

// MarkFailed appends a sign_failed record for seq.
func (l *SeqLog) MarkFailed(seq uint64, uid uint32) error {
	if seq != l.last {
		return errors.New("seqlog: MarkFailed out of order")
	}
	return l.append(SeqRecord{Seq: seq, Status: "sign_failed", UID: uid})
}
