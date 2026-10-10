package keysvc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yard/internal/frontend"
)

// Outcome is a call's typed outcome as the caller knows it.
type Outcome int

const (
	OutUnknown Outcome = iota // no answer, a lost answer, 5xx, 503 stopped: verify before anything else
	OutDone                   // 200
	OutNotDone                // a definite refusal: nothing changed (400, 401, 409)
)

func (o Outcome) String() string {
	return [...]string{"unknown", "done", "notdone"}[o]
}

// Answer is halo_serve's answer to one request.
type Answer struct {
	Out    Outcome
	Status int    // 0: no answer
	Reason string // the error text (409/400), or the transport error
	Body   map[string]any
}

// Refusal classes of a 409 (yard_keys.cpp Register; serve.cpp spill/restore).
const (
	RefStale        = "stale"        // stale epoch: yard moved on
	RefFenced       = "fenced"       // revoked: the epoch is at or below the fence
	RefUsed         = "used"         // an attempt started; a usable checkpoint is not guaranteed
	RefReplay       = "replay"       // jti seen
	RefIncarnation  = "incarnation"  // the entry id names another halo incarnation: re-read
	RefNoSeal       = "noseal"       // open not right after a seal
	RefBusy         = "busy"         // a lease holds the slot: retry
	RefCancelled    = "cancelled"    // round 5: a revoke cancelled the operation: a new operation
	RefOutlived     = "outlived"     // round 5: the operation outlived its TTL: a new operation
	RefOpConflict   = "opconflict"   // round 5: the op id names another operation (a yard bug)
	RefBackpressure = "backpressure" // recent operation history is full: wait before retrying
	RefOther        = "other"
)

// Class names a 409's reason.
func (a Answer) Class() string {
	r := a.Reason
	switch {
	case strings.Contains(r, "stale epoch"):
		return RefStale
	case strings.HasPrefix(r, "revoked"):
		return RefFenced
	case strings.Contains(r, "already used"):
		return RefUsed
	case strings.Contains(r, "replayed"):
		return RefReplay
	case strings.Contains(r, "server incarnation"):
		return RefIncarnation
	case strings.Contains(r, "not right after a seal"):
		return RefNoSeal
	case strings.Contains(r, "holds a key"):
		return RefBusy
	case strings.Contains(r, "was cancelled by a revoke"):
		return RefCancelled
	case strings.Contains(r, "outlived its TTL"):
		return RefOutlived
	case strings.Contains(r, "already names another operation"):
		return RefOpConflict
	case strings.Contains(r, "too many recent operations"):
		return RefBackpressure
	}
	return RefOther
}

// Slot is a live key at halo (GET /admin/keys; never the key).
type Slot struct {
	Epoch   int64  `json:"epoch"`
	KeyName string `json:"key_name"`
	Entry   string `json:"entry"`
	InUse   bool   `json:"in_use"`
}

// HaloSess is one session of GET /admin/keys.
type HaloSess struct {
	Session        string `json:"session"`
	HighEpoch      int64  `json:"high_epoch"`
	RevokedThrough *int64 `json:"revoked_through"`
	SealedEpoch    *int64 `json:"sealed_epoch"`
	SpilledEpoch   int64  `json:"spilled_epoch"`
	RestoredEpoch  int64  `json:"restored_epoch"`
	Seal           *Slot  `json:"seal"`
	Open           *Slot  `json:"open"`
}

// KeysView is GET /admin/keys.
type KeysView struct {
	Incarnation string     `json:"incarnation"`
	Stopped     bool       `json:"stopped"`
	Sessions    []HaloSess `json:"sessions"`
}

// Sess returns a session's record (zero if halo has none).
func (v KeysView) Sess(s string) HaloSess {
	for _, x := range v.Sessions {
		if x.Session == s {
			return x
		}
	}
	return HaloSess{Session: s}
}

// Entry is one retained state of GET /admin/sessions.
type Entry struct {
	Key       uint64 `json:"key"`
	Spilled   bool   `json:"spilled"`
	Session   string `json:"session"`
	KeyID     string `json:"key_id"`
	YardBound bool   `json:"yard_bound"`
	EntryID   string `json:"entry_id"`
	FileBytes int64  `json:"file_bytes"`
}

// HaloAPI is what the key service calls on halo_serve's admin routes.
type HaloAPI interface {
	Register(ctx context.Context, sess, use, token string, key []byte) Answer
	Keys(ctx context.Context) (KeysView, error)
	Sessions(ctx context.Context) ([]Entry, error)
	Spill(ctx context.Context, entry uint64) Answer
	Restore(ctx context.Context, entry uint64) Answer
}

// HaloClient is an HTTP client of halo_serve's admin routes. The key route
// is served only on halo's admin Unix socket (same uid; halo checks
// SO_PEERCRED): NewUnixHalo. NewTCPHalo is for `--yard-keys-tcp 1` behind
// the tailnet's WireGuard only (the key is in the body; halo has no TLS).
type HaloClient struct {
	HTTP   *http.Client
	Base   string
	APIKey string // halo's --api-key (Authorization: Bearer), if set
}

// ErrPeer: the admin socket is not served by the expected uid.
var ErrPeer = errors.New("keysvc: halo admin socket peer is not the expected uid")

// NewUnixHalo dials halo's admin socket at path for every request. peerUID
// >= 0: the server end must be that uid (SO_PEERCRED / LOCAL_PEERCRED),
// so a socket left by another user is never sent a key.
func NewUnixHalo(path string, peerUID int, timeout time.Duration) *HaloClient {
	d := net.Dialer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := d.DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			if peerUID >= 0 {
				uid, err := frontend.PeerUID(c.(*net.UnixConn))
				if err != nil || int(uid) != peerUID {
					c.Close()
					return nil, fmt.Errorf("%w (%d, %v)", ErrPeer, uid, err)
				}
			}
			return c, nil
		},
		DisableKeepAlives: true, // one request per connection: a lost connection is one lost request
	}
	return &HaloClient{HTTP: &http.Client{Transport: tr, Timeout: timeout}, Base: "http://halo"}
}

// NewTCPHalo is the tailnet route (an explicit deployment choice).
func NewTCPHalo(base string, timeout time.Duration) *HaloClient {
	return &HaloClient{HTTP: &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}},
		Base: strings.TrimRight(base, "/")}
}

func (h *HaloClient) do(ctx context.Context, method, path string, body []byte) Answer {
	req, err := http.NewRequestWithContext(ctx, method, h.Base+path, bytes.NewReader(body))
	if err != nil {
		return Answer{Reason: err.Error()}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.HTTP.Do(req)
	if err != nil {
		return Answer{Reason: err.Error()} // unknown: the request may have landed
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Answer{Status: resp.StatusCode, Reason: err.Error()}
	}
	a := Answer{Status: resp.StatusCode}
	_ = json.Unmarshal(b, &a.Body)
	if e, ok := a.Body["error"].(string); ok {
		a.Reason = e
	}
	switch {
	case resp.StatusCode == 200:
		a.Out = OutDone
	case resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 409 || resp.StatusCode == 404:
		a.Out = OutNotDone
	default: // 500 not persisted, 503 stopped, anything else: unknown
		a.Out = OutUnknown
	}
	return a
}

var b64u = base64.RawURLEncoding

// Register is POST /admin/keys/{sess}. The body holds the key; it is
// cleared after the request is written.
func (h *HaloClient) Register(ctx context.Context, sess, use, token string, key []byte) Answer {
	var buf bytes.Buffer
	buf.WriteString(`{"token":`)
	tb, _ := json.Marshal(token)
	buf.Write(tb)
	buf.WriteString(`,"use":"` + use + `"`)
	if key != nil {
		buf.WriteString(`,"key":"`)
		k := make([]byte, b64u.EncodedLen(len(key)))
		b64u.Encode(k, key)
		buf.Write(k)
		clear(k)
		buf.WriteString(`"`)
	}
	buf.WriteString("}")
	body := buf.Bytes()
	defer clear(body)
	return h.do(ctx, "POST", "/admin/keys/"+sess, body)
}

func (h *HaloClient) Keys(ctx context.Context) (KeysView, error) {
	var v KeysView
	err := h.getJSON(ctx, "/admin/keys", &v)
	return v, err
}

func (h *HaloClient) Sessions(ctx context.Context) ([]Entry, error) {
	var v struct {
		Sessions []Entry `json:"sessions"`
	}
	err := h.getJSON(ctx, "/admin/sessions", &v)
	return v.Sessions, err
}

func (h *HaloClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", h.Base+path, nil)
	if err != nil {
		return err
	}
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("keysvc: GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func (h *HaloClient) Spill(ctx context.Context, entry uint64) Answer {
	return h.do(ctx, "POST", "/admin/sessions/"+strconv.FormatUint(entry, 10)+"/spill", nil)
}

func (h *HaloClient) Restore(ctx context.Context, entry uint64) Answer {
	return h.do(ctx, "POST", "/admin/sessions/"+strconv.FormatUint(entry, 10)+"/restore", nil)
}
