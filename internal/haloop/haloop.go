// Package haloop is a client for halo-flash's operation API (halo-flash docs/OPERATIONS.md; cordis RFC 0007), as the
// broker uses it for the local route (design/AGENT-OPERATIONS.md section 6): one model call is one operation, whose
// observation stream is relayed to the harness and whose record resolves a lost answer while halo still holds it.
//
// Every verb carries Halo-Incarnation, Halo-Not-After and Halo-Digest; the digest is the SHA-256 of the submit's
// body bytes, which are kept and resent unchanged. Records live as long as halo's incarnation: an `unknown` (another
// incarnation), a `closed`, or a `never_accepted` past the deadline cannot be resolved, and the caller keeps its
// conservative charge.
package haloop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Client struct {
	Base      string // http://127.0.0.1:18080
	Key       string // halo's API key (the broker's, never the harness's)
	Principal string // X-Halo-Principal
	HTTP      *http.Client
}

// Contract is what the broker needs from GET /v1/halo/contract.
type Contract struct {
	Incarnation string `json:"incarnation"`
	TimeMs      int64  `json:"time_ms"`
	Inference   struct {
		Mode string `json:"mode"`
	} `json:"inference"`
}

// Op identifies one attempt and binds it: incarnation, deadline and the exact submit bytes.
type Op struct {
	ID          string
	Attempt     uint64
	Incarnation string
	NotAfter    int64
	Body        []byte // the submit body, exactly as first sent
	Digest      string
}

// Usage as halo reports it: disjoint prompt, cached and completion tokens.
type Usage struct {
	Prompt     int64   `json:"prompt_tokens"`
	Cached     int64   `json:"cached_tokens"`
	Completion int64   `json:"completion_tokens"`
	EngineMs   float64 `json:"engine_ms"`
}

// Status is an operation's status view.
type Status struct {
	OperationID     string `json:"operation_id"`
	Attempt         uint64 `json:"attempt"`
	Status          string `json:"status"`
	Digest          string `json:"digest"`
	CancelRequested bool   `json:"cancel_requested"`
	Finish          string `json:"finish"`
	Usage           *Usage `json:"usage"`
	ExpiresAt       int64  `json:"expires_at"`
}

// Terminal statuses, and the ones whose usage resolves a call.
func (s Status) HasUsage() bool {
	return s.Usage != nil && (s.Status == "done" || s.Status == "released" || s.Status == "expired")
}

// NeverRan says the attempt was never accepted, finally: closed (its deadline passed) or cancelled_before_accept.
// Nothing ran, so a caller may settle at zero. `unknown` (another incarnation) is not this: the record is lost and
// the caller keeps its conservative charge.
func (s Status) NeverRan() bool { return s.Status == "closed" || s.Status == "cancelled_before_accept" }

func (c *Client) do(ctx context.Context, method, path string, body []byte, op *Op) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	if c.Principal != "" {
		req.Header.Set("X-Halo-Principal", c.Principal)
	}
	if op != nil {
		req.Header.Set("Halo-Incarnation", op.Incarnation)
		req.Header.Set("Halo-Not-After", strconv.FormatInt(op.NotAfter, 10))
		req.Header.Set("Halo-Digest", op.Digest)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

func (c *Client) Contract(ctx context.Context) (Contract, error) {
	var k Contract
	resp, err := c.do(ctx, "GET", "/v1/halo/contract", nil, nil)
	if err != nil {
		return k, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return k, fmt.Errorf("haloop: contract: HTTP %d", resp.StatusCode)
	}
	return k, json.NewDecoder(resp.Body).Decode(&k)
}

// NewOp builds an attempt's exact submit body. Its bytes, and so its digest, never change afterwards.
func NewOp(id string, attempt uint64, incarnation string, notAfter int64, api, mode string, request json.RawMessage) (*Op, error) {
	body, err := json.Marshal(struct {
		OperationID string          `json:"operation_id"`
		Attempt     uint64          `json:"attempt"`
		NotAfter    int64           `json:"not_after"`
		API         string          `json:"api"`
		Request     json.RawMessage `json:"request"`
		Mode        string          `json:"mode"`
	}{id, attempt, notAfter, api, request, mode})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &Op{ID: id, Attempt: attempt, Incarnation: incarnation, NotAfter: notAfter, Body: body,
		Digest: hex.EncodeToString(sum[:])}, nil
}

func (o *Op) path(suffix string) string {
	return "/v1/operations/" + o.ID + "/" + strconv.FormatUint(o.Attempt, 10) + suffix
}

// Answer is a verb's HTTP status with its decoded view (when the body was one) and raw body.
type Answer struct {
	Code       int
	View       Status
	RetryAfter string
	Raw        []byte
}

func (c *Client) answer(resp *http.Response) (Answer, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	a := Answer{Code: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After"), Raw: raw}
	if err != nil {
		return a, err
	}
	_ = json.Unmarshal(raw, &a.View) // error bodies are not views; View stays empty
	return a, nil
}

// Submit sends (or resends) the attempt's exact body. 202 accepted; a duplicate gets the current status; 409 stale
// incarnation or conflict; 410 past not_after; 429/503 a refusal of this copy only.
func (c *Client) Submit(ctx context.Context, o *Op) (Answer, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.Base, "/")+"/v1/operations", bytes.NewReader(o.Body))
	if err != nil {
		return Answer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Halo-Incarnation", o.Incarnation)
	req.Header.Set("Halo-Digest", o.Digest)
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	if c.Principal != "" {
		req.Header.Set("X-Halo-Principal", c.Principal)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Answer{}, err
	}
	return c.answer(resp)
}

func (c *Client) Status(ctx context.Context, o *Op) (Answer, error) {
	resp, err := c.do(ctx, "GET", o.path(""), nil, o)
	if err != nil {
		return Answer{}, err
	}
	return c.answer(resp)
}

// Result fetches the final body while halo holds it.
func (c *Client) Result(ctx context.Context, o *Op) (Answer, error) {
	resp, err := c.do(ctx, "GET", o.path("/result"), nil, o)
	if err != nil {
		return Answer{}, err
	}
	return c.answer(resp)
}

// Stream opens the observation stream from event `from` (SSE frames of the operation's API). Leaving it is an
// observer departing, never a cancel. The caller closes the body.
func (c *Client) Stream(ctx context.Context, o *Op, from int) (*http.Response, error) {
	return c.do(ctx, "GET", o.path("/stream?from="+strconv.Itoa(from)), nil, o)
}

func (c *Client) Cancel(ctx context.Context, o *Op) (Answer, error) {
	resp, err := c.do(ctx, "POST", o.path("/cancel"), []byte{}, o)
	if err != nil {
		return Answer{}, err
	}
	return c.answer(resp)
}

// Ack tells halo the caller has durably committed the result: halo releases the body.
func (c *Client) Ack(ctx context.Context, o *Op) (Answer, error) {
	resp, err := c.do(ctx, "POST", o.path("/ack"), []byte{}, o)
	if err != nil {
		return Answer{}, err
	}
	return c.answer(resp)
}
