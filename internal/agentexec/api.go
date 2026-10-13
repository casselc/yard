package agentexec

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"yard/internal/jsonshape"
)

// The envelope (cordis RFC 0007, as yard serves it; section 3). Every verb carries Yard-Incarnation; status,
// result, cancel and ack also carry Yard-Not-After and Yard-Digest (the SHA-256 of the submit body's bytes). Every
// answer carries Yard-Incarnation and Yard-Time. The owner is X-Yard-Principal.
//
//	GET  /v1/yard/contract
//	POST /v1/operations                            submit (202 accepted; a duplicate gets its status)
//	GET  /v1/operations/{op}/{attempt}             status
//	GET  /v1/operations/{op}/{attempt}/result      the outcome, while held
//	POST /v1/operations/{op}/{attempt}/cancel
//	POST /v1/operations/{op}/{attempt}/ack         the caller committed the outcome: the record is released
//	GET  /v1/artifacts/{id}                        the bytes, or 410 artifact_unavailable with the tombstone
//	POST /v1/artifacts/{id}/leases                 {holder, until} (Yard-Time ms)
//	DELETE /v1/artifacts/{id}/leases/{holder}
//	GET  /v1/yard/corrections?after=N              the owner's corrections after sequence N

var opIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func (e *Exec) Handler(apiKey string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/yard/contract", e.contract)
	mux.HandleFunc("POST /v1/operations", e.submit)
	mux.HandleFunc("GET /v1/operations/{op}/{attempt}", e.verb)
	mux.HandleFunc("GET /v1/operations/{op}/{attempt}/result", e.verb)
	mux.HandleFunc("POST /v1/operations/{op}/{attempt}/cancel", e.verb)
	mux.HandleFunc("POST /v1/operations/{op}/{attempt}/ack", e.verb)
	mux.HandleFunc("GET /v1/artifacts/{id}", e.artifact)
	mux.HandleFunc("POST /v1/artifacts/{id}/leases", e.lease)
	mux.HandleFunc("DELETE /v1/artifacts/{id}/leases/{holder}", e.unlease)
	mux.HandleFunc("GET /v1/yard/corrections", e.corrections)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Yard-Incarnation", e.cfg.Store.Inc)
		w.Header().Set("Yard-Time", strconv.FormatInt(e.now(), 10))
		if apiKey != "" && r.Header.Get("Authorization") != "Bearer "+apiKey {
			reply(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, code int, reason, msg string) {
	reply(w, code, map[string]any{"refused": reason, "error": msg})
}

func (e *Exec) contract(w http.ResponseWriter, r *http.Request) {
	vals := map[string]any{}
	for d := range e.cfg.Valuations {
		vals[d] = map[string]any{"current": d == e.cfg.Current}
	}
	reply(w, 200, map[string]any{
		"incarnation": e.cfg.Store.Inc, "time_ms": e.now(),
		"operations": map[string]any{
			"apis": []string{"agent"}, "owner": "X-Yard-Principal", "digest": "sha256 (hex) of the submit body",
			"max_submit_age_ms": e.cfg.MaxSubmitAgeMs, "max_running": e.cfg.MaxRunning,
			"clock": "Yard-Time: persistent logical ms; never repeats or goes back across restarts",
		},
		"agent": map[string]any{
			"agents": []string{"claude"}, "routes": []string{"local"}, "repos": keys(e.cfg.Repos),
			"ceilings": e.cfg.Ceilings, "valuations": vals, "current_valuation": e.cfg.Current,
			"outcomes":   []string{"completed", "insufficient", "invalid_output", "budget_exhausted", "timeout", "cancelled", "worker_failed"},
			"execution":  []string{"stopped", "unconfirmed"},
			"certainty":  []string{"exact", "bounded"},
			"guarantees": "no effect outside the VM but metered model calls; a repeat spends again and may differ",
		},
	})
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// view is a status answer.
func view(rec Rec) map[string]any {
	v := map[string]any{"operation_id": rec.Op, "attempt": rec.Attempt, "status": rec.Status, "digest": rec.Digest}
	switch rec.Status {
	case StRunning:
		v["stage"], v["cancel_requested"] = rec.Stage, rec.Cancel
	case StDone, StReleased:
		v["outcome"] = rec.Outcome
	}
	return v
}

// validate checks a task against the runner configuration: a refusal reason, or "".
func (e *Exec) validate(t Task) (int, string, string) {
	switch {
	case t.Agent != "claude":
		return 403, "not_permitted", "agent " + t.Agent
	case t.Route != "local":
		return 403, "not_permitted", "route " + t.Route
	case e.cfg.Repos[t.Input.Repo] == "":
		return 403, "not_permitted", "repository " + t.Input.Repo
	case t.Valuation != e.cfg.Current:
		return 409, "valuation_changed", "the current valuation is " + e.cfg.Current
	case t.Limits.Tokens <= 0 || t.Limits.Charge <= 0 || t.Limits.Seconds <= 0 || t.Limits.Money < 0:
		return 422, "limits_missing", "tokens, charge, money_micro_usd and seconds are each required"
	case t.Limits.Tokens > e.cfg.Ceilings.Tokens || t.Limits.Charge > e.cfg.Ceilings.Charge ||
		t.Limits.Money > e.cfg.Ceilings.Money || t.Limits.Seconds > e.cfg.Ceilings.Seconds:
		return 403, "not_permitted", "limits above the ceilings"
	case len(t.Instructions) == 0:
		return 422, "invalid_task", "no instructions"
	}
	if _, err := jsonshape.Parse(t.Output); err != nil {
		return 422, "invalid_task", "output schema: " + err.Error()
	}
	return 0, "", ""
}

func (e *Exec) submit(w http.ResponseWriter, r *http.Request) {
	inc := r.Header.Get("Yard-Incarnation")
	if inc == "" {
		reply(w, 400, map[string]string{"error": "a submit names its incarnation (Yard-Incarnation)"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		reply(w, 413, map[string]string{"error": "body too large"})
		return
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if d := r.Header.Get("Yard-Digest"); d != "" && d != digest {
		reply(w, 400, map[string]string{"error": "Yard-Digest is not the SHA-256 of the body"})
		return
	}
	var b struct {
		OperationID string          `json:"operation_id"`
		Attempt     *uint64         `json:"attempt"`
		NotAfter    *int64          `json:"not_after"`
		API         string          `json:"api"`
		Request     json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(body, &b); err != nil || !opIDRe.MatchString(b.OperationID) || b.Attempt == nil ||
		b.NotAfter == nil || b.API != "agent" || len(b.Request) == 0 {
		reply(w, 400, map[string]string{"error": "operation_id, attempt, not_after, api \"agent\" and request are required"})
		return
	}
	if inc != e.cfg.Store.Inc {
		reply(w, 409, map[string]string{"error": "stale incarnation", "status": "unknown"})
		return
	}
	k := Key{Owner: r.Header.Get("X-Yard-Principal"), Op: b.OperationID, Attempt: *b.Attempt}
	now := e.now()
	if rec, err := e.cfg.Store.Get(r.Context(), k); err == nil { // a duplicate, or a conflict
		if rec.Digest != digest {
			reply(w, 409, map[string]any{"error": "conflict: another submit holds this attempt", "status": rec.Status})
			return
		}
		reply(w, 200, view(rec))
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if *b.NotAfter < now {
		reply(w, 410, map[string]any{"status": "closed", "error": "past not_after"})
		return
	}
	if *b.NotAfter-now > e.cfg.MaxSubmitAgeMs {
		reply(w, 400, map[string]string{"error": fmt.Sprintf("not_after is more than %d ms ahead", e.cfg.MaxSubmitAgeMs)})
		return
	}
	var t Task
	if err := json.Unmarshal(b.Request, &t); err != nil {
		refuse(w, 422, "invalid_task", err.Error())
		return
	}
	if code, reason, msg := e.validate(t); code != 0 {
		refuse(w, code, reason, msg) // a refusal closes this copy only; nothing is recorded
		return
	}
	running, _ := e.cfg.Store.Running(r.Context())
	if e.cfg.MaxRunning > 0 && len(running) >= e.cfg.MaxRunning {
		w.Header().Set("Retry-After", "10")
		refuse(w, 429, "capacity", "the executor is at its running limit")
		return
	}
	if _, _, err := BuildInput(e.cfg.Repos[t.Input.Repo], t.Input.Commit, t.Change, e.cfg.ImageDir); err != nil {
		refuse(w, 422, "input_unavailable", err.Error())
		return
	}
	rec, inserted, err := e.cfg.Store.Accept(r.Context(), Rec{Key: k, Digest: digest, NotAfter: *b.NotAfter, Body: body,
		Status: StRunning, Stage: StageAccepted, Created: now})
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if !inserted && rec.Digest != digest {
		reply(w, 409, map[string]any{"error": "conflict", "status": rec.Status})
		return
	}
	e.launch(k)
	code := 202
	if !inserted {
		code = 200
	}
	reply(w, code, view(rec))
}

func (e *Exec) verb(w http.ResponseWriter, r *http.Request) {
	att, err := strconv.ParseUint(r.PathValue("attempt"), 10, 64)
	if err != nil || !opIDRe.MatchString(r.PathValue("op")) {
		reply(w, 404, map[string]string{"error": "no such operation route"})
		return
	}
	inc, nah, digest := r.Header.Get("Yard-Incarnation"), r.Header.Get("Yard-Not-After"), r.Header.Get("Yard-Digest")
	notAfter, perr := strconv.ParseInt(nah, 10, 64)
	if inc == "" || digest == "" || perr != nil {
		reply(w, 400, map[string]string{"error": "every verb carries Yard-Incarnation, Yard-Not-After and Yard-Digest"})
		return
	}
	k := Key{Owner: r.Header.Get("X-Yard-Principal"), Op: r.PathValue("op"), Attempt: att}
	what := ""
	if i := strings.LastIndex(r.URL.Path, "/"); i >= 0 {
		switch tail := r.URL.Path[i+1:]; tail {
		case "result", "cancel", "ack":
			what = tail
		}
	}
	if inc != e.cfg.Store.Inc { // another incarnation: this store never knew the attempt
		reply(w, 200, map[string]any{"operation_id": k.Op, "attempt": k.Attempt, "status": "unknown"})
		return
	}
	ctx := r.Context()
	rec, err := e.cfg.Store.Get(ctx, k)
	if errors.Is(err, sql.ErrNoRows) {
		if what == "cancel" { // tombstone it: a later copy of the submit is then a no-op
			body := []byte{}
			rec, _, err = e.cfg.Store.Accept(ctx, Rec{Key: k, Digest: digest, NotAfter: notAfter, Body: body,
				Status: StCancelled, Created: e.now()})
			if err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
			reply(w, 200, view(rec))
			return
		}
		st := "never_accepted" // not yet: a delayed copy may still arrive
		if e.now() > notAfter {
			st = "closed"
		}
		reply(w, 200, map[string]any{"operation_id": k.Op, "attempt": k.Attempt, "status": st})
		return
	} else if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if rec.Digest != digest {
		reply(w, 409, map[string]any{"error": "conflict: the digest is not this attempt's", "status": rec.Status})
		return
	}
	switch what {
	case "":
		reply(w, 200, view(rec))
	case "result":
		if rec.Status != StDone {
			reply(w, 409, view(rec))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(rec.Outcome)
	case "cancel":
		if rec.Status == StRunning {
			e.cfg.Store.SetCancel(ctx, k)
			rec.Cancel = true
		}
		reply(w, 200, view(rec))
	case "ack":
		if rec.Status == StDone { // commit before ack is the caller's; here the record is released, and only the
			rec.Status, rec.Acked = StReleased, true // operation's own leases go with it
			if err := e.cfg.Store.Update(ctx, rec); err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
			e.cfg.Store.ReleaseHolder(ctx, "op:"+k.String())
		}
		reply(w, 200, view(rec))
	}
}

func (e *Exec) artifact(w http.ResponseWriter, r *http.Request) {
	path, a, err := e.cfg.Store.OpenArtifact(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrUnavailable) {
		reply(w, 410, map[string]any{"error": "artifact_unavailable", "tombstone": a})
		return
	}
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	f, err := os.Open(path)
	if err != nil { // the row says available but the bytes are gone: never answer empty
		reply(w, 410, map[string]any{"error": "artifact_unavailable", "tombstone": a})
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Artifact-Sha256", a.SHA256)
	io.Copy(w, f)
}

func (e *Exec) lease(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Holder string `json:"holder"`
		Until  int64  `json:"until"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); err != nil || b.Holder == "" ||
		strings.HasPrefix(b.Holder, "op:") {
		reply(w, 400, map[string]string{"error": "a holder (not op:...) and until (Yard-Time ms)"})
		return
	}
	if err := e.cfg.Store.Lease(r.Context(), r.PathValue("id"), b.Holder, b.Until); errors.Is(err, ErrUnavailable) {
		reply(w, 410, map[string]string{"error": "artifact_unavailable"})
		return
	} else if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	reply(w, 200, map[string]any{"artifact": r.PathValue("id"), "holder": b.Holder, "until": b.Until})
}

func (e *Exec) unlease(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.PathValue("holder"), "op:") {
		reply(w, 400, map[string]string{"error": "the operation's lease goes with its ack"})
		return
	}
	e.cfg.Store.Release(r.Context(), r.PathValue("id"), r.PathValue("holder"))
	reply(w, 200, map[string]string{"released": r.PathValue("holder")})
}

func (e *Exec) corrections(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	cs, err := e.cfg.Store.Corrections(r.Context(), r.Header.Get("X-Yard-Principal"), after, 500)
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if cs == nil {
		cs = []Correction{}
	}
	reply(w, 200, map[string]any{"corrections": cs})
}
