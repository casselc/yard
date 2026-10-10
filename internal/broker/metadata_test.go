package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func mdEnv(t *testing.T, md MetadataConfig, sandboxes ...string) *testEnv {
	if len(sandboxes) == 0 {
		sandboxes = []string{"sa"}
	}
	return newEnv(t, Config{Metadata: md}, sandboxes)
}

func (e *testEnv) imdsToken(sbx string) string {
	e.t.Helper()
	r := e.req(sbx, "PUT", "169.254.169.254", "/latest/api/token", "")
	r.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp := e.do(r)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(b) < 32 {
		e.t.Fatalf("token: %d %q", resp.StatusCode, b)
	}
	return string(b)
}

func (e *testEnv) ecs(sbx string) (int, map[string]string) {
	e.t.Helper()
	resp := e.do(e.req(sbx, "GET", "169.254.170.2", "/creds", ""))
	defer resp.Body.Close()
	var m map[string]string
	if resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			e.t.Fatal(err)
		}
	}
	return resp.StatusCode, m
}

func TestIMDSv2Flow(t *testing.T) {
	e := mdEnv(t, MetadataConfig{}, "sa", "sb")
	// IMDSv1 (no token) is refused
	resp := e.do(e.req("sa", "GET", "169.254.169.254", "/latest/meta-data/iam/security-credentials/", ""))
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("v1: %d", resp.StatusCode)
	}
	tok := e.imdsToken("sa")
	get := func(sbx, path, token string) (int, string) {
		r := e.req(sbx, "GET", "169.254.169.254", path, "")
		if token != "" {
			r.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp := e.do(r)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if st, role := get("sa", "/latest/meta-data/iam/security-credentials/", tok); st != 200 || role != "yard-task" {
		t.Fatalf("role list: %d %q", st, role)
	}
	st, body := get("sa", "/latest/meta-data/iam/security-credentials/yard-task", tok)
	if st != 200 {
		t.Fatalf("creds: %d %s", st, body)
	}
	var c map[string]string
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatal(err)
	}
	if c["Code"] != "Success" || c["Type"] != "AWS-HMAC" || !strings.HasPrefix(c["AccessKeyId"], "ASIAFAKE") ||
		!strings.HasPrefix(c["SecretAccessKey"], "fake-secret-access-key-") || !strings.HasPrefix(c["Token"], "fake-session-token-") {
		t.Fatalf("creds %v", c)
	}
	exp, err := time.Parse(time.RFC3339, c["Expiration"])
	if err != nil || exp.After(time.Now().Add(5*time.Minute+time.Second)) {
		t.Errorf("advertised Expiration %v: want <= now+5m (real is now+15m)", c["Expiration"])
	}
	if st, _ := get("sa", "/latest/meta-data/iam/security-credentials/other-role", tok); st != 404 {
		t.Errorf("other role: %d", st)
	}
	// the token is bound to the link it was issued on
	if st, body := get("sb", "/latest/meta-data/iam/security-credentials/yard-task", tok); st != 401 {
		t.Errorf("sa's token on sb's link: %d %s", st, body)
	}
	if st, _ := get("sa", "/latest/meta-data/iam/security-credentials/yard-task", "not-a-token"); st != 401 {
		t.Errorf("bad token: %d", st)
	}
	// a proxied token PUT, and bad TTLs
	for _, h := range []map[string]string{
		{"X-aws-ec2-metadata-token-ttl-seconds": "60", "X-Forwarded-For": "1.2.3.4"},
		{"X-aws-ec2-metadata-token-ttl-seconds": "0"},
		{"X-aws-ec2-metadata-token-ttl-seconds": "21601"},
		{},
	} {
		r := e.req("sa", "PUT", "169.254.169.254", "/latest/api/token", "")
		for k, v := range h {
			r.Header.Set(k, v)
		}
		resp := e.do(r)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("token PUT %v accepted", h)
		}
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Errorf("%d mints", n)
	}
	e.minter.mu.Lock()
	req := e.minter.calls[0]
	e.minter.mu.Unlock()
	if req.Principal != e.principal("sa") || req.Epoch != 1 || !strings.HasPrefix(req.MintID, "m-") {
		t.Errorf("mint request %+v", req)
	}
}

func TestECSFlowAndSingleFlight(t *testing.T) {
	e := newEnv(t, Config{Limits: Limits{PerLinkMetadata: 32}}, []string{"sa"})
	release := make(chan struct{})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		<-release
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		return validCred(req), nil
	})
	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _ := e.ecs("sa")
			codes <- st
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Errorf("concurrent fetch: %d", c)
		}
	}
	st, m := e.ecs("sa")
	if st != 200 || m["RoleArn"] == "" || m["Token"] == "" {
		t.Fatalf("ecs: %d %v", st, m)
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("%d mints for 21 fetches: want one in flight, then the cache", n)
	}
}

func TestMintTagMustMatch(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.MintID = "m-someone-else"
		return c, nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("a credential without our yard-mint tag was served: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "mint" && ev.Reason == "mint_tag" })
}

// A mint whose answer is lost (an error after it may have applied) is not
// re-sent before the settle bound (spec/warden blindRetry).
func TestMintUnknownIsNotRetriedBeforeSettle(t *testing.T) {
	e := mdEnv(t, MetadataConfig{Skew: 100 * time.Millisecond, MintWait: 100 * time.Millisecond})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if !req.Begin(time.Now().Add(300 * time.Millisecond)) { // a JWT expiring in 300 ms: fence at +400 ms
			return Credential{}, ErrNotSent
		}
		return Credential{}, errors.New("connection reset after the request was written")
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("status %d", st)
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if st, _ := e.ecs("sa"); st != 503 {
			t.Fatalf("status %d", st)
		}
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("%d mints before the settle bound: an unknown mint was re-sent", n)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "mint" && ev.Outcome == "unknown" && ev.Detail == "error" })
	time.Sleep(450 * time.Millisecond)
	e.minter.set(nil)
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatalf("after the settle bound: %d", st)
	}
	if n := e.minter.n.Load(); n != 2 {
		t.Fatalf("%d mints", n)
	}
}

// A late answer (after the waiting request gave up) is adopted, not minted again.
func TestLateMintAnswerAdopted(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: 30 * time.Millisecond})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		time.Sleep(150 * time.Millisecond)
		return validCred(req), nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("first: %d", st)
	}
	time.Sleep(250 * time.Millisecond)
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatalf("after the late answer: %d", st)
	}
	if n := e.minter.n.Load(); n != 1 {
		t.Fatalf("%d mints", n)
	}
}

func TestStaleEpochRefused(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.Epoch = req.Epoch - 1 // minted under the pre-suspend epoch
		return c, nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("stale-epoch credential served: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "mint" && ev.Reason == "stale_epoch" })

	// the epoch moves (suspend/resume) while a mint is in flight: the answer is fenced
	release := make(chan struct{})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		<-release
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		return validCred(req), nil
	})
	done := make(chan int)
	go func() { st, _ := e.ecs("sa"); done <- st }()
	time.Sleep(50 * time.Millisecond)
	if err := e.update(func(ls []Link) []Link { ls[0].Epoch = 2; return ls }); err != nil {
		t.Fatal(err)
	}
	close(release)
	if st := <-done; st == 200 {
		t.Fatalf("a credential minted under epoch 1 was served after the move to 2: %d", st)
	}
	e.minter.set(nil)
	st, _ := e.ecs("sa")
	if st != 200 {
		t.Fatalf("epoch 2 mint: %d", st)
	}
	e.minter.mu.Lock()
	last := e.minter.calls[len(e.minter.calls)-1]
	e.minter.mu.Unlock()
	if last.Epoch != 2 {
		t.Fatalf("mint asked for epoch %d", last.Epoch)
	}
}

func TestEpochChangeDropsHeldCredential(t *testing.T) {
	e := mdEnv(t, MetadataConfig{})
	_, m1 := e.ecs("sa")
	if err := e.update(func(ls []Link) []Link { ls[0].Epoch = 2; return ls }); err != nil {
		t.Fatal(err)
	}
	_, m2 := e.ecs("sa")
	if m1["AccessKeyId"] == m2["AccessKeyId"] || e.minter.n.Load() != 2 {
		t.Fatalf("the pre-suspend credential survived the epoch change")
	}
}

func TestCredentialTTLBound(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.Expiration = time.Now().Add(2 * time.Hour)
		return c, nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("a 2-hour credential was served: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "mint" && ev.Reason == "ttl_bound" })
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.Expiration = time.Now().Add(30 * time.Second) // below the serve margin
		return c, nil
	})
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("a credential about to expire was served: %d", st)
	}
}

func TestRevokeDropsCredential(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	if st, _ := e.ecs("sa"); st != 200 {
		t.Fatal(st)
	}
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) { return Credential{}, ErrNoGrant })
	e.b.Revoke(e.principal("sa"))
	if st, _ := e.ecs("sa"); st != 503 {
		t.Fatalf("revoked credential still served: %d", st)
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool {
		return ev.Kind == "mint" && ev.Outcome == "not_done" && ev.Reason == "no_grant"
	})
}

func TestRefreshBeforeExpiry(t *testing.T) {
	e := mdEnv(t, MetadataConfig{MintWait: time.Second})
	e.minter.set(func(ctx context.Context, req MintRequest) (Credential, error) {
		if err := begin(req); err != nil {
			return Credential{}, err
		}
		c := validCred(req)
		c.Expiration = time.Now().Add(4 * time.Minute) // inside RefreshBefore (5m)
		return c, nil
	})
	_, m1 := e.ecs("sa")
	e.minter.set(nil)
	_, m2 := e.ecs("sa") // still served (above the serve margin) while a refresh starts
	if m2["AccessKeyId"] != m1["AccessKeyId"] {
		t.Fatalf("held credential not served during refresh")
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.minter.n.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	_, m3 := e.ecs("sa")
	if m3["AccessKeyId"] == m1["AccessKeyId"] {
		t.Fatalf("refreshed credential not adopted")
	}
}

func TestNoMinterFailsClosed(t *testing.T) {
	e := newEnv(t, Config{}, []string{"sa"}, func(c *Config, d *Deps) { d.Minter = nil })
	if st, _ := e.ecs("sa"); st != http.StatusServiceUnavailable {
		t.Fatalf("%d", st)
	}
}
