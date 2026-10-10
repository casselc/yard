package broker

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const (
	fakeAnthropicKey = "sk-ant-FAKE-test-key-0001"
	fakeOpenAIKey    = "sk-FAKE-openai-test-key-0002"
)

type fakeCloud struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []*http.Request
}

func newFakeCloud(t *testing.T) *fakeCloud {
	f := &fakeCloud{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, r.Clone(context.Background()))
		f.mu.Unlock()
		w.Header().Set("Set-Cookie", "upstream=1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_1","content":[{"type":"text","text":"ok"}]}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCloud) hostPort() string { u, _ := url.Parse(f.srv.URL); return u.Host }

func (f *fakeCloud) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.seen...)
}

func cloudEnv(t *testing.T) (*testEnv, *fakeCloud, *fakeCloud) {
	ant, oai := newFakeCloud(t), newFakeCloud(t)
	pool := x509.NewCertPool()
	pool.AddCert(ant.srv.Certificate())
	pool.AddCert(oai.srv.Certificate())
	cfg := Config{
		UpstreamAllow: []string{ant.hostPort(), oai.hostPort()},
		Providers: []Provider{
			{Name: "anthropic", Hosts: []string{"anthropic.yard"}, Upstream: ant.srv.URL, Secret: "anthropic", Inject: "x-api-key", Routes: AnthropicRoutes},
			{Name: "openai", Hosts: []string{"openai.yard"}, Upstream: oai.srv.URL, Secret: "openai", Inject: "bearer", Routes: OpenAIRoutes},
		},
		AllowPrivateUpstream: true, CloudRootCAs: pool,
	}
	e := newEnv(t, cfg, []string{"sa"}, func(c *Config, d *Deps) {
		d.Secrets = MapSource{"anthropic": fakeAnthropicKey, "openai": fakeOpenAIKey}
	})
	return e, ant, oai
}

func TestCloudKeyInjectedSandboxAuthStripped(t *testing.T) {
	e, ant, oai := cloudEnv(t)

	r := e.req("sa", "POST", "anthropic.yard", "/v1/messages", `{"model":"claude","messages":[]}`)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Anthropic-Version", "2023-06-01")
	r.Header.Set("Authorization", "Bearer sk-sandbox-placeholder")
	r.Header.Set("X-Api-Key", "sandbox-placeholder")
	r.Header.Set("X-Halo-Principal", "spoof")
	resp := e.do(r)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("anthropic status %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("upstream cookie reached the sandbox")
	}
	ar := ant.requests()
	if len(ar) != 1 {
		t.Fatalf("anthropic saw %d", len(ar))
	}
	if got := ar[0].Header.Get("X-Api-Key"); got != fakeAnthropicKey {
		t.Errorf("x-api-key %q: want the injected key", got)
	}
	if got := ar[0].Header.Values("Authorization"); len(got) != 0 {
		t.Errorf("sandbox Authorization forwarded: %v", got)
	}
	if ar[0].Header.Get("X-Halo-Principal") != "" || ar[0].Header.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("headers %v", ar[0].Header)
	}

	r = e.req("sa", "POST", "openai.yard", "/v1/responses", `{"model":"gpt"}`)
	r.Header.Set("Authorization", "Bearer sk-sandbox-placeholder")
	r.Header.Set("Openai-Organization", "org-evil")
	r.Header.Set("Idempotency-Key", "turn-9")
	resp = e.do(r)
	resp.Body.Close()
	or := oai.requests()
	if len(or) != 1 {
		t.Fatalf("openai saw %d (status %d)", len(or), resp.StatusCode)
	}
	if got := or[0].Header.Get("Authorization"); got != "Bearer "+fakeOpenAIKey {
		t.Errorf("Authorization %q: want the injected key", got)
	}
	if or[0].Header.Get("Openai-Organization") != "" {
		t.Errorf("client account header forwarded")
	}
	if k := or[0].Header.Get("Idempotency-Key"); k == "turn-9" || !strings.HasPrefix(k, "yb1-") {
		t.Errorf("Idempotency-Key %q", k)
	}
	if strings.Contains(string(body), fakeAnthropicKey) {
		t.Errorf("key in the sandbox's response")
	}
	// a provider route not on the list
	resp = e.do(e.req("sa", "POST", "anthropic.yard", "/v1/files", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 403 || len(ant.requests()) != 1 {
		t.Errorf("unlisted provider route: %d", resp.StatusCode)
	}
}

func TestCloudSecretMissingFailsClosed(t *testing.T) {
	cl := newFakeCloud(t)
	pool := x509.NewCertPool()
	pool.AddCert(cl.srv.Certificate())
	cfg := Config{UpstreamAllow: []string{cl.hostPort()}, AllowPrivateUpstream: true, CloudRootCAs: pool,
		Providers: []Provider{{Name: "openai", Hosts: []string{"openai.yard"}, Upstream: cl.srv.URL, Secret: "openai", Inject: "bearer", Routes: OpenAIRoutes}}}
	e := newEnv(t, cfg, []string{"sa"}, func(c *Config, d *Deps) { d.Secrets = MapSource{} })
	resp := e.do(e.req("sa", "POST", "openai.yard", "/v1/responses", `{}`))
	resp.Body.Close()
	if resp.StatusCode != 503 || len(cl.requests()) != 0 {
		t.Fatalf("status %d, upstream %d", resp.StatusCode, len(cl.requests()))
	}
}

func TestUpstreamAllowlist(t *testing.T) {
	_, err := New(Config{TrustDomain: "home.arpa", UpstreamAllow: []string{"api.anthropic.com:443"},
		Providers: []Provider{{Name: "x", Hosts: []string{"x.yard"}, Upstream: "https://evil.example", Secret: "x", Inject: "bearer", Routes: OpenAIRoutes}}},
		testDeps())
	if err == nil {
		t.Fatal("a provider upstream outside upstream_allow was accepted")
	}
	_, err = New(Config{TrustDomain: "home.arpa", UpstreamAllow: []string{"api.anthropic.com:443"},
		Providers: []Provider{{Name: "x", Hosts: []string{"x.yard"}, Upstream: "http://api.anthropic.com", Secret: "x", Inject: "bearer", Routes: OpenAIRoutes}}},
		testDeps())
	if err == nil {
		t.Fatal("a plain-http provider upstream was accepted")
	}
	b, err := New(Config{TrustDomain: "home.arpa", UpstreamAllow: []string{"api.anthropic.com:443", "127.0.0.1:443"}},
		testDeps())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.dialAllowed(context.Background(), "tcp", "evil.example:443"); !errors.Is(err, ErrNotAllowlisted) {
		t.Errorf("dial evil.example: %v", err)
	}
	if _, err := b.dialAllowed(context.Background(), "tcp", "api.anthropic.com:80"); !errors.Is(err, ErrNotAllowlisted) {
		t.Errorf("dial another port: %v", err)
	}
	// an allowlisted name resolving to a private address is refused
	if _, err := b.dialAllowed(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrNotAllowlisted) {
		t.Errorf("dial private: %v", err)
	}
	for _, a := range []string{"10.1.2.3", "192.168.1.72", "100.64.0.10", "169.254.169.254", "fd7a:115c:a1e0::1", "::1"} {
		if isPublic(mustAddr(a)) {
			t.Errorf("%s not private", a)
		}
	}
	if !isPublic(mustAddr("160.79.104.10")) {
		t.Errorf("public address treated as private")
	}
}
