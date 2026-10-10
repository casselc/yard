package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileSource(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, v string, mode os.FileMode) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("good", "sk-FILE-secret-value\n", 0o600)
	write("ro", "sk-FILE-readonly", 0o400)
	write("loose", "sk-FILE-loose-value", 0o644)
	write("multi", "line1\nline2\n", 0o600)
	write("empty", "\n", 0o600)
	if err := os.Symlink(filepath.Join(dir, "good"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a writer holds the FIFO open with data in it: reading it would block
	wfd, err := unix.Open(filepath.Join(dir, "fifo"), unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wfd)
	unix.Write(wfd, []byte("sk-FIFO-content"))
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	fs := FileSource{Dir: dir, stopAt: filepath.Dir(root)}
	s, err := fs.Secret(context.Background(), "good")
	if err != nil || s.value() != "sk-FILE-secret-value" {
		t.Fatalf("good: %v", err)
	}
	if _, err := fs.Secret(context.Background(), "ro"); err != nil {
		t.Fatalf("0400: %v", err)
	}
	for _, name := range []string{"loose", "multi", "empty", "link", "fifo", "sub", "../good", "Good"} {
		done := make(chan error, 1)
		go func() { _, err := fs.Secret(context.Background(), name); done <- err }()
		var err error
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: Secret blocked (a FIFO must not block the open)", name)
		}
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if !errors.Is(err, ErrSecretPolicy) {
			t.Errorf("%s: %v is not a policy error", name, err)
		}
		if strings.Contains(err.Error(), "sk-FILE") || strings.Contains(err.Error(), "line1") {
			t.Errorf("%s: error carries content: %v", name, err)
		}
	}
	if _, err := fs.Secret(context.Background(), "missing"); !errors.Is(err, ErrNoSecret) {
		t.Errorf("missing: %v", err)
	}
	// a group/world-writable directory, or ancestor, is refused
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Secret(context.Background(), "good"); err == nil {
		t.Errorf("world-writable dir accepted")
	}
	os.Chmod(dir, 0o700)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Secret(context.Background(), "good"); !errors.Is(err, ErrSecretPolicy) {
		t.Errorf("world-writable ancestor accepted: %v", err)
	}
	os.Chmod(root, 0o700)
	// the directory itself replaced by a symlink is refused (O_NOFOLLOW on the dir)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileSource{Dir: alias, stopAt: filepath.Dir(root)}).Secret(context.Background(), "good"); err == nil {
		t.Errorf("symlinked secret dir accepted")
	}
	if _, err := (FileSource{Dir: "relative"}).Secret(context.Background(), "good"); err == nil {
		t.Errorf("relative dir accepted")
	}
	// the broker logs a category, never the source's message
	if c := secretErrCategory(errors.New("sk-LEAK in a custom source's error")); c != "unavailable" {
		t.Errorf("category %q", c)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret("sk-PRINT-me-not")
	c := Credential{AccessKeyID: "AKID", SecretAccessKey: s, SessionToken: s}
	outs := []string{fmt.Sprint(s), fmt.Sprintf("%s %v %+v %#v %q %x %X %d", s, s, s, s, s, s, s, s),
		fmt.Sprintf("%v %+v %#v", c, c, &c)}
	j, _ := json.Marshal(c)
	outs = append(outs, string(j))
	for _, o := range outs {
		if strings.Contains(o, "sk-PRINT") || strings.Contains(o, "736b2d") {
			t.Errorf("secret printed: %s", o)
		}
	}
}

// Every flow that touches a secret, then a scan of everything the broker
// wrote (audit, spans, logs) for secret values and request/response bodies.
func TestNoSecretsOrBodiesInOutputs(t *testing.T) {
	e, _, _ := cloudEnv(t)
	bodyMarker := "BODY-MARKER-7f3a"
	for _, h := range []string{"anthropic.yard", "openai.yard"} {
		path := "/v1/messages"
		if h == "openai.yard" {
			path = "/v1/responses?api_key=QUERY-MARKER-91"
		}
		r := e.req("sa", "POST", h, path, `{"prompt":"`+bodyMarker+`"}`)
		r.Header.Set("Authorization", "Bearer sk-sandbox-placeholder-XYZ")
		resp := e.do(r)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	tok := e.imdsToken("sa")
	r := e.req("sa", "GET", "169.254.169.254", "/latest/meta-data/iam/security-credentials/yard-task", "")
	r.Header.Set("X-aws-ec2-metadata-token", tok)
	resp := e.do(r)
	var c map[string]string
	json.NewDecoder(resp.Body).Decode(&c)
	resp.Body.Close()
	if c["SecretAccessKey"] == "" {
		t.Fatal("no credential")
	}
	e.audit.waitFor(t, `"route":"imds credentials"`)
	e.spans.waitFor(t, `imds credentials`)
	all := e.audit.String() + e.spans.String() + e.logs.String()
	for _, s := range []string{fakeAnthropicKey, fakeOpenAIKey, c["SecretAccessKey"], c["Token"], tok,
		"sk-sandbox-placeholder-XYZ", bodyMarker, "QUERY-MARKER-91", `"text":"ok"`} {
		if strings.Contains(all, s) {
			t.Errorf("output contains %q", s)
		}
	}
	// the credential's NAME and the mint id are recorded
	if !strings.Contains(e.audit.String(), `"credential":"anthropic"`) || !strings.Contains(e.audit.String(), `"mint_id":"m-`) {
		t.Errorf("audit lacks credential name or mint id:\n%s", e.audit.String())
	}
}

func TestPeerCheck(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	// only 10.9.9.9 may use this link; the test client is 127.0.0.1
	if err := e.update(func(ls []Link) []Link {
		ls[0].Peers = []netip.Prefix{netip.MustParsePrefix("10.9.9.9/32")}
		ls[0].Incarnation = incOf("sa-0002") // a different peer set is a new allocation
		return ls
	}); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	resp, err := c.Do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("a non-peer got an answer: %d", resp.StatusCode)
	}
	if len(halo.headers()) != 0 {
		t.Fatal("halo reached from a non-peer")
	}
	e.audit.waitEvent(t, func(ev AuditEvent) bool { return ev.Kind == "conn" && ev.Reason == "peer" })
}

func TestSyncLinks(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa", "sb"})
	good := append([]Link(nil), e.reg.S.Links...)
	// a removed link is refused at once
	if err := e.update(func([]Link) []Link { return []Link{good[1]} }); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	if resp, err := c.Do(e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)); err == nil {
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("removed link served: %d", resp.StatusCode)
		}
	}
	// invalid and duplicate links are served by nobody
	dupe := good[1]
	dupe.Workload.Sandbox = "other"
	bad := good[0]
	bad.Workload.Run = "UPPER"
	err := e.update(func([]Link) []Link { return []Link{good[1], dupe, bad} })
	if err == nil {
		t.Fatal("bad links not reported")
	}
	if resp, err := c.Do(e.req("sb", "POST", "inference.yard", "/v1/responses", `{}`)); err == nil {
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("a link listed twice was served: %d", resp.StatusCode)
		}
	}
	if n := len(halo.headers()); n != 0 {
		t.Fatalf("halo reached %d times through removed or duplicate links", n)
	}
	// loopback links are refused unless the test relaxation is on
	l := good[0]
	if err := l.validate(false); err == nil {
		t.Fatal("loopback link accepted")
	}
	l.Addr = netip.MustParseAddrPort("0.0.0.0:8099")
	if err := l.validate(true); err == nil {
		t.Fatal("wildcard link accepted")
	}
	// the same principal on two links
	two := good[1]
	two.Addr = netip.MustParseAddrPort("10.77.9.1:8099")
	if err := e.update(func([]Link) []Link { return []Link{good[1], two} }); err == nil {
		t.Fatal("one principal on two links not reported")
	}
}

func TestSyncListens(t *testing.T) {
	reg := &StaticRegistry{}
	halo := newFakeHalo(t)
	cfg := haloCfg(halo)
	cfg.TrustDomain, cfg.AllowLoopback = "home.arpa", true
	var opened []netip.AddrPort
	d := testDeps()
	d.Registry = reg
	d.Listen = func(a netip.AddrPort) (net.Listener, error) {
		opened = append(opened, a)
		return net.Listen("tcp", "127.0.0.1:0") // the test cannot bind 10.77.x; the key is the link address
	}
	d.Secrets = MapSource{"halo-key": testHaloKey}
	b, err := New(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	reg.Set([]Link{{Addr: netip.MustParseAddrPort("127.0.0.2:8099"), Incarnation: incOf("sa-0001"),
		Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Workload: workload("sa"), Epoch: 1, Class: ClassOwnCode}})
	if err := b.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || opened[0].String() != "127.0.0.2:8099" {
		t.Fatalf("opened %v", opened)
	}
	reg.Set(reg.S.Links) // a heartbeat: new serial, same links
	if err := b.Sync(context.Background(), true); err != nil || len(opened) != 1 {
		t.Fatalf("second sync reopened: %v %v", opened, err)
	}
}

func TestTraceparentParse(t *testing.T) {
	good := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, ok := ParseTraceparent(good)
	if !ok || tc.Traceparent() != good {
		t.Fatalf("%v %q", ok, tc.Traceparent())
	}
	for _, bad := range []string{"", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
		"00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"} {
		if _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSpanExportShape(t *testing.T) {
	halo := newFakeHalo(t)
	e := newEnv(t, haloCfg(halo), []string{"sa"})
	r := e.req("sa", "POST", "inference.yard", "/v1/responses", `{}`)
	r.Header.Set("Traceparent", "garbage")
	resp := e.do(r)
	resp.Body.Close()
	e.spans.waitFor(t, "resourceSpans")
	line := strings.Split(strings.TrimSpace(e.spans.String()), "\n")[0]
	var v struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					TraceID, SpanID, ParentSpanID, Name string
					Attributes                          []struct {
						Key   string
						Value map[string]any
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatal(err)
	}
	sp := v.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if len(sp.TraceID) != 32 || len(sp.SpanID) != 16 || sp.ParentSpanID != "" {
		t.Fatalf("span ids %+v", sp)
	}
	attrs := map[string]any{}
	for _, a := range sp.Attributes {
		for _, x := range a.Value {
			attrs[a.Key] = x
		}
	}
	if attrs["yard.principal"] != e.principal("sa") || attrs["yard.chain.root"] != e.principal("sa") ||
		attrs["yard.capture"] != "off" || attrs["yard.observed"] != "host" || attrs["yard.run.class"] != "own-code" {
		t.Fatalf("attrs %v", attrs)
	}
	// halo got the new trace, not the garbage
	if tp := halo.headers()[0].Get("Traceparent"); !strings.Contains(tp, sp.TraceID) || !strings.Contains(tp, sp.SpanID) {
		t.Fatalf("traceparent %q vs span %s/%s", tp, sp.TraceID, sp.SpanID)
	}
}

func TestCaptureOnlyOffInB0(t *testing.T) {
	_, err := New(Config{TrustDomain: "home.arpa", Capture: "content"}, testDeps())
	if err == nil {
		t.Fatal("content capture accepted in B0")
	}
}
