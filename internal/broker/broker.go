// Package broker is yard-broker B0: the per-node egress and credential
// broker, the sandbox's only route out (REPORT.md 5.4, CONTROL-PLANE.md,
// IDENTITY.md, WARDEN.md, A2A-MCP.md, halo-flash docs/SCHEDULER.md).
//
// One listener per sandbox link (the host side of its epair or tap; pf
// rdr's 169.254.169.254 and 169.254.170.2 port 80 to it). The caller is the
// sandbox allocation (incarnation) that held the link when the connection
// was accepted, from one of the link's peer addresses, mapped to its SPIFFE
// id by yard-ctl's state (Registry); never anything the request says.
// Control state is versioned and leased: an older or stale snapshot
// authorizes nothing.
//
// Routes, by Host and then method + path:
//   - halo hosts (inference.yard): halo_serve, with X-Halo-Principal,
//     X-Halo-Chain-Id and a principal-namespaced Idempotency-Key set by the
//     broker and every client X-Halo-*/Idempotency-Key/credential header gone;
//   - provider hosts (anthropic.yard, openai.yard): the cloud API with the
//     key injected from a SecretSource; allowlisted public upstreams only;
//     quotas per principal and per day;
//   - 169.254.169.254 (IMDSv2) and 169.254.170.2 (ECS): short-lived cloud
//     credentials from a Minter;
//   - everything else: 403 and an audit event.
package broker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Route is one allowed method + path. A "*" path segment matches one
// segment of [A-Za-z0-9_.-]. MaxBody bounds the request body (0: the
// broker's default).
type Route struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	MaxBody int64  `json:"max_body,omitempty"`
}

// Provider is a brokered cloud LLM API.
type Provider struct {
	Name     string   `json:"name"`     // "anthropic", "openai"
	Hosts    []string `json:"hosts"`    // sandbox-facing names, e.g. "anthropic.yard"
	Upstream string   `json:"upstream"` // https://api.anthropic.com
	Secret   string   `json:"secret"`   // SecretSource name
	Inject   string   `json:"inject"`   // "x-api-key" (Anthropic) | "bearer" (OpenAI)
	Routes   []Route  `json:"routes"`
}

// Limits bound what one sandbox can take from the shared broker.
type Limits struct {
	MaxBody         int64         `json:"max_body"`          // default request body cap (64 MiB)
	UploadIdle      time.Duration `json:"-"`                 // a body making no progress this long is aborted (30s)
	WriteIdle       time.Duration `json:"-"`                 // a downstream write blocked this long aborts the response (60s)
	PerLinkProxy    int           `json:"per_link_proxy"`    // concurrent halo/cloud requests per link (4)
	PerLinkMetadata int           `json:"per_link_metadata"` // concurrent metadata requests per link (8), a separate pool
	GlobalProxy     int           `json:"global_proxy"`      // concurrent halo/cloud requests on the node (64); metadata not counted
	MaxConnsPerLink int           `json:"max_conns_per_link"`
	// Per principal, all proxied traffic: token buckets refilled per minute.
	RequestsPerMin int   `json:"requests_per_min"` // 60
	BytesPerMin    int64 `json:"bytes_per_min"`    // 256 MiB (request + response bytes)
	// Key-injected cloud egress per UTC day: per principal and node-wide.
	CloudDailyRequests       int64 `json:"cloud_daily_requests"`        // 2000
	CloudDailyBytes          int64 `json:"cloud_daily_bytes"`           // 1 GiB
	CloudDailyRequestsGlobal int64 `json:"cloud_daily_requests_global"` // 10000
	CloudDailyBytesGlobal    int64 `json:"cloud_daily_bytes_global"`    // 4 GiB
	// Per link, every request (denied ones included), before routing.
	LinkRequestsPerSec float64 `json:"link_requests_per_sec"` // 20
	LinkRequestBurst   int     `json:"link_request_burst"`    // 40
}

func (l *Limits) defaults() {
	if l.MaxBody <= 0 {
		l.MaxBody = 64 << 20
	}
	if l.UploadIdle <= 0 {
		l.UploadIdle = 30 * time.Second
	}
	if l.WriteIdle <= 0 {
		l.WriteIdle = 60 * time.Second
	}
	setInt := func(p *int, v int) {
		if *p <= 0 {
			*p = v
		}
	}
	set64 := func(p *int64, v int64) {
		if *p <= 0 {
			*p = v
		}
	}
	setInt(&l.PerLinkProxy, 4)
	setInt(&l.PerLinkMetadata, 8)
	setInt(&l.GlobalProxy, 64)
	setInt(&l.MaxConnsPerLink, 32)
	setInt(&l.RequestsPerMin, 60)
	set64(&l.BytesPerMin, 256<<20)
	set64(&l.CloudDailyRequests, 2000)
	set64(&l.CloudDailyBytes, 1<<30)
	set64(&l.CloudDailyRequestsGlobal, 10000)
	set64(&l.CloudDailyBytesGlobal, 4<<30)
	if l.LinkRequestsPerSec <= 0 {
		l.LinkRequestsPerSec = 20
	}
	setInt(&l.LinkRequestBurst, 40)
}

// Config configures a Broker.
type Config struct {
	TrustDomain string `json:"trust_domain"` // e.g. home.arpa

	// halo_serve. B0 requires a halo key and either https or a loopback
	// http address; mTLS between nodes is B1.
	HaloURL    string   `json:"halo_url"`    // http://127.0.0.1:8080
	HaloHosts  []string `json:"halo_hosts"`  // inference.yard
	HaloSecret string   `json:"halo_secret"` // SecretSource name of halo's API key (required with halo_url)
	HaloRoutes []Route  `json:"halo_routes"` // default: DefaultHaloRoutes

	Providers []Provider `json:"providers"`
	// UpstreamAllow lists every host:port the broker may dial for providers.
	UpstreamAllow []string `json:"upstream_allow"`

	Limits Limits `json:"limits"`

	// HaloHeaderTimeout / CloudHeaderTimeout bound the wait for response
	// headers (streams send headers at once; default 5m each).
	HaloHeaderTimeout  time.Duration `json:"-"`
	CloudHeaderTimeout time.Duration `json:"-"`

	// RegistryLease: a snapshot authorizes nothing after Issued + lease
	// (default 30s); RegistrySkew: how far Issued may be ahead of our clock.
	RegistryLease time.Duration `json:"-"`
	RegistrySkew  time.Duration `json:"-"`

	Metadata MetadataConfig `json:"-"`

	// Capture is the content-capture mode. B0 supports only "off".
	Capture string `json:"capture"`

	// Test-only relaxations.
	AllowLoopback        bool `json:"-"` // loopback link addresses
	AllowPrivateUpstream bool `json:"-"` // provider upstreams resolving to non-public addresses
	// CloudRootCAs replaces the system roots for provider TLS (tests).
	CloudRootCAs *x509.CertPool `json:"-"`
	Resolver     Resolver       `json:"-"`

	Now func() time.Time `json:"-"`
}

// DefaultHaloRoutes: the Responses, Chat Completions and Messages surfaces.
var DefaultHaloRoutes = []Route{
	{Method: "POST", Path: "/v1/responses"}, {Method: "GET", Path: "/v1/responses/*"},
	{Method: "POST", Path: "/v1/responses/*/cancel"}, {Method: "POST", Path: "/v1/chat/completions"},
	{Method: "POST", Path: "/v1/messages"}, {Method: "POST", Path: "/v1/messages/count_tokens"},
	{Method: "GET", Path: "/v1/models"},
}

// AnthropicRoutes and OpenAIRoutes are the default provider surfaces.
var (
	AnthropicRoutes = []Route{{Method: "POST", Path: "/v1/messages"}, {Method: "POST", Path: "/v1/messages/count_tokens"},
		{Method: "GET", Path: "/v1/models"}}
	OpenAIRoutes = []Route{{Method: "POST", Path: "/v1/responses"}, {Method: "POST", Path: "/v1/chat/completions"},
		{Method: "GET", Path: "/v1/models"}, {Method: "POST", Path: "/v1/embeddings"}}
)

// Metadata IPs (pfanchor.Metadata).
const (
	imdsHost = "169.254.169.254"
	ecsHost  = "169.254.170.2"
)

// Deps are the broker's pluggable parts.
type Deps struct {
	Registry Registry
	Floors   FloorStore // required: serial/epoch/incarnation high-water marks across restarts
	// FirstBoot allows starting with no persisted floors (yard-broker
	// -init-floors). Without it a missing floors file is recovery-required.
	FirstBoot bool
	Chains    ChainSource  // nil: NoChains
	Secrets   SecretSource // nil: none (provider and halo routes fail closed)
	Minter    Minter       // nil: the metadata endpoints answer 503
	Spans     Exporter     // nil: none
	Audit     AuditSink    // required
	Logf      func(format string, a ...any)
	// Listen opens a link listener (default net.Listen "tcp").
	Listen func(addr netip.AddrPort) (net.Listener, error)
}

// Broker is one node's broker.
type Broker struct {
	cfg     Config
	deps    Deps
	halo    *url.URL
	hosts   map[string]*service
	allow   allowlist
	creds   *credStore
	toks    *imdsTokens
	Count   Counters
	denyLim denyLimiter
	quota   *quotas
	gsem    chan struct{} // global proxy slots

	syncMu          sync.Mutex // serializes Sync: read, check, persist, apply
	floors          Floors     // guarded by syncMu
	lastSn          *Snapshot  // the snapshot applied last in this process (syncMu)
	floorsUncertain bool       // a save's durability is unknown: no authorization change until re-established (syncMu)

	authMu sync.Mutex // guards auth only; never held while taking another lock
	auth   authState

	mu      sync.Mutex // guards links, servers, closed, linkServer.conns/dead
	links   map[netip.AddrPort]Link
	servers map[netip.AddrPort]*linkServer
	closed  bool
}

// authState is the published authorization generation. Its deadline is on
// the monotonic clock, derived at validation from the snapshot's remaining
// lease; once expired, a generation never becomes valid again.
type authState struct {
	gen      uint64
	deadline time.Time // monotonic (time.Now)
	expired  bool
}

// linkServer is one allocation generation's listener and server: it
// serves exactly one incarnation, tags every connection it accepts with it,
// and is closed (listener, backlog and connections) when that allocation
// changes. A replacement allocation gets a new listener.
type linkServer struct {
	key   netip.AddrPort
	inc   string
	srv   *http.Server
	conns map[*trackedConn]struct{} // guarded by Broker.mu
	dead  bool                      // detached; accepts nothing more (Broker.mu)
	psem  chan struct{}             // proxy slots
	msem  chan struct{}             // metadata slots
	rate  *rateBucket               // per-link request admission
}

// New validates the configuration and builds a broker. It serves nothing
// until a Sync has applied a fresh snapshot.
func New(cfg Config, d Deps) (*Broker, error) {
	if d.Registry == nil || d.Audit == nil || d.Floors == nil {
		return nil, errors.New("broker: registry, floor store and audit sink are required")
	}
	if cfg.TrustDomain == "" {
		return nil, errors.New("broker: trust domain required")
	}
	if cfg.Capture == "" {
		cfg.Capture = "off"
	}
	if cfg.Capture != "off" {
		return nil, fmt.Errorf("broker: capture %q: B0 supports only \"off\"", cfg.Capture)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RegistryLease <= 0 {
		cfg.RegistryLease = 30 * time.Second
	}
	if cfg.RegistrySkew <= 0 {
		cfg.RegistrySkew = 5 * time.Second
	}
	if cfg.HaloHeaderTimeout <= 0 {
		cfg.HaloHeaderTimeout = 5 * time.Minute
	}
	if cfg.CloudHeaderTimeout <= 0 {
		cfg.CloudHeaderTimeout = 5 * time.Minute
	}
	cfg.Limits.defaults()
	if d.Chains == nil {
		d.Chains = NoChains{}
	}
	if d.Logf == nil {
		d.Logf = func(string, ...any) {}
	}
	if d.Listen == nil {
		d.Listen = func(a netip.AddrPort) (net.Listener, error) { return net.Listen("tcp", a.String()) }
	}
	fl, err := d.Floors.Load()
	switch {
	case errors.Is(err, ErrNoFloors) && d.FirstBoot: // MUTANT:missingFloorsIsFirstBoot
		fl = NewFloors()
		if err := d.Floors.Save(fl); err != nil {
			return nil, fmt.Errorf("broker: first boot: saving floors: %w", err)
		}
		d.Logf("first boot: floors initialised at zero")
	case errors.Is(err, ErrNoFloors):
		return nil, errors.New("broker: no floors on an established install: recovery required (restore the floors file, or -init-floors only for a new install)")
	case err != nil:
		return nil, fmt.Errorf("broker: floors: %w", err)
	}
	fl = cloneFloors(fl)
	cfg.Metadata.defaults()
	b := &Broker{cfg: cfg, deps: d, hosts: map[string]*service{}, allow: allowlist{}, floors: fl,
		links: map[netip.AddrPort]Link{}, servers: map[netip.AddrPort]*linkServer{},
		gsem: make(chan struct{}, cfg.Limits.GlobalProxy)}
	b.quota = newQuotas(cfg.Limits, cfg.Now)
	b.toks = &imdsTokens{m: map[string]imdsToken{}, now: cfg.Now}
	b.creds = newCredStore(cfg.Metadata, d.Minter, cfg.Now, d.Audit.Audit, &b.Count)
	b.creds.authOK = b.authOK
	for _, a := range cfg.UpstreamAllow {
		h, p, err := net.SplitHostPort(a)
		if err != nil || h == "" || p == "" {
			return nil, fmt.Errorf("broker: upstream_allow %q: want host:port", a)
		}
		b.allow[strings.ToLower(a)] = true
	}
	if cfg.HaloURL != "" {
		u, err := checkHaloURL(cfg.HaloURL)
		if err != nil {
			return nil, err
		}
		if cfg.HaloSecret == "" { // MUTANT:haloKeyOptional
			return nil, errors.New("broker: halo_secret is required with halo_url (halo trusts the X-Halo-* headers only from a keyed caller)")
		}
		b.halo = u
		routes := cfg.HaloRoutes
		if routes == nil {
			routes = DefaultHaloRoutes
		}
		svc := &service{kind: "halo", name: "halo", routes: routes, upstream: u, secret: cfg.HaloSecret}
		svc.proxy = b.newProxy(svc, b.haloTransport(u))
		for _, h := range cfg.HaloHosts {
			if err := b.addHost(h, svc); err != nil {
				return nil, err
			}
		}
	}
	for i := range cfg.Providers {
		p := cfg.Providers[i]
		u, err := url.Parse(p.Upstream)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.User != nil {
			return nil, fmt.Errorf("broker: provider %s upstream %q: want https://host[:port]", p.Name, p.Upstream)
		}
		if !b.allow.allows(hostPort(u)) {
			return nil, fmt.Errorf("broker: provider %s upstream %s is not in upstream_allow", p.Name, hostPort(u))
		}
		if p.Inject != "x-api-key" && p.Inject != "bearer" {
			return nil, fmt.Errorf("broker: provider %s inject %q", p.Name, p.Inject)
		}
		if p.Secret == "" || len(p.Routes) == 0 {
			return nil, fmt.Errorf("broker: provider %s needs a secret name and routes", p.Name)
		}
		svc := &service{kind: "cloud", name: p.Name, routes: p.Routes, upstream: u, secret: p.Secret, inject: p.Inject}
		svc.proxy = b.newProxy(svc, b.cloudTransport())
		for _, h := range p.Hosts {
			if err := b.addHost(h, svc); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// checkHaloURL: https anywhere, or http to a loopback IP literal; no
// userinfo, path or query.
func checkHaloURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		return nil, fmt.Errorf("broker: halo_url %q: want scheme://host:port", s)
	}
	switch u.Scheme {
	case "https":
	case "http":
		a, err := netip.ParseAddr(u.Hostname())
		if err != nil || !a.IsLoopback() { // MUTANT:haloPlainRemote
			return nil, fmt.Errorf("broker: halo_url %q: plain http only to a loopback address (mTLS is B1)", s)
		}
	default:
		return nil, fmt.Errorf("broker: halo_url %q: scheme", s)
	}
	return u, nil
}

func (b *Broker) addHost(h string, s *service) error {
	h = strings.ToLower(h)
	if h == "" || h == imdsHost || h == ecsHost || strings.ContainsAny(h, ":/") {
		return fmt.Errorf("broker: host name %q", h)
	}
	if _, dup := b.hosts[h]; dup {
		return fmt.Errorf("broker: host %q configured twice", h)
	}
	b.hosts[h] = s
	return nil
}

func hostPort(u *url.URL) string {
	h, p := u.Hostname(), u.Port()
	if p == "" {
		p = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return strings.ToLower(net.JoinHostPort(h, p))
}

// Principal is the SPIFFE id of the link's workload.
func (b *Broker) Principal(l Link) string { return l.Workload.SPIFFE(b.cfg.TrustDomain) }

// ErrClosed: the broker was closed.
var ErrClosed = errors.New("broker closed")

// maxRetired bounds the retired-incarnation memory (oldest evicted).
const maxRetired = 65536

// syncReject records a refused snapshot, loudly.
func (b *Broker) syncReject(reason string, err error) error {
	b.Count.Add("registry_rejected_" + reason)
	b.deps.Audit.Audit(AuditEvent{Time: b.cfg.Now(), Kind: "registry", Decision: "deny", Reason: reason, Outcome: "not_done"})
	b.deps.Logf("registry snapshot refused (%s): %v", reason, err)
	return fmt.Errorf("registry %s: %w", reason, err)
}

// testHookBeforePublish runs inside Sync after persistence and the
// credential fence, before the freshness recheck and publication (tests).
var testHookBeforePublish atomic.Pointer[func()]

// fresh reports whether a snapshot's lease still has time at now.
func (b *Broker) fresh(sn Snapshot, now time.Time) bool {
	return now.Before(sn.Issued.Add(b.cfg.RegistryLease)) // MUTANT:leaseIgnored
}

// recoverFloors re-establishes durable floors after an uncertain save:
// the conservative union of what is in memory and what is on disk, saved
// again. Until it succeeds no snapshot is applied.
func (b *Broker) recoverFloors() error {
	disk, err := b.deps.Floors.Load()
	if err != nil && !errors.Is(err, ErrNoFloors) {
		return err
	}
	m := b.floors
	if err == nil {
		m = mergeFloors(b.floors, disk)
	}
	if err := b.deps.Floors.Save(m); err != nil {
		return err
	}
	b.floors = m
	b.floorsUncertain = false
	b.Count.Add("floors_recovered")
	return nil
}

// Sync pulls a snapshot and applies it if it is fresh, newer than every
// snapshot applied before (persisted floors; the same serial only with the
// same content digest), does not lower any principal's epoch, does not move
// or bring back an incarnation. Conflicting entries (an address, a
// principal or an incarnation listed twice) are all invalid. The floors are
// made durable first; a replaced allocation's listener, backlog and
// connections are closed and its credential fenced before the replacement
// is published under a new authorization generation, whose freshness is
// rechecked immediately before publication. Sync calls are serialized;
// after Close, Sync does nothing.
func (b *Broker) Sync(ctx context.Context, listen bool) error {
	unlock := b.lockSync() // MUTANT:syncUnserialized
	defer unlock()
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed { // MUTANT:syncAfterClose
		return ErrClosed
	}
	if b.floorsUncertain { // MUTANT:uncertainIgnored
		if err := b.recoverFloors(); err != nil {
			return b.syncReject("floors_uncertain", err)
		}
	}
	sn, err := b.deps.Registry.Snapshot(ctx)
	now := b.cfg.Now()
	if err != nil {
		return b.syncReject("unreadable", err)
	}
	digest := snapshotDigest(sn)
	restart := false
	switch {
	case sn.Serial == 0:
		return b.syncReject("no_serial", errors.New("serial must be >= 1"))
	case sn.Issued.After(now.Add(b.cfg.RegistrySkew)):
		return b.syncReject("future", fmt.Errorf("issued %v is ahead of our clock", sn.Issued))
	case !b.fresh(sn, now):
		return b.syncReject("stale", fmt.Errorf("issued %v, lease %v", sn.Issued, b.cfg.RegistryLease))
	case sn.Serial < b.floors.Serial: // MUTANT:serialRegression
		return b.syncReject("regression", fmt.Errorf("serial %d below the applied %d", sn.Serial, b.floors.Serial))
	case sn.Serial == b.floors.Serial:
		if digest != b.floors.Digest { // MUTANT:replayUnverified
			return b.syncReject("unverified_replay", fmt.Errorf("serial %d reused with other content", sn.Serial))
		}
		if b.lastSn != nil {
			return nil // the same snapshot again, already applied
		}
		restart = true // the snapshot applied before a restart: apply it again
	}

	// validate every entry, then drop ALL entries in any conflict
	var bad []error
	type cand struct {
		l Link
		p string
	}
	var cs []cand
	byAddr, byP, byInc := map[netip.AddrPort]int{}, map[string]int{}, map[string]int{}
	for _, l := range sn.Links {
		l.Peers = append([]netip.Prefix(nil), l.Peers...)
		if err := l.validate(b.cfg.AllowLoopback); err != nil {
			bad = append(bad, err)
			continue
		}
		p := b.Principal(l)
		cs = append(cs, cand{l, p})
		byAddr[l.Addr]++
		byP[p]++
		byInc[l.Incarnation]++
	}
	next := map[netip.AddrPort]Link{}
	for _, c := range cs {
		if byAddr[c.l.Addr] > 1 || byP[c.p] > 1 || byInc[c.l.Incarnation] > 1 { // MUTANT:conflictKeepsFirst
			bad = append(bad, fmt.Errorf("link %v (%s): address, principal or incarnation listed more than once: none served", c.l.Addr, c.p))
			b.Count.Add("registry_conflicting_link")
			continue
		}
		next[c.l.Addr] = c.l
	}
	// floors: epochs never go down, retired incarnations never come back,
	// an active incarnation (persisted, so this survives restarts) never
	// changes its address or principal
	for _, l := range next {
		p := b.Principal(l)
		if l.Epoch < b.floors.Epochs[p] { // MUTANT:epochRegression
			return b.syncReject("epoch_regression", fmt.Errorf("%s epoch %d below %d", p, l.Epoch, b.floors.Epochs[p]))
		}
		if _, gone := b.floors.Retired[l.Incarnation]; gone { // MUTANT:resurrect
			return b.syncReject("resurrected", fmt.Errorf("incarnation %s was retired", l.Incarnation))
		}
		if o, ok := b.floors.Active[l.Incarnation]; ok && (o.Addr != l.Addr.String() || o.Principal != p) { // MUTANT:activeUnpersisted
			return b.syncReject("incarnation_reused", fmt.Errorf("incarnation %s changed address or principal", l.Incarnation))
		}
	}
	nf := cloneFloors(b.floors)
	nf.Serial, nf.Digest = sn.Serial, digest
	nf.Active = map[string]AllocRecord{}
	for _, l := range next {
		p := b.Principal(l)
		if l.Epoch > nf.Epochs[p] {
			nf.Epochs[p] = l.Epoch
		}
		nf.Active[l.Incarnation] = AllocRecord{Addr: l.Addr.String(), Principal: p}
	}
	for inc := range b.floors.Active {
		if _, still := nf.Active[inc]; !still {
			nf.Retired[inc] = sn.Serial
		}
	}
	if len(nf.Retired) > maxRetired {
		// safe only because incarnations are 128 random bits (validate):
		// eviction bounds memory, uniqueness prevents reuse
		type kv struct {
			k string
			v uint64
		}
		var all []kv
		for k, v := range nf.Retired {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })
		for _, x := range all[:len(all)-maxRetired] {
			delete(nf.Retired, x.k)
		}
	}
	// persist before applying; an uncertain save stops authorization changes
	if !restart {
		if err := b.deps.Floors.Save(nf); err != nil {
			if errors.Is(err, ErrFloorsUncertain) {
				b.floorsUncertain = true
				b.Count.Add("floors_uncertain")
			}
			return b.syncReject("floors_unsaved", err)
		}
	}
	b.floors = nf
	snCopy := sn
	b.lastSn = &snCopy

	// 1. unpublish replaced and removed allocations; detach their servers
	b.mu.Lock()
	old := make(map[netip.AddrPort]Link, len(b.links))
	for a, l := range b.links {
		old[a] = l
	}
	var dead []*linkServer
	var retired []Link
	for a, o := range old {
		if n, ok := next[a]; ok && n.sameAllocation(o) {
			continue
		}
		delete(b.links, a)
		retired = append(retired, o)
	}
	for a, ls := range b.servers {
		n, ok := next[a]
		o, had := old[a]
		if ok && n.Incarnation == ls.inc && (!had || n.sameAllocation(o)) {
			continue // the same allocation keeps its listener
		}
		ls.dead = true // MUTANT:keepOldListener
		delete(b.servers, a)
		dead = append(dead, ls)
	}
	b.mu.Unlock()
	for _, ls := range dead {
		_ = ls.srv.Close() // listener (and its backlog) and every connection
		b.Count.Add("listener_closed")
	}
	for _, o := range retired {
		b.toks.retire(o.Incarnation)
		b.Count.Add("link_retired")
	}
	// 2. fence credentials under the next generation (not valid until published)
	b.authMu.Lock()
	gen := b.auth.gen + 1
	b.authMu.Unlock()
	nextP := map[string]bool{}
	for _, l := range next {
		p := b.Principal(l)
		nextP[p] = true
		b.creds.bind(p, l.Incarnation, l.Epoch, gen)
	}
	for _, o := range old {
		if p := b.Principal(o); !nextP[p] {
			b.creds.unbind(p, "link_gone")
		}
	}
	if h := testHookBeforePublish.Load(); h != nil {
		(*h)()
	}
	// 3. recheck freshness immediately before publication, then publish
	pubNow := b.cfg.Now()
	if !b.fresh(sn, pubNow) { // MUTANT:noRecheckBeforePublish
		return b.syncReject("stale_at_publish", fmt.Errorf("lease ran out while applying (issued %v)", sn.Issued))
	}
	remaining := sn.Issued.Add(b.cfg.RegistryLease).Sub(pubNow)
	if remaining > b.cfg.RegistryLease {
		remaining = b.cfg.RegistryLease
	}
	var start []netip.AddrPort
	b.mu.Lock()
	b.links = next
	b.authMu.Lock()
	b.auth = authState{gen: gen, deadline: time.Now().Add(remaining)} // monotonic
	b.authMu.Unlock()
	if listen && !b.closed {
		for a := range next {
			if _, ok := b.servers[a]; !ok {
				start = append(start, a)
			}
		}
	}
	b.mu.Unlock()
	for _, a := range start {
		ln, err := b.deps.Listen(a)
		if err != nil {
			bad = append(bad, fmt.Errorf("listen %v: %w", a, err))
			continue
		}
		ls, err := b.attach(ln, a, next[a].Incarnation)
		if err != nil {
			continue
		}
		go func() { _ = ls.srv.Serve(&peerListener{Listener: ln, b: b, ls: ls}) }()
	}
	b.Count.Add("registry_applied")
	return errors.Join(bad...)
}

func (b *Broker) lockSync() func() {
	b.syncMu.Lock()
	return b.syncMu.Unlock
}

// authOK reports whether authorization generation gen is the published one
// and inside its monotonic deadline. The first caller that sees it past the
// deadline marks it expired (irreversibly) and fences, asynchronously,
// exactly the credential slots bound under it. Safe to call under
// credStore.mu (it takes only authMu).
func (b *Broker) authOK(gen uint64) bool {
	b.authMu.Lock()
	a := b.auth
	if gen != a.gen || a.expired || gen == 0 {
		b.authMu.Unlock()
		return false
	}
	if time.Now().Before(a.deadline) { // MUTANT:leaseNotEnforced
		b.authMu.Unlock()
		return true
	}
	b.auth.expired = true
	b.authMu.Unlock()
	b.Count.Add("registry_lease_expired")
	go b.onExpired(gen)
	return false
}

func (b *Broker) onExpired(gen uint64) {
	b.creds.expireGen(gen)
	b.deps.Audit.Audit(AuditEvent{Time: b.cfg.Now(), Kind: "registry", Decision: "deny", Reason: "lease_expired", Outcome: "not_done"})
	b.deps.Logf("registry lease expired (generation %d): refusing every link until a fresh snapshot", gen)
}

// currentGen is the published generation.
func (b *Broker) currentGen() uint64 {
	b.authMu.Lock()
	defer b.authMu.Unlock()
	return b.auth.gen
}

// Revoke fences a sandbox's credential slot (warden revoke, abort,
// withdraw, supersede). Once it returns no credential response of an older
// generation is committed; a response committed before it may still be
// written to the sandbox, and a credential already delivered stays valid at
// AWS until its real expiry: real revocation is the warden's
// aws:TokenIssueTime / yard-mint deny (spec/broker B7).
func (b *Broker) Revoke(principal string) { b.creds.revoke(principal) }

type ctxKey int

const (
	keyListener ctxKey = iota
	keyState
	keyConn
)

// Serve serves a listener for the allocation currently published at its
// address (tests and tools; Sync opens its own listeners).
func (b *Broker) Serve(ln net.Listener) error {
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return err
	}
	key := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	b.mu.Lock()
	l, ok := b.links[key]
	b.mu.Unlock()
	if !ok {
		ln.Close()
		return errUnknownLink
	}
	ls, err := b.attach(ln, key, l.Incarnation)
	if err != nil {
		return err
	}
	return ls.srv.Serve(&peerListener{Listener: ln, b: b, ls: ls})
}

var errUnknownLink = errors.New("no link published at this address")

// errorLog sends net/http's own errors (TLS, malformed requests, panics)
// to Logf instead of discarding them.
func (b *Broker) errorLog(prefix string) *log.Logger {
	return log.New(logfWriter(func(s string) { b.deps.Logf("%s%s", prefix, strings.TrimSpace(s)) }), "", 0)
}

type logfWriter func(string)

func (f logfWriter) Write(p []byte) (int, error) { f(string(p)); return len(p), nil }

// attach registers a server for one allocation generation. A server already
// registered at the key is detached under the lock and closed outside it
// (its connections' untrack callbacks take the lock).
func (b *Broker) attach(ln net.Listener, key netip.AddrPort, inc string) (*linkServer, error) {
	ls := &linkServer{key: key, inc: inc, conns: map[*trackedConn]struct{}{},
		psem: make(chan struct{}, b.cfg.Limits.PerLinkProxy), msem: make(chan struct{}, b.cfg.Limits.PerLinkMetadata),
		rate: newRateBucket(b.cfg.Limits.LinkRequestsPerSec, b.cfg.Limits.LinkRequestBurst)}
	ls.srv = &http.Server{
		Handler:           b,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return context.WithValue(context.Background(), keyListener, key) },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, keyConn, c) // the trackedConn: its server generation is the caller's
		},
		ErrorLog: b.errorLog("http server " + key.String() + ": "),
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		ln.Close()
		return nil, ErrClosed
	}
	old := b.servers[key]
	if old != nil {
		old.dead = true
	}
	b.servers[key] = ls
	b.mu.Unlock()
	if old != nil {
		_ = old.srv.Close() // MUTANT:closeUnderLock
	}
	return ls, nil
}

// Close stops every listener and connection, settles and joins the mint
// workers (at most 5 s), and makes later Syncs no-ops.
func (b *Broker) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.syncMu.Lock() // wait for a Sync in flight
	b.syncMu.Unlock()
	b.mu.Lock()
	srvs := b.servers
	b.servers = map[netip.AddrPort]*linkServer{}
	for _, ls := range srvs {
		ls.dead = true
	}
	b.mu.Unlock()
	for _, s := range srvs {
		_ = s.srv.Close()
	}
	if err := b.creds.close(5 * time.Second); err != nil {
		b.deps.Logf("close: %v", err)
		return err
	}
	return nil
}

// serving returns the link a connection of server generation ls may act
// for: ls still registered and alive, the same incarnation published at its
// address, and the authorization generation valid. Also the per-link
// semaphores.
func (b *Broker) serving(ls *linkServer) (Link, bool) {
	if ls == nil {
		return Link{}, false
	}
	b.mu.Lock()
	l, ok := b.links[ls.key]
	live := !ls.dead && b.servers[ls.key] == ls && ok && l.Incarnation == ls.inc // MUTANT:connIncarnationUnchecked
	b.mu.Unlock()
	if !live || !b.authOK(b.currentGen()) {
		return Link{}, false
	}
	return l, true
}

// trackedConn is an accepted connection and the server generation (hence
// the allocation) it belongs to.
type trackedConn struct {
	net.Conn
	ls   *linkServer
	once sync.Once
	b    *Broker
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.b.mu.Lock()
		delete(c.ls.conns, c) // this server generation's set, never a later one's
		c.b.mu.Unlock()
	})
	return c.Conn.Close()
}

// testHookAccepted runs after the kernel hands over a connection and before
// it is validated (tests pause here).
var testHookAccepted atomic.Pointer[func()]

// peerListener admits a connection only for its own server generation:
// validation of generation, link, peer, authorization and the connection
// cap, and the tracking, happen in one critical section, so a connection
// is never tagged with an allocation other than the one its listener
// served, and never tracked by a generation already torn down.
type peerListener struct {
	net.Listener
	b  *Broker
	ls *linkServer
}

func (p *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if h := testHookAccepted.Load(); h != nil {
			(*h)()
		}
		ra, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		authOK := p.b.authOK(p.b.currentGen())
		reason := ""
		p.b.mu.Lock()
		l, ok := p.b.links[p.ls.key]
		switch {
		case p.ls.dead || p.b.servers[p.ls.key] != p.ls || !ok || l.Incarnation != p.ls.inc || !authOK:
			reason = "unknown_link"
		case !l.peerOK(ra.Addr()):
			reason = "peer"
		case len(p.ls.conns) >= p.b.cfg.Limits.MaxConnsPerLink: // MUTANT:connUnlimited
			reason = "conn_limit"
		}
		var tc *trackedConn
		if reason == "" {
			tc = &trackedConn{Conn: c, ls: p.ls, b: p.b}
			p.ls.conns[tc] = struct{}{}
		}
		p.b.mu.Unlock()
		if tc != nil {
			return tc, nil
		}
		p.b.Count.Add("deny_" + reason)
		now := p.b.cfg.Now()
		if ok, suppressed := p.b.denyLim.allow("conn "+p.ls.key.String(), now); ok {
			p.b.deps.Audit.Audit(AuditEvent{Time: now, Kind: "conn", Link: p.ls.key.String(), Remote: ra.String(),
				Decision: "deny", Reason: reason, Outcome: "not_done", Suppressed: suppressed})
		} else {
			p.b.Count.Add("audit_conn_deny_suppressed")
		}
		c.Close()
	}
}

// rateBucket is a small token bucket (per-link request admission).
type rateBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateBucket(perSec float64, burst int) *rateBucket {
	return &rateBucket{rate: perSec, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (r *rateBucket) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens = min(r.burst, r.tokens+now.Sub(r.last).Seconds()*r.rate)
	r.last = now
	if r.tokens < 1 { // MUTANT:linkRateUnchecked
		return false
	}
	r.tokens--
	return true
}

// Metrics returns the counters (AMBIGUITY.md rule 5).
func (b *Broker) Metrics() map[string]int64 { return b.Count.Snapshot() }

// WritePrometheus renders counters in the Prometheus text format.
func WritePrometheus(w io.Writer, m map[string]int64) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if _, err := io.WriteString(w, "# TYPE yard_broker_events_total counter\n"); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "yard_broker_events_total{event=%q} %d\n", k, m[k]); err != nil {
			return err
		}
	}
	return nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "yard_broker", "message": msg}})
}
