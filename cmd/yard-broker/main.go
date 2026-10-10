// Command yard-broker is the per-node egress and credential broker (B0).
//
//	yard-broker -config /usr/local/etc/yard/broker.json          # serve
//	yard-broker -config /usr/local/etc/yard/broker.json -check   # validate, print the links, exit (writes nothing)
//
// It pulls the link snapshot from registry_file (written by yard-ctl /
// yard-spawn, replaced by rename, with a serial and an issue time) every
// sync_interval, keeps its floors (serial, epochs, retired incarnations) in
// floors_file, opens one listener per link, and serves the halo, provider
// and metadata routes (internal/broker). Secrets come from secrets_dir (one
// 0600 file per name). It never reads the environment for credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"yard/internal/broker"
)

type fileConfig struct {
	broker.Config
	SecretsDir   string `json:"secrets_dir"`
	RegistryFile string `json:"registry_file"`
	FloorsFile   string `json:"floors_file"`
	AuditFile    string `json:"audit_file"` // required; "-" = stdout, explicitly
	SpansFile    string `json:"spans_file"`
	MetricsFile  string `json:"metrics_file"` // Prometheus text, rewritten every sync
	SyncInterval string `json:"sync_interval"`
	Minter       string `json:"minter"` // "none" (default) | "dev-fake" (needs -dev)
	Metadata     struct {
		RoleName string `json:"role_name"`
		ECSPath  string `json:"ecs_path"`
	} `json:"metadata"`
}

func main() {
	cfgPath := flag.String("config", "/usr/local/etc/yard/broker.json", "config file")
	check := flag.Bool("check", false, "validate the config and the snapshot, print the links, exit (writes nothing)")
	dev := flag.Bool("dev", false, "development mode: allows loopback link addresses and the dev-fake minter (never in production)")
	initFloors := flag.Bool("init-floors", false, "create the floors file of a NEW install and exit (refuses if one exists)")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)
	if *initFloors {
		if err := initFloorsFile(*cfgPath); err != nil {
			log.Fatalf("yard-broker: %v", err)
		}
		return
	}
	if err := run(*cfgPath, *check, *dev); err != nil {
		log.Fatalf("yard-broker: %v", err)
	}
}

// openLog opens an append-only log owned by us with no group/other bits;
// an existing file of another type, owner or mode is refused.
func openLog(path string) (*os.File, error) {
	if path == "-" {
		return os.Stdout, nil
	}
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("log path %q: want an absolute path (or \"-\" for stdout)", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !fi.Mode().IsRegular():
			err = fmt.Errorf("%s is not a regular file", path)
		case fi.Mode().Perm()&0o077 != 0:
			err = fmt.Errorf("%s has mode %#o; want 0600", path, fi.Mode().Perm())
		case !ok || int(st.Uid) != os.Geteuid():
			err = fmt.Errorf("%s is not owned by uid %d", path, os.Geteuid())
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func loadConfig(cfgPath string) (fileConfig, error) {
	var fc fileConfig
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return fc, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return fc, fmt.Errorf("%s: %w", cfgPath, err)
	}
	return fc, nil
}

// initFloorsFile creates the floors file of a new install (never over an
// existing one: a missing file on an established install is recovery).
func initFloorsFile(cfgPath string) error {
	fc, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if fc.FloorsFile == "" {
		return errors.New("floors_file is required")
	}
	if err := broker.InitFileFloors(fc.FloorsFile); err != nil {
		return err
	}
	log.Printf("initialised %s", fc.FloorsFile)
	return nil
}

func run(cfgPath string, check, dev bool) error {
	fc, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	cfg := fc.Config
	cfg.AllowLoopback = dev
	cfg.Metadata.RoleName, cfg.Metadata.ECSPath = fc.Metadata.RoleName, fc.Metadata.ECSPath
	for i := range cfg.Providers {
		if cfg.Providers[i].Routes == nil {
			switch cfg.Providers[i].Inject {
			case "x-api-key":
				cfg.Providers[i].Routes = broker.AnthropicRoutes
			case "bearer":
				cfg.Providers[i].Routes = broker.OpenAIRoutes
			}
		}
	}
	interval := 5 * time.Second
	if fc.SyncInterval != "" {
		if interval, err = time.ParseDuration(fc.SyncInterval); err != nil || interval < 100*time.Millisecond {
			return fmt.Errorf("sync_interval %q", fc.SyncInterval)
		}
	}
	if fc.RegistryFile == "" || fc.FloorsFile == "" {
		return errors.New("registry_file and floors_file are required")
	}
	ff := broker.FileFloors{Path: fc.FloorsFile}
	var floors broker.FloorStore = ff
	var audit *broker.JSONLAudit
	var spans *broker.JSONLExporter
	if check { // -check writes nothing: no log file, no floors
		loaded, err := ff.Load()
		switch {
		case errors.Is(err, broker.ErrNoFloors):
			return errors.New("no floors file: run -init-floors for a new install, or restore it (recovery)")
		case err != nil:
			return err
		default:
			floors = &broker.MemFloors{F: &loaded}
		}
		audit = broker.NewJSONLAudit(io.Discard, 0, log.Printf)
	} else {
		aw, err := openLog(fc.AuditFile)
		if err != nil {
			return fmt.Errorf("audit_file: %w", err)
		}
		audit = broker.NewJSONLAudit(aw, 0, log.Printf)
		if fc.SpansFile != "" {
			sw, err := openLog(fc.SpansFile)
			if err != nil {
				return fmt.Errorf("spans_file: %w", err)
			}
			spans = broker.NewJSONLExporter(sw, 0, log.Printf)
		}
	}
	d := broker.Deps{Registry: broker.FileRegistry{Path: fc.RegistryFile}, Floors: floors, Audit: audit, Logf: log.Printf}
	if spans != nil {
		d.Spans = spans
	}
	if fc.SecretsDir != "" {
		d.Secrets = broker.FileSource{Dir: fc.SecretsDir}
	}
	switch fc.Minter {
	case "", "none":
	case "dev-fake":
		if !dev { // MUTANT:devFakeWithoutDev
			return errors.New(`minter "dev-fake" requires -dev (it must never run in production)`)
		}
		log.Printf("WARNING: dev-fake minter: the metadata endpoints serve obviously fake credentials")
		d.Minter = devMinter{}
	default:
		return fmt.Errorf("minter %q: B0 has none or dev-fake (the warden minter is B1)", fc.Minter)
	}
	br, err := broker.New(cfg, d)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if check {
		if err := br.Sync(ctx, false); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		sn, err := d.Registry.Snapshot(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("serial %d issued %s\n", sn.Serial, sn.Issued.UTC().Format(time.RFC3339))
		for _, l := range sn.Links {
			fmt.Printf("%v inc=%s peers=%v %s epoch=%d class=%s\n", l.Addr, l.Incarnation, l.Peers, br.Principal(l), l.Epoch, l.Class)
		}
		return br.Close()
	}
	metrics := func() {
		if fc.MetricsFile == "" {
			return
		}
		m := br.Metrics()
		m["audit_dropped"], m["audit_write_errors"] = audit.Sink.Dropped.Load(), audit.Sink.WriteErrors.Load()
		m["audit_abandoned"] = audit.Sink.Abandoned.Load()
		if spans != nil {
			m["spans_dropped"], m["spans_write_errors"] = spans.Sink.Dropped.Load(), spans.Sink.WriteErrors.Load()
			m["spans_abandoned"] = spans.Sink.Abandoned.Load()
		}
		var buf bytes.Buffer
		_ = broker.WritePrometheus(&buf, m)
		if err := writeAtomic(fc.MetricsFile, buf.Bytes()); err != nil {
			log.Printf("metrics: %v", err)
		}
	}
	if err := br.Sync(ctx, true); err != nil {
		log.Printf("sync: %v", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping")
			err := br.Close()
			// bounded drain; the terminal loss totals are exported after it
			audit.Sink.Close(5 * time.Second)
			if spans != nil {
				spans.Sink.Close(5 * time.Second)
			}
			metrics()
			return err
		case <-t.C:
			if err := br.Sync(ctx, true); err != nil {
				log.Printf("sync: %v", err)
			}
			metrics()
		}
	}
}

// devMinter serves credentials that cannot work anywhere (smoke tests of
// the SDK path only). Selected only with -dev.
type devMinter struct{}

func (devMinter) Mint(_ context.Context, req broker.MintRequest) (broker.Credential, error) {
	if !req.Begin(time.Now().Add(5 * time.Minute)) {
		return broker.Credential{}, broker.ErrNotSent
	}
	return broker.Credential{
		AccessKeyID:     "ASIAYARDDEVFAKE00000",
		SecretAccessKey: broker.NewSecret("dev-fake-secret-" + req.MintID),
		SessionToken:    broker.NewSecret("dev-fake-token-" + req.MintID),
		Expiration:      time.Now().Add(15 * time.Minute),
		Epoch:           req.Epoch,
		MintID:          req.MintID,
	}, nil
}
