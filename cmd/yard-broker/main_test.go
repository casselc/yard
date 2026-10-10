package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpenLogChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "audit.jsonl")
	f, err := openLog(good)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if fi, _ := os.Stat(good); fi.Mode().Perm() != 0o600 {
		t.Fatalf("created with %v", fi.Mode())
	}
	loose := filepath.Join(dir, "loose.jsonl")
	os.WriteFile(loose, nil, 0o644)
	os.Chmod(loose, 0o644)
	link := filepath.Join(dir, "link.jsonl")
	os.Symlink(good, link)
	fifo := filepath.Join(dir, "fifo")
	syscall.Mkfifo(fifo, 0o600)
	for _, p := range []string{loose, link, fifo, dir, "", "relative.jsonl"} {
		if f, err := openLog(p); err == nil {
			f.Close()
			t.Errorf("%q accepted", p)
		}
	}
}

func TestDevFakeMinterNeedsDevFlag(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "broker.json")
	os.WriteFile(cfg, []byte(`{"trust_domain":"home.arpa","registry_file":"`+dir+`/reg.json","floors_file":"`+dir+
		`/floors.json","audit_file":"`+dir+`/audit.jsonl","minter":"dev-fake"}`), 0o600)
	// an established install without its floors file is recovery, not first boot
	if err := run(cfg, true, true); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("missing floors: %v", err)
	}
	if err := initFloorsFile(cfg); err != nil {
		t.Fatal(err)
	}
	if err := initFloorsFile(cfg); err == nil {
		t.Fatal("-init-floors overwrote an existing floors file")
	}
	err := run(cfg, true, false)
	if err == nil || !strings.Contains(err.Error(), "-dev") {
		t.Fatalf("dev-fake without -dev: %v", err)
	}
	// -check writes nothing
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err == nil {
		t.Fatal("-check created the audit file")
	}
}
