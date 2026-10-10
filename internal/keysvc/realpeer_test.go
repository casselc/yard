package keysvc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional cross-repository check: run only with the shared GPU lock held.
// It mints real signed operations, seals/restores a real cached state through
// the C++ admin socket, and checks both sides' durable epoch observations.
func TestRealHaloPeer(t *testing.T) {
	binary, model := os.Getenv("HALO_KEYS_PEER_BINARY"), os.Getenv("HALO_KEYS_PEER_MODEL")
	if binary == "" || model == "" {
		t.Skip("set HALO_KEYS_PEER_BINARY and HALO_KEYS_PEER_MODEL under the shared GPU lock")
	}
	if os.Getenv("HALO_GPU_LOCKED") != "1" {
		t.Fatal("real peer test requires the shared GPU lock launcher")
	}
	e := newEnvWithBits(t, mutants{}, 2048) // C++ JWKS policy rejects smaller RSA keys
	e.clock.Store(time.Now().UnixMilli())
	dir, err := os.MkdirTemp("", "keypeer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	jwks, err := json.Marshal(e.ring.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	jpath, socket := filepath.Join(dir, "jwks.json"), filepath.Join(dir, "admin.sock")
	if err := os.WriteFile(jpath, jwks, 0600); err != nil {
		t.Fatal(err)
	}
	log := &bytes.Buffer{}
	cmd := exec.Command(binary, "--model", model, "--host", "127.0.0.1", "--port", "18439",
		"--max-context", "4096", "--prefix-cache", "fast", "--spill-dir", filepath.Join(dir, "spill"),
		"--yard-jwks", jpath, "--yard-issuer", testIss, "--admin-socket", socket)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = append(os.Environ(), "HALO_CACHE_TRACE=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("peer shutdown: %v\n%s", err, log.String())
			}
			if t.Failed() {
				t.Logf("peer log: %s", log.String())
			}
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("peer did not stop within 30 seconds")
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(180 * time.Second)
	for {
		resp, err := client.Get("http://127.0.0.1:18439/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("real peer startup timeout")
		}
		time.Sleep(time.Second)
	}
	client.Timeout = 120 * time.Second
	// Raw completions have no stable chat-prefix checkpoint. Fast mode retains
	// their finished live state, providing the entry used by the admin route.
	request, err := json.Marshal(map[string]any{"model": "halo", "prompt": strings.Repeat("The quick brown fox jumps over the lazy dog. ", 80),
		"temperature": 0, "max_tokens": 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post("http://127.0.0.1:18439/v1/completions", "application/json",
		bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("cache-seeding request: %d %s", resp.StatusCode, responseBody)
	}
	e.svc.o.Halo = NewUnixHalo(socket, os.Getuid(), 120*time.Second)
	entries, err := e.svc.o.Halo.Sessions(e.ctx)
	if err != nil || len(entries) == 0 {
		t.Fatalf("cache entries: %+v, %v", entries, err)
	}
	e.epochs.set("s1", 1)
	for checkpoint := int64(10); checkpoint < 12; checkpoint++ {
		e.clock.Store(time.Now().UnixMilli())
		if err := e.cycle("s1", checkpoint, entries[0].Key); err != nil {
			t.Fatalf("real checkpoint %d: %v", checkpoint, err)
		}
		view, err := e.svc.o.Halo.Keys(e.ctx)
		if err != nil || view.Sess("s1").RestoredEpoch != checkpoint-8 {
			t.Fatalf("restored epoch after checkpoint %d: %+v, %v", checkpoint, view, err)
		}
	}
	t.Log("two signed operation-id spill/restore cycles completed against the real C++ peer")
}
