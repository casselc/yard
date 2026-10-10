// yard-devsrv is the SR1 e2e's stand-in dev server: an HTTP server that
// keeps its state in the workspace, so a suspend/resume cycle can be checked
// from outside (HARNESS.md SR1; ops/sr1/sr1-10-e2e.sh).
//
//	yard-devsrv [-listen :8080] [-state /workspace/.devsrv/state.json]
//	            [-start-delay 0] [-ignore-term] [-hang-on-start N]
//
// At start it counts the start in the state file (fsynced) and then listens.
// GET /healthz answers 200 once listening; GET / answers its state as JSON.
// On SIGTERM it shuts down, counts a graceful stop, and exits 0, unless
// -ignore-term (then only SIGKILL ends it). -hang-on-start N: the N-th
// start never listens (a dev server that never gets ready).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type state struct {
	Starts int64 `json:"starts"` // processes started on this workspace
	Stops  int64 `json:"stops"`  // graceful stops (SIGTERM handled)
	Reqs   int64 `json:"reqs"`   // GET / served, saved at each graceful stop
}

var (
	mu   sync.Mutex
	st   state
	path string
)

func save() error {
	b, _ := json.Marshal(st)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	listen := flag.String("listen", ":8080", "address")
	flag.StringVar(&path, "state", "/workspace/.devsrv/state.json", "state file")
	delay := flag.Duration("start-delay", 0, "sleep before listening")
	ignoreTerm := flag.Bool("ignore-term", false, "ignore SIGTERM")
	hangOn := flag.Int64("hang-on-start", 0, "never listen on this start (1-based)")
	flag.Parse()
	t0 := time.Now()
	die := func(f string, a ...any) { fmt.Fprintf(os.Stderr, "yard-devsrv: "+f+"\n", a...); os.Exit(1) }
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		die("%v", err)
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			die("state %s: %v", path, err)
		}
	}
	st.Starts++
	if err := save(); err != nil {
		die("save: %v", err)
	}
	if *ignoreTerm {
		signal.Ignore(syscall.SIGTERM)
	}
	term := make(chan os.Signal, 1)
	if !*ignoreTerm {
		signal.Notify(term, syscall.SIGTERM)
	}
	if *hangOn > 0 && st.Starts == *hangOn {
		fmt.Fprintf(os.Stderr, "yard-devsrv: start %d: never listening (-hang-on-start)\n", st.Starts)
		<-term
		mu.Lock()
		st.Stops++
		save()
		os.Exit(0)
	}
	time.Sleep(*delay)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		die("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	// /mark?v=X: the service itself writes its workspace marker (inside its
	// jail, on its own clone) and fsyncs it; / reads it back
	mux.HandleFunc("/mark", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("v")
		f, err := os.OpenFile("/workspace/marker", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err == nil {
			_, err = f.WriteString(v)
			if serr := f.Sync(); err == nil {
				err = serr
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "marked", v)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		st.Reqs++
		out := map[string]any{"starts": st.Starts, "stops": st.Stops, "reqs": st.Reqs, "pid": os.Getpid(),
			"gen": os.Getenv("YARD_GEN"), "up_ms": time.Since(t0).Milliseconds()}
		mu.Unlock()
		if b, err := os.ReadFile("/workspace/marker"); err == nil {
			out["marker"] = string(b)
		}
		json.NewEncoder(w).Encode(out)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "yard-devsrv: start %d pid %d listening on %s after %s\n", st.Starts, os.Getpid(), ln.Addr(), time.Since(t0))
	go func() {
		<-term
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		mu.Lock()
		st.Stops++
		if err := save(); err != nil {
			fmt.Fprintf(os.Stderr, "yard-devsrv: save at stop: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "yard-devsrv: graceful stop %d\n", st.Stops)
		os.Exit(0)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		die("serve: %v", err)
	}
	select {} // Shutdown in progress: the signal goroutine exits
}
