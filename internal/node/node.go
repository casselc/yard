// Package node is yard-node: the process that owns an agent's VMs on one host (design/AGENT-OPERATIONS.md
// section 5). It is told what to start by yard-ctl and answers for each allocation by its id, which is never
// reused:
//
//	POST /v1/allocs/{id}/start      start it (idempotent); a tombstoned id is refused (410)
//	GET  /v1/allocs/{id}            running | exited | absent | tombstoned, with the exit and whether a result came
//	GET  /v1/allocs/{id}/result     the guest's result, once received (kept until the allocation is forgotten)
//	POST /v1/allocs/{id}/stop       kill and reap (idempotent); answers the state after
//	POST /v1/allocs/{id}/tombstone  refuse any later start; stops it if it runs (F3, F4)
//	POST /v1/allocs/{id}/lease      renew the lease; at its expiry the node stops the VM itself (F8)
//	DELETE /v1/allocs/{id}          forget it (yard-ctl has captured what it needed)
//	GET  /v1/allocs                 every allocation the node knows (reconciliation, F7)
//
// Exit records and tombstones are files, so they survive a node restart; VMs are started with a parent-death
// signal, so a node that dies takes its VMs with it, and on restart every allocation that was running is
// recorded exited ("node_restart"). The control channel of each VM (task out, result in) is the node's: it
// listens on the allocation's v.sock_5000, sends the task, writes the result durably, then acks the guest.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Spec is what yard-ctl asks the node to run.
type Spec struct {
	VCPU    int64             `json:"vcpu"`
	MemMiB  int64             `json:"mem_mib"`
	Kernel  string            `json:"kernel"`
	Rootfs  string            `json:"rootfs"`
	Input   string            `json:"input"` // the read-only input image
	Task    json.RawMessage   `json:"task"`  // passed to the guest as is
	LeaseMs int64             `json:"lease_ms"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// State of an allocation as the node reports it.
type State struct {
	ID       string `json:"id"`
	State    string `json:"state"` // running | exited | absent | tombstoned
	Finished bool   `json:"finished"`
	Exit     string `json:"exit,omitempty"` // why it exited: guest, stopped, lease, crashed, node_restart, start_failed
	StartMs  int64  `json:"start_unix_ms,omitempty"`
	EndMs    int64  `json:"end_unix_ms,omitempty"`
}

// VM is one running VM, as a Launcher starts it.
type VM interface {
	Wait() error // returns when the VM process has exited (reaped)
	Kill() error
	CPU() (user, sys time.Duration, maxRSSKiB int64)
}

// Launcher starts a VM for an allocation in dir (where its sockets live).
type Launcher interface {
	Launch(id, dir string, s Spec) (VM, error)
}

type alloc struct {
	State
	spec     Spec
	vm       VM
	lease    time.Time
	done     chan struct{}
	stopping bool
}

type Node struct {
	root  string // one directory per allocation
	l     Launcher
	mu    sync.Mutex
	alloc map[string]*alloc
	now   func() time.Time
	Logf  func(string, ...any)
	dead  bool // a crashed node writes nothing more (tests: crash)
}

var idRe = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

// New opens the node over root, recovering what its files say.
func New(root string, l Launcher) (*Node, error) {
	n := &Node{root: root, l: l, alloc: map[string]*alloc{}, now: time.Now, Logf: func(string, ...any) {}}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() || !idRe.MatchString(e.Name()) {
			continue
		}
		var st State
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "state.json"))
		if err != nil || json.Unmarshal(b, &st) != nil {
			continue
		}
		if st.State == "running" { // it died with the previous node process
			st.State, st.Exit, st.EndMs = "exited", "node_restart", n.now().UnixMilli()
		}
		st.Finished = fileExists(filepath.Join(root, e.Name(), "result.json"))
		a := &alloc{State: st, done: make(chan struct{})}
		close(a.done)
		n.alloc[e.Name()] = a
		n.save(a)
	}
	return n, nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func (n *Node) dir(id string) string { return filepath.Join(n.root, id) }

// save writes the allocation's state atomically (file, fsync, rename).
func (n *Node) save(a *alloc) {
	if n.dead {
		return
	}
	b, _ := json.Marshal(a.State)
	p := filepath.Join(n.dir(a.ID), "state.json")
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		n.Logf("save %s: %v", a.ID, err)
		return
	}
	f.Write(b)
	f.Sync()
	f.Close()
	if err := os.Rename(tmp, p); err != nil {
		n.Logf("save %s: %v", a.ID, err)
	}
}

func (n *Node) get(id string) State {
	n.mu.Lock()
	defer n.mu.Unlock()
	if a, ok := n.alloc[id]; ok {
		a.Finished = a.Finished || fileExists(filepath.Join(n.dir(id), "result.json"))
		return a.State
	}
	return State{ID: id, State: "absent"}
}

var (
	errTombstoned = errors.New("tombstoned")
	errBadID      = errors.New("bad allocation id")
)

// Start starts the allocation unless it exists (idempotent) or is tombstoned.
func (n *Node) Start(id string, s Spec) (State, error) {
	if !idRe.MatchString(id) { // recovery reloads only valid ids: never write state it would not reload
		return State{}, errBadID
	}
	n.mu.Lock()
	if a, ok := n.alloc[id]; ok {
		n.mu.Unlock()
		if a.State.State == "tombstoned" {
			return a.State, errTombstoned
		}
		return n.get(id), nil
	}
	if err := os.MkdirAll(n.dir(id), 0o700); err != nil {
		n.mu.Unlock()
		return State{}, err
	}
	a := &alloc{State: State{ID: id, State: "running", StartMs: n.now().UnixMilli()}, spec: s, done: make(chan struct{})}
	if s.LeaseMs > 0 {
		a.lease = n.now().Add(time.Duration(s.LeaseMs) * time.Millisecond)
	}
	n.alloc[id] = a
	n.save(a)
	n.mu.Unlock()
	vm, err := n.l.Launch(id, n.dir(id), s)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		a.State.State, a.Exit, a.EndMs = "exited", "start_failed", n.now().UnixMilli()
		close(a.done)
		n.save(a)
		return a.State, err
	}
	a.vm = vm
	go n.reap(a)
	return a.State, nil
}

func (n *Node) reap(a *alloc) {
	err := a.vm.Wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	if a.State.State == "running" {
		a.State.State = "exited"
	}
	if a.Exit == "" {
		a.Exit = "guest"
		if fileExists(filepath.Join(n.dir(a.ID), "result.json")) {
			a.Finished = true
		} else if err != nil {
			a.Exit = "crashed"
		}
	}
	a.EndMs = n.now().UnixMilli()
	n.save(a)
	close(a.done)
}

// crash makes the node stop writing, as a node process that died would (tests).
func (n *Node) crash() {
	n.mu.Lock()
	n.dead = true
	n.mu.Unlock()
}

// Stop kills the VM and waits for it to be reaped (bounded by ctx).
func (n *Node) Stop(ctx context.Context, id, why string) (State, error) {
	n.mu.Lock()
	a, ok := n.alloc[id]
	if !ok {
		n.mu.Unlock()
		return State{ID: id, State: "absent"}, nil
	}
	if a.State.State == "running" && a.vm != nil {
		if a.Exit == "" {
			a.Exit = why
		}
		a.vm.Kill()
	}
	done := a.done
	n.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return n.get(id), ctx.Err()
	}
	return n.get(id), nil
}

// Tombstone refuses any later start of the allocation; one that runs is stopped first.
func (n *Node) Tombstone(ctx context.Context, id string) (State, error) {
	if !idRe.MatchString(id) {
		return State{}, errBadID
	}
	n.mu.Lock()
	a, ok := n.alloc[id]
	if !ok {
		if err := os.MkdirAll(n.dir(id), 0o700); err != nil {
			n.mu.Unlock()
			return State{}, err
		}
		a = &alloc{State: State{ID: id, State: "tombstoned"}, done: make(chan struct{})}
		close(a.done)
		n.alloc[id] = a
		n.save(a)
		n.mu.Unlock()
		return a.State, nil
	}
	n.mu.Unlock()
	if _, err := n.Stop(ctx, id, "tombstoned"); err != nil {
		return n.get(id), err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	a.State.State = "tombstoned"
	n.save(a)
	return a.State, nil
}

// Renew extends the allocation's lease.
func (n *Node) Renew(id string, ms int64) (State, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, ok := n.alloc[id]
	if !ok {
		return State{ID: id, State: "absent"}, nil
	}
	a.lease = n.now().Add(time.Duration(ms) * time.Millisecond)
	return a.State, nil
}

// Watchdog stops every running VM whose lease has expired (F8). Call it periodically.
func (n *Node) Watchdog(ctx context.Context) {
	n.mu.Lock()
	var due []string
	for id, a := range n.alloc {
		if a.State.State == "running" && !a.lease.IsZero() && n.now().After(a.lease) {
			due = append(due, id)
		}
	}
	n.mu.Unlock()
	for _, id := range due {
		n.Logf("lease expired: stopping %s", id)
		n.Stop(ctx, id, "lease")
	}
}

// Forget drops an exited or tombstoned allocation's records.
func (n *Node) Forget(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	a, ok := n.alloc[id]
	if !ok {
		return nil
	}
	if a.State.State == "running" {
		return fmt.Errorf("%s is running", id)
	}
	delete(n.alloc, id)
	return os.RemoveAll(n.dir(id))
}

func (n *Node) List() []State {
	n.mu.Lock()
	ids := make([]string, 0, len(n.alloc))
	for id := range n.alloc {
		ids = append(ids, id)
	}
	n.mu.Unlock()
	sort.Strings(ids)
	out := make([]State, 0, len(ids))
	for _, id := range ids {
		out = append(out, n.get(id))
	}
	return out
}

// Result is the guest's result file, once received.
func (n *Node) Result(id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(n.dir(id), "result.json"))
}

// Handler serves the node's API.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	withID := func(f func(w http.ResponseWriter, r *http.Request, id string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if !idRe.MatchString(id) {
				reply(w, 400, map[string]string{"error": "bad allocation id"})
				return
			}
			f(w, r, id)
		}
	}
	mux.HandleFunc("POST /v1/allocs/{id}/start", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		var s Spec
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&s); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		st, err := n.Start(id, s)
		switch {
		case errors.Is(err, errTombstoned):
			reply(w, 410, st)
		case err != nil:
			reply(w, 500, map[string]any{"error": err.Error(), "state": st})
		default:
			reply(w, 200, st)
		}
	}))
	mux.HandleFunc("GET /v1/allocs/{id}", withID(func(w http.ResponseWriter, r *http.Request, id string) { reply(w, 200, n.get(id)) }))
	mux.HandleFunc("GET /v1/allocs/{id}/result", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		b, err := n.Result(id)
		if err != nil {
			reply(w, 404, map[string]string{"error": "no result"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	mux.HandleFunc("POST /v1/allocs/{id}/stop", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		st, err := n.Stop(ctx, id, "stopped")
		if err != nil {
			reply(w, 504, st)
			return
		}
		reply(w, 200, st)
	}))
	mux.HandleFunc("POST /v1/allocs/{id}/tombstone", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		st, err := n.Tombstone(ctx, id)
		if err != nil {
			reply(w, 504, st)
			return
		}
		reply(w, 200, st)
	}))
	mux.HandleFunc("POST /v1/allocs/{id}/lease", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		var b struct {
			Ms int64 `json:"ms"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b)
		st, _ := n.Renew(id, b.Ms)
		reply(w, 200, st)
	}))
	mux.HandleFunc("DELETE /v1/allocs/{id}", withID(func(w http.ResponseWriter, r *http.Request, id string) {
		if err := n.Forget(id); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"forgotten": id})
	}))
	mux.HandleFunc("GET /v1/allocs", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, n.List()) })
	return mux
}

// Serve serves the API on a Unix socket and runs the watchdog until ctx ends.
func (n *Node) Serve(ctx context.Context, sock string) error {
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	os.Chmod(sock, 0o600)
	srv := &http.Server{Handler: n.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				srv.Close()
				return
			case <-t.C:
				n.Watchdog(ctx)
			}
		}
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
