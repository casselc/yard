// Package ctl is the yard-ctl HTTP API: the STS mint endpoint, key
// administration, and the published discovery/JWKS documents.
package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"yard/internal/frontend"
	"yard/internal/issuer"
	"yard/internal/jwks"
	"yard/internal/keyring"
)

// MaxBody bounds request bodies.
const MaxBody = 16 << 10

// Server wires the pieces together.
type Server struct {
	FE   frontend.Frontend
	Iss  *issuer.Issuer
	Ring *keyring.Ring
	Pub  *jwks.Publisher
	Log  func(format string, a ...any)

	mu sync.Mutex // serialises key administration + publishing
}

// Republish renders the current JWKS and writes it out.
func (s *Server) Republish() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.republishLocked()
}

func (s *Server) republishLocked() error {
	changed, err := s.Pub.Publish(s.Ring.JWKS())
	if err == nil && changed {
		st := s.Ring.Snapshot()
		s.logf("jwks published: generation=%d keys=%d", st.Generation, len(s.Ring.JWKS().Keys))
	}
	return err
}

func (s *Server) logf(f string, a ...any) {
	if s.Log != nil {
		s.Log(f, a...)
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(jwks.JWKSPath, s.Pub)
	mux.Handle(jwks.DiscoveryPath, s.Pub)
	mux.HandleFunc("POST /v1/mint", s.auth("mint", s.handleMint))
	mux.HandleFunc("GET /v1/keys", s.auth("admin", s.handleKeys))
	mux.HandleFunc("POST /v1/admin/rotate", s.auth("admin", s.handleRotate))
	mux.HandleFunc("POST /v1/admin/retire", s.auth("admin", s.handleRetire))
	return mux
}

type ctxCaller struct{}

func (s *Server) auth(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.FE.Identify(r)
		if err != nil {
			s.logf("auth: %s %s: %v", r.Method, r.URL.Path, err)
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if !c.Has(role) {
			s.logf("auth: %s lacks role %s for %s", c.Name, role, r.URL.Path)
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxCaller{}, c)))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(v)
	w.Write(append(b, '\n'))
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) handleMint(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(ctxCaller{}).(frontend.Caller)
	var req issuer.Request
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	tok, err := s.Iss.Mint(issuer.Caller{Name: c.Name}, &req)
	if err != nil {
		var pe *issuer.PolicyError
		if errors.As(err, &pe) {
			s.logf("mint denied caller=%s kind=%s aud=%q: %v", c.Name, req.Kind, req.Audience, err)
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		s.logf("mint error caller=%s: %v", c.Name, err)
		writeErr(w, http.StatusInternalServerError, "mint failed")
		return
	}
	// Never log the token itself.
	s.logf("mint caller=%s kind=%s aud=%q sub=%q seq=%d kid=%s exp=%d", c.Name, req.Kind, req.Audience, tok.Sub, tok.Seq, tok.Kid, tok.Exp)
	writeJSON(w, http.StatusOK, tok)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Ring.Snapshot())
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Ring.Rotate(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.logf("rotated by %s", r.Context().Value(ctxCaller{}).(frontend.Caller).Name)
	if err := s.republishLocked(); err != nil {
		writeErr(w, http.StatusInternalServerError, "rotated, but publish failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Ring.Snapshot())
}

func (s *Server) handleRetire(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Ring.Retire(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.logf("retired by %s", r.Context().Value(ctxCaller{}).(frontend.Caller).Name)
	if err := s.republishLocked(); err != nil {
		writeErr(w, http.StatusInternalServerError, "retired, but publish failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Ring.Snapshot())
}

// Housekeep retires a retiring key once its grace has passed. Call it
// periodically.
func (s *Server) Housekeep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Ring.RetireDue() {
		return nil
	}
	if err := s.Ring.Retire(); err != nil {
		return fmt.Errorf("auto-retire: %w", err)
	}
	s.logf("auto-retired the retiring key")
	return s.republishLocked()
}

// Run serves until ctx is done.
func (s *Server) Run(ctx context.Context, every time.Duration) error {
	if err := s.Republish(); err != nil {
		return err
	}
	l, err := s.FE.Listen()
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: s.Handler(), ConnContext: s.FE.ConnContext,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(l) }()
	s.logf("serving on %s", s.FE)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return hs.Shutdown(sc)
		case err := <-errc:
			return err
		case <-t.C:
			if err := s.Housekeep(); err != nil {
				s.logf("housekeep: %v", err)
			}
		}
	}
}
