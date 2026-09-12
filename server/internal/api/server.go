package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/web"
	"privatephone/server/internal/ws"
)

const maxBody = 1 << 20 // 1 MiB

type Server struct {
	st      *db.Store
	hub     *ws.Hub
	ver     *protocol.Verifier
	srv     *http.Server
	tlsCert string
	tlsKey  string
}

// WithTLS switches the node to HTTPS/WSS using the given certificate files.
func (s *Server) WithTLS(certFile, keyFile string) *Server {
	s.tlsCert, s.tlsKey = certFile, keyFile
	return s
}

func New(st *db.Store, hub *ws.Hub, ver *protocol.Verifier, addr string) *Server {
	s := &Server{st: st, hub: hub, ver: ver}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/ws", s.hub.Handle)

	mux.HandleFunc("GET /api/v1/subscribers", s.signed(s.handleListSubscribers))
	mux.HandleFunc("GET /api/v1/snapshot", s.signed(s.handleSnapshot))
	mux.HandleFunc("GET /api/v1/pending", s.signed(s.handlePending))
	mux.Handle("POST /api/v1/markers", s.signed(s.handleSubmit))
	mux.Handle("POST /api/v1/messages", s.signed(s.handleSubmit))
	mux.Handle("POST /api/v1/alerts", s.signed(s.handleSubmit))
	mux.Handle("POST /api/v1/zones", s.signed(s.handleSubmit))
	mux.Handle("POST /api/v1/ca/subscribers", s.signedAdmin(s.handleCreateSubscriber))
	mux.Handle("POST /api/v1/ca/revoke", s.signedAdmin(s.handleSubscriberStatus))
	mux.Handle("GET /api/v1/journal", s.signedAdmin(s.handleJournalExport))
	mux.Handle("POST /api/v1/journal/verify", s.signedAdmin(s.handleJournalVerify))
	mux.Handle("POST /api/v1/journal/import", s.signedAdmin(s.handleJournalImport))
	mux.Handle("GET /api/v1/admin/stats", s.signedAdmin(s.handleAdminStats))

	mux.Handle("/tiles/", http.StripPrefix("/tiles/", http.FileServer(http.FS(web.Tiles()))))
	mux.Handle("/", s.spa(web.Dist()))

	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

func (s *Server) httpServe() error {
	if s.tlsCert != "" && s.tlsKey != "" {
		return s.srv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}
	return s.srv.ListenAndServe()
}

func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", s.srv.Addr)
		errCh <- s.httpServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return s.srv.Shutdown(shCtx)
	}
}

func (s *Server) Handler() http.Handler {
	return s.srv.Handler
}

// signed extracts and verifies the packet, then calls handler. Any failure is
// answered with 401 before the handler can touch the database.
func (s *Server) signed(handler func(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, err := s.decodeEnvelope(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if _, err := s.ver.Verify(r.Context(), ev); err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		handler(w, r, ev)
	}
}

// signedAdmin additionally requires the caller's role to be "admin".
func (s *Server) signedAdmin(handler func(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, err := s.decodeEnvelope(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		role, err := s.ver.Verify(r.Context(), ev)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if role != "admin" {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		handler(w, r, ev)
	}
}

func (s *Server) decodeEnvelope(r *http.Request) (*protocol.Envelope, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return nil, errors.New("read body")
	}
	_ = r.Body.Close()
	ev := &protocol.Envelope{
		Sender:    r.Header.Get("X-Sender"),
		Signature: r.Header.Get("X-Signature"),
		Nonce:     r.Header.Get("X-Nonce"),
		Kind:      r.Header.Get("X-Kind"),
		Data:      body,
	}
	ts, err := parseTS(r.Header.Get("X-TS"))
	if err != nil {
		return nil, errors.New("bad timestamp")
	}
	ev.TS = ts
	if ev.Sender == "" || ev.Kind == "" || ev.Nonce == "" || ev.Signature == "" {
		return nil, errors.New("missing signed fields")
	}
	return ev, nil
}

func parseTS(v string) (int64, error) {
	var ts int64
	_, err := fmt.Sscan(v, &ts)
	return ts, err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
