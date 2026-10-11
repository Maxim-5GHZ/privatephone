package api

import (
	"net/http"
	"strconv"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

// fileBodyLimit caps one signed file upload: 8 MiB ciphertext is ~10.7 MiB
// base64 plus the key envelope and signature headers.
const fileBodyLimit = 12 << 20 // 12 MiB

// snapshotMessageCap keeps the live snapshot bounded on LAN nodes; older rows
// stay reachable via GET /api/v1/messages (history paging).
const snapshotMessageCap = ws.SnapshotMessageCap

// signedLarge is like signed but allows a bigger signed JSON body (files).
// Signature still covers the exact raw bytes.
func (s *Server) signedLarge(limit int, handler func(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, err := s.decodeEnvelopeWithLimit(r, limit)
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

// handleMessageHistory pages visible messages older than ?before_id= (0 =
// latest), newest-first capped at ?limit= (default 50, max 200). Search over
// ciphertext is meaningless, so text search lives client-side over decrypted
// rows; the server only pages.
func (s *Server) handleMessageHistory(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	msgs, more, err := s.st.ListMessagesPaged(r.Context(), ev.Sender, before, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "history")
		return
	}
	if msgs == nil {
		msgs = []db.Message{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs, "more": more})
}

// handleGetFile returns one full file record (with blob) the caller may see,
// addressed by ?sender= + ?n=. Snapshots carry metadata only; bytes load here.
func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	sender := r.URL.Query().Get("sender")
	n := r.URL.Query().Get("n")
	if sender == "" || n == "" {
		writeErr(w, http.StatusBadRequest, "sender and n required")
		return
	}
	f, err := s.st.FileByNonce(r.Context(), sender, n)
	if err != nil {
		writeErr(w, http.StatusNotFound, "file not found")
		return
	}
	// Visibility reuses the file list (same rules as messages): the row must
	// be present in what the caller may see.
	visible, err := s.st.ListFilesFor(r.Context(), ev.Sender)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "file")
		return
	}
	allowed := false
	for _, v := range visible {
		if v.Sender == f.Sender && v.Nonce == f.Nonce {
			allowed = true
			break
		}
	}
	if !allowed {
		writeErr(w, http.StatusForbidden, "not addressed to you")
		return
	}
	writeJSON(w, http.StatusOK, f)
}
