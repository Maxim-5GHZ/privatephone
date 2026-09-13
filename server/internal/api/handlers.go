package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"privatephone/server/internal/ca"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "db unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListSubscribers(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	subs, err := s.st.ListSubscribers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list subscribers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscribers": subs})
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	markers, err := s.st.ListMarkers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "markers")
		return
	}
	messages, err := s.st.ListMessagesFor(r.Context(), ev.Sender)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "messages")
		return
	}
	alerts, err := s.st.ListActiveAlerts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "alerts")
		return
	}
	zones, err := s.st.ListZones(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "zones")
		return
	}
	writeJSON(w, http.StatusOK, ws.Snapshot{
		Markers: markers, Messages: messages, Alerts: alerts, Zones: zones, Online: s.hub.Online(),
	})
}

// handlePending returns the store-and-forward backlog the caller may see
// (broadcast, addressed to them, their own sends) — direct traffic never leaks
// to unrelated subscribers.
func (s *Server) handlePending(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	pkts, err := s.st.UndeliveredPacketsFor(r.Context(), ev.Sender)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": pkts})
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	f := protocol.Frame{
		Sender:    ev.Sender,
		TS:        ev.TS,
		Nonce:     ev.Nonce,
		Kind:      ev.Kind,
		Signature: ev.Signature,
		Data:      ev.Data,
	}
	switch ev.Kind {
	case "marker":
		rec, err := s.hub.IngestMarker(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("marker rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, rec)
	case "marker_update":
		rec, err := s.hub.IngestMarkerUpdate(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("marker update rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, rec)
	case "marker_delete":
		role, err := s.ver.Role(r.Context(), ev.Sender)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unknown sender")
			return
		}
		if err := s.hub.IngestMarkerDelete(r.Context(), f, role); err != nil {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("marker delete rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	case "message":
		rec, err := s.hub.IngestMessage(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("message rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, rec)
	case "alert":
		rec, err := s.hub.IngestAlert(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("alert rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, rec)
	case "alert_ack":
		rec, err := s.hub.IngestAlertAck(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("alert ack rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, rec)
	case "alert_clear":
		role, err := s.ver.Role(r.Context(), ev.Sender)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unknown sender")
			return
		}
		rec, err := s.hub.IngestAlertClear(r.Context(), f, role)
		if err != nil {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("alert clear rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, rec)
	case "zone":
		rec, err := s.hub.IngestZone(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("zone rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, rec)
	case "zone_update":
		rec, err := s.hub.IngestZoneUpdate(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("zone update rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, rec)
	case "zone_delete":
		role, err := s.ver.Role(r.Context(), ev.Sender)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unknown sender")
			return
		}
		if err := s.hub.IngestZoneDelete(r.Context(), f, role); err != nil {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("zone delete rejected: %v", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	default:
		writeErr(w, http.StatusBadRequest, "unsupported kind")
	}
}

func (s *Server) handleCreateSubscriber(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var req struct {
		Callsign string `json:"callsign"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil || req.Callsign == "" {
		writeErr(w, http.StatusBadRequest, "callsign required")
		return
	}
	if req.Role == "" {
		req.Role = "operator"
	}
	if req.Role != "operator" && req.Role != "admin" {
		writeErr(w, http.StatusBadRequest, "role must be operator or admin")
		return
	}
	res, err := ca.Create(r.Context(), s.st, req.Callsign, req.Role)
	if err != nil {
		if errors.Is(err, db.ErrDuplicate) {
			writeErr(w, http.StatusConflict, "callsign already registered")
			return
		}
		writeErr(w, http.StatusInternalServerError, "create subscriber")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"subscriber":  res.Subscriber,
		"public_pem":  res.PublicPEM,
		"private_pem": res.PrivatePEM,
	})
}

// handleSubscriberStatus revokes or unrevokes a callsign. The action is itself
// journaled (kind revoke_subscriber / unrevoke_subscriber) for the audit trail.
func (s *Server) handleSubscriberStatus(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	if ev.Kind != "revoke_subscriber" && ev.Kind != "unrevoke_subscriber" {
		writeErr(w, http.StatusBadRequest, "unsupported kind")
		return
	}
	var req struct {
		Callsign string `json:"callsign"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil || req.Callsign == "" {
		writeErr(w, http.StatusBadRequest, "callsign required")
		return
	}
	revoke := ev.Kind == "revoke_subscriber"
	var err error
	if revoke {
		err = s.st.RevokeSubscriber(r.Context(), req.Callsign)
	} else {
		err = s.st.UnrevokeSubscriber(r.Context(), req.Callsign)
	}
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "unknown callsign")
			return
		}
		writeErr(w, http.StatusInternalServerError, "subscriber status")
		return
	}
	f := protocol.Frame{
		Sender: ev.Sender, TS: ev.TS, Nonce: ev.Nonce, Kind: ev.Kind,
		Signature: ev.Signature, Data: ev.Data,
	}
	s.hub.Journal(r.Context(), f, "@system")
	s.hub.MarkRevoked(req.Callsign, revoke)
	if revoke {
		s.hub.Kick(req.Callsign)
	}
	key := "revoked"
	if !revoke {
		key = "unrevoked"
	}
	writeJSON(w, http.StatusOK, map[string]string{key: req.Callsign})
}

// handleJournalExport returns the ordered tamper-evident journal (admin only).
// The ?after=<unix-ts> parameter trims to packets with ts >= after — used for
// incremental sneaker-net transfer between isolated nodes.
func (s *Server) handleJournalExport(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var after int64
	if v := r.URL.Query().Get("after"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	entries, err := s.st.ListJournal(r.Context(), after)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "journal")
		return
	}
	head, err := s.st.JournalHead(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "journal head")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"head": head, "entries": entries})
}

// handleJournalVerify recomputes the hash chain and reports integrity.
func (s *Server) handleJournalVerify(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	bad, head, err := s.st.VerifyJournal(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "verify journal")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": bad < 0, "bad_index": bad, "head": head})
}

// handleJournalImport replays a sneaker-net bag onto this node (all-or-nothing
// validation, idempotent deduplication). Used by the admin UI as well as the
// CLI importer.
func (s *Server) handleJournalImport(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var req struct {
		Entries []db.JournalEntry `json:"entries"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bag must be JSON with an \"entries\" array")
		return
	}
	report, err := s.hub.ImportBag(r.Context(), req.Entries)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("import failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleAdminStats returns a compact dashboard snapshot for the admin view:
// subscriber counts, presence, active alarms and journal size/head.
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	ctx := r.Context()
	subs, err := s.st.ListSubscribers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list subscribers")
		return
	}
	active, revoked := 0, 0
	for _, sub := range subs {
		if sub.Revoked != 0 {
			revoked++
		} else {
			active++
		}
	}
	alerts, err := s.st.ListActiveAlerts(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "alerts")
		return
	}
	count, err := s.st.JournalCount(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "journal count")
		return
	}
	head, err := s.st.JournalHead(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "journal head")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subscribers":     len(subs),
		"active":          active,
		"revoked":         revoked,
		"online":          len(s.hub.Online()),
		"alerts":          len(alerts),
		"journal_entries": count,
		"journal_head":    head,
	})
}
