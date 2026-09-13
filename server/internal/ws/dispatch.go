package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"log"

	"privatephone/server/internal/protocol"
)

// dispatch verifies a frame and routes it to the matching ingest/relay path.
// Frames that fail verification are dropped here — nothing is persisted and no
// nonce is consumed, so unauthenticated junk cannot pollute the journal or the
// replay cache (verified packets hit the guard inside protocol.Verifier).
func (h *Hub) dispatch(ctx context.Context, c *client, data []byte) {
	var f protocol.Frame
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	role, err := h.ver.Verify(ctx, f.Envelope())
	if err != nil {
		log.Printf("ws: dropping packet from %q: %v", f.Sender, err)
		return
	}
	switch f.Kind {
	case "hello":
		c.setID(f.Sender)
		h.pushBacklog(ctx, c)
		h.broadcastPresence()
	case "marker":
		if _, err := h.IngestMarker(ctx, f); err != nil {
			log.Printf("ws: marker: %v", err)
		}
	case "marker_update":
		if _, err := h.IngestMarkerUpdate(ctx, f); err != nil {
			log.Printf("ws: marker_update: %v", err)
		}
	case "marker_delete":
		if err := h.IngestMarkerDelete(ctx, f, role); err != nil {
			log.Printf("ws: marker_delete: %v", err)
		}
	case "message":
		if _, err := h.IngestMessage(ctx, f); err != nil {
			log.Printf("ws: message: %v", err)
		}
	case "ack":
		h.handleAck(ctx, f)
	case "alert":
		if _, err := h.IngestAlert(ctx, f); err != nil {
			log.Printf("ws: alert: %v", err)
		}
	case "alert_ack":
		if rec, err := h.IngestAlertAck(ctx, f); err != nil {
			log.Printf("ws: alert_ack: %v", err)
		} else {
			h.broadcastJSON(out{Kind: "alert_acks", Data: rec})
		}
	case "alert_clear":
		if rec, err := h.IngestAlertClear(ctx, f, role); err != nil {
			log.Printf("ws: alert_clear: %v", err)
		} else {
			h.broadcastJSON(out{Kind: "alert_cleared", Data: rec})
		}
	case "zone":
		if _, err := h.IngestZone(ctx, f); err != nil {
			log.Printf("ws: zone: %v", err)
		}
	case "zone_update":
		if _, err := h.IngestZoneUpdate(ctx, f); err != nil {
			log.Printf("ws: zone_update: %v", err)
		}
	case "zone_delete":
		if err := h.IngestZoneDelete(ctx, f, role); err != nil {
			log.Printf("ws: zone_delete: %v", err)
		}
	case "call_invite", "call_accept", "call_reject", "call_bye", "ice":
		h.relayCall(ctx, c, f)
	case "ptt_start", "ptt_end", "ptt_talking", "ptt_offer", "ptt_answer", "ptt_ice":
		h.relayPTT(ctx, c, f)
	}
}

// encCargo tells whether a packet carries E2EE cargo and returns the envelope
// JSON as found in the "enc" field. The node never inspects the ciphertext — it
// stores and relays the envelope opaque, so markers, alerts, zones and message
// bodies are end-to-end encrypted while the journal stays tamper-evident.
func encCargo(data json.RawMessage) (string, bool) {
	var probe struct {
		Enc json.RawMessage `json:"enc"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || len(probe.Enc) == 0 {
		return "", false
	}
	if s := string(bytes.TrimSpace(probe.Enc)); s == "" || s == "null" || s == `""` {
		return "", false
	}
	return string(probe.Enc), true
}
