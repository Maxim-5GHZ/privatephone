package ws

import (
	"context"
	"encoding/json"

	"privatephone/server/internal/protocol"
)

// relayCall routes WebRTC signaling frames only to the addressed subscriber.
func (h *Hub) relayCall(ctx context.Context, c *client, f protocol.Frame) {
	var m struct {
		To string `json:"to"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil || m.To == "" {
		return
	}
	target := h.findClient(m.To)
	if target == nil {
		reply, _ := json.Marshal(out{Kind: "call_error", Data: map[string]string{"to": m.To, "error": "offline"}})
		if reply != nil {
			c.enqueue(reply)
		}
		return
	}
	// forward the exact signed frame the remote peer will verify itself
	b, _ := json.Marshal(f)
	if b != nil {
		target.enqueue(b)
	}
}

// relayPTT routes push-to-talk conference signaling to one or more members
// (`to` is a single callsign or a JSON array). Sessions are ephemeral: frames
// are forwarded unjournaled, like regular call signaling.
func (h *Hub) relayPTT(ctx context.Context, c *client, f protocol.Frame) {
	var m struct {
		To json.RawMessage `json:"to"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil || len(m.To) == 0 {
		return
	}
	recips := relayRecipients(m.To)
	if len(recips) == 0 {
		return
	}
	b, _ := json.Marshal(f)
	if b != nil {
		h.deliver(b, recips, f.Sender)
	}
}

// relayRecipients expands a `to` field that is either a single callsign or a
// JSON array of callsigns into the recipient list.
func relayRecipients(to json.RawMessage) []string {
	if len(to) == 0 {
		return nil
	}
	if to[0] == '[' {
		var list []string
		_ = json.Unmarshal(to, &list)
		return list
	}
	var one string
	if json.Unmarshal(to, &one) != nil || one == "" {
		return nil
	}
	return []string{one}
}

// parseRecipients turns the recipient field into a set of callsigns. "" or nil
// means broadcast to everyone.
func parseRecipients(s string) []string {
	if s == "" {
		return nil
	}
	if s[0] == '[' {
		var list []string
		if json.Unmarshal([]byte(s), &list) == nil {
			return list
		}
	}
	return []string{s}
}

// deliver pushes b only to addressed clients (plus the author) or to all when
// the recipient list is empty (broadcast). Revoked callsigns are skipped in
// both modes — defense-in-depth so CRL'd subscribers never receive fresh
// ciphertext, even a frame already in flight on a live connection.
func (h *Hub) deliver(b []byte, recips []string, author string) {
	to := map[string]struct{}{author: {}}
	if len(recips) > 0 {
		for _, r := range recips {
			to[r] = struct{}{}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		id := c.getID()
		if _, rev := h.revoked[id]; rev {
			continue
		}
		if len(recips) == 0 {
			c.tryEnqueue(b)
			continue
		}
		if _, ok := to[id]; ok {
			c.tryEnqueue(b)
		}
	}
}
