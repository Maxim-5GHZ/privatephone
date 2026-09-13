package ws

import (
	"context"
	"encoding/json"
	"errors"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
)

// IngestMarker validates and persists a geo marker, journals it and pushes it
// to all connected clients (markers are shared situation awareness). E2EE cargo
// replaces the parsed fields with an opaque envelope; positional data is then
// only recoverable by subscribers who decrypt it.
func (h *Hub) IngestMarker(ctx context.Context, f protocol.Frame) (db.Marker, error) {
	var m struct {
		Lat  float64         `json:"lat"`
		Lon  float64         `json:"lon"`
		Type string          `json:"type"`
		Desc string          `json:"desc"`
		N    string          `json:"n"`
		Enc  json.RawMessage `json:"enc"`
	}
	var rec db.Marker
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	lat, lon, mtype, desc := m.Lat, m.Lon, m.Type, m.Desc
	if enc, ok := encCargo(f.Data); ok {
		lat, lon, mtype, desc = 0, 0, "enc", enc
	} else if mtype == "" {
		mtype = "other"
	}
	id, err := h.st.AddMarker(ctx, f.Sender, lat, lon, mtype, desc, m.N)
	if err != nil {
		return rec, err
	}
	rec = db.Marker{ID: id, Sender: f.Sender, Lat: lat, Lon: lon, Type: mtype, Descr: desc, Nonce: m.N, Created: now()}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "marker", Data: rec})
	return rec, nil
}

// IngestMarkerUpdate edits type/description of a marker the sender authored.
// E2EE updates carry the full new content (lat/lon/type/desc) encrypted so the
// node never merges patches it cannot read.
func (h *Hub) IngestMarkerUpdate(ctx context.Context, f protocol.Frame) (db.Marker, error) {
	var m struct {
		N    string          `json:"n"`
		Type string          `json:"type"`
		Desc string          `json:"desc"`
		Enc  json.RawMessage `json:"enc"`
	}
	var rec db.Marker
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	cur, err := h.st.MarkerByNonce(ctx, f.Sender, m.N)
	if err != nil {
		return rec, err
	}
	mtype, desc := m.Type, m.Desc
	if enc, ok := encCargo(f.Data); ok {
		mtype, desc = "enc", enc
	} else if mtype == "" {
		mtype = cur.Type
	}
	if err := h.st.UpdateMarkerText(ctx, cur.ID, mtype, desc); err != nil {
		return rec, err
	}
	rec = db.Marker{ID: cur.ID, Sender: cur.Sender, Lat: cur.Lat, Lon: cur.Lon, Type: mtype, Descr: desc, Nonce: cur.Nonce, Created: cur.Created}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "marker_updated", Data: rec})
	return rec, nil
}

// IngestMarkerDelete removes a marker (author or admin). Markers are addressed
// by the original signed nonce so both snapshot- and backlog-sourced copies match.
func (h *Hub) IngestMarkerDelete(ctx context.Context, f protocol.Frame, role string) error {
	var m struct {
		N string `json:"n"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return err
	}
	cur, err := h.st.MarkerByNonce(ctx, f.Sender, m.N)
	if err != nil {
		return err
	}
	if cur.Sender != f.Sender && role != "admin" {
		return errors.New("not the author")
	}
	if err := h.st.DeactivateMarker(ctx, cur.ID); err != nil {
		return err
	}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "marker_deleted", Data: map[string]any{"sender": cur.Sender, "n": cur.Nonce, "id": cur.ID}})
	return nil
}

// IngestMessage validates and persists a text message, then routes it to the
// addressed recipients ("" = broadcast). E2EE bodies are carried as an opaque
// envelope in place of the plaintext text; routing fields stay readable.
func (h *Hub) IngestMessage(ctx context.Context, f protocol.Frame) (db.Message, error) {
	var m struct {
		Recipient string          `json:"recipient"`
		Body      string          `json:"body"`
		N         string          `json:"n"`
		Enc       json.RawMessage `json:"enc"`
	}
	var rec db.Message
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	body := m.Body
	if enc, ok := encCargo(f.Data); ok {
		body = enc
	}
	id, err := h.st.AddMessage(ctx, f.Sender, m.Recipient, body, m.N)
	if err != nil {
		return rec, err
	}
	rec = db.Message{ID: id, Sender: f.Sender, Recipient: m.Recipient, Body: body, Nonce: m.N, Created: now()}
	h.journal(ctx, f, m.Recipient)
	b, _ := json.Marshal(out{Kind: "message", Data: rec})
	h.deliver(b, parseRecipients(m.Recipient), f.Sender)
	return rec, nil
}

func (h *Hub) handleAck(ctx context.Context, f protocol.Frame) {
	var a struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(f.Data, &a); err != nil {
		return
	}
	_ = h.st.MarkDelivered(ctx, a.IDs)
}

var alertTypes = map[string]bool{"sos": true, "gather": true, "info": true}

// IngestAlert creates and broadcasts an engagement alarm. Alerts are broadcast
// (recipient "") so they replay from the backlog to late joiners. E2EE cargo
// skips the type whitelist — the banner type is recovered client-side.
func (h *Hub) IngestAlert(ctx context.Context, f protocol.Frame) (db.Alert, error) {
	var m struct {
		Type string          `json:"type"`
		Text string          `json:"text"`
		Lat  float64         `json:"lat"`
		Lon  float64         `json:"lon"`
		N    string          `json:"n"`
		Enc  json.RawMessage `json:"enc"`
	}
	var rec db.Alert
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	atype, atext := m.Type, m.Text
	if enc, ok := encCargo(f.Data); ok {
		atype, atext = "enc", enc
	} else if !alertTypes[m.Type] {
		return rec, errors.New("unknown alert type")
	}
	id, err := h.st.AddAlert(ctx, f.Sender, atype, atext, m.Lat, m.Lon, m.N)
	if err != nil {
		return rec, err
	}
	rec = db.Alert{ID: id, Sender: f.Sender, Type: atype, Text: atext, Lat: m.Lat, Lon: m.Lon, Nonce: m.N, Created: now(), Acks: []string{}}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "alert", Data: rec})
	return rec, nil
}

// IngestAlertAck records an acknowledgment of the alert identified by its
// author + original nonce. Acks only live in the tally (snapshot), the packet
// itself is journaled for audit with recipient "@system" (no backlog replay).
func (h *Hub) IngestAlertAck(ctx context.Context, f protocol.Frame) (map[string]any, error) {
	var m struct {
		Sender string `json:"author"`
		N      string `json:"n"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return nil, err
	}
	cur, err := h.st.AlertByNonce(ctx, m.Sender, m.N)
	if err != nil {
		return nil, err
	}
	if err := h.st.AckAlert(ctx, cur.ID, f.Sender); err != nil {
		return nil, err
	}
	h.journal(ctx, f, "@system")
	return map[string]any{"id": cur.ID, "author": cur.Sender, "n": cur.Nonce, "sender": f.Sender}, nil
}

// IngestAlertClear deactivates an alarm (author or admin).
func (h *Hub) IngestAlertClear(ctx context.Context, f protocol.Frame, role string) (map[string]any, error) {
	var m struct {
		Sender string `json:"author"`
		N      string `json:"n"`
	}
	var rec map[string]any
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return nil, err
	}
	cur, err := h.st.AlertByNonce(ctx, m.Sender, m.N)
	if err != nil {
		return nil, err
	}
	if cur.Sender != f.Sender && role != "admin" {
		return nil, errors.New("not the author")
	}
	if err := h.st.ClearAlert(ctx, cur.ID, f.Sender); err != nil {
		return nil, err
	}
	h.journal(ctx, f, "")
	rec = map[string]any{"id": cur.ID, "author": cur.Sender, "n": cur.Nonce, "by": f.Sender}
	return rec, nil
}

// IngestZone persists and broadcasts a shared polygon (recipient "" like
// markers). E2EE cargo skips the minimum-points check — the polygon geometry is
// recovered client-side from the encrypted envelope.
func (h *Hub) IngestZone(ctx context.Context, f protocol.Frame) (db.Zone, error) {
	var m struct {
		Name   string          `json:"name"`
		Color  string          `json:"color"`
		Points [][2]float64    `json:"points"`
		N      string          `json:"n"`
		Enc    json.RawMessage `json:"enc"`
	}
	var rec db.Zone
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	name, color, points := m.Name, m.Color, ""
	if enc, ok := encCargo(f.Data); ok {
		name, color, points = "enc", "enc", enc
	} else {
		if len(m.Points) < 3 {
			return rec, errors.New("zone needs at least 3 points")
		}
		if name == "" {
			name = "Зона"
		}
		if color == "" {
			color = "#ff3b30"
		}
		raw, err := json.Marshal(m.Points)
		if err != nil {
			return rec, err
		}
		points = string(raw)
	}
	id, err := h.st.AddZone(ctx, f.Sender, name, color, points, m.N)
	if err != nil {
		return rec, err
	}
	rec = db.Zone{ID: id, Sender: f.Sender, Name: name, Color: color, Points: points, Nonce: m.N, Created: now()}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "zone", Data: rec})
	return rec, nil
}

// IngestZoneUpdate renames/recolours a zone the sender authored. E2EE updates
// carry the full polygon content encrypted; geometry comes from the envelope.
func (h *Hub) IngestZoneUpdate(ctx context.Context, f protocol.Frame) (db.Zone, error) {
	var m struct {
		Name  string          `json:"name"`
		Color string          `json:"color"`
		N     string          `json:"n"`
		Enc   json.RawMessage `json:"enc"`
	}
	var rec db.Zone
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	cur, err := h.st.ZoneByNonce(ctx, f.Sender, m.N)
	if err != nil {
		return rec, err
	}
	if cur.Sender != f.Sender {
		return rec, errors.New("not the author")
	}
	name, color := m.Name, m.Color
	if _, ok := encCargo(f.Data); ok {
		name, color = "enc", "enc"
	} else {
		if name == "" {
			name = cur.Name
		}
		if color == "" {
			color = cur.Color
		}
	}
	if err := h.st.UpdateZoneText(ctx, cur.ID, name, color); err != nil {
		return rec, err
	}
	rec = db.Zone{ID: cur.ID, Sender: cur.Sender, Name: name, Color: color, Points: cur.Points, Nonce: cur.Nonce, Created: cur.Created}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "zone_updated", Data: rec})
	return rec, nil
}

// IngestZoneDelete deactivates a polygon (author or admin), addressed by nonce.
func (h *Hub) IngestZoneDelete(ctx context.Context, f protocol.Frame, role string) error {
	var m struct {
		N string `json:"n"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return err
	}
	cur, err := h.st.ZoneByNonce(ctx, f.Sender, m.N)
	if err != nil {
		return err
	}
	if cur.Sender != f.Sender && role != "admin" {
		return errors.New("not the author")
	}
	if err := h.st.DeactivateZone(ctx, cur.ID); err != nil {
		return err
	}
	h.journal(ctx, f, "")
	h.broadcastJSON(out{Kind: "zone_deleted", Data: map[string]any{"sender": cur.Sender, "n": cur.Nonce, "id": cur.ID}})
	return nil
}
