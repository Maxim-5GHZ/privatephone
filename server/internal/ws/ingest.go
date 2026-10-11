package ws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

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
// The target marker is addressed by `target` (the nonce stored at creation);
// `n` is accepted as a fallback for plaintext clients. A separate field is
// required because E2EE updates arrive in a fresh envelope whose own `n` is
// new — looking the marker up by it would always miss.
// E2EE updates carry the full new content (lat/lon/type/desc) encrypted so the
// node never merges patches it cannot read.
func (h *Hub) IngestMarkerUpdate(ctx context.Context, f protocol.Frame) (db.Marker, error) {
	var m struct {
		Target string          `json:"target"`
		N      string          `json:"n"`
		Type   string          `json:"type"`
		Desc   string          `json:"desc"`
		Enc    json.RawMessage `json:"enc"`
	}
	var rec db.Marker
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	nonce := m.Target
	if nonce == "" {
		nonce = m.N
	}
	cur, err := h.st.MarkerByNonce(ctx, f.Sender, nonce)
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
// addressed recipients ("" = broadcast, "chat:<id>" = named chat members).
// E2EE bodies are carried as an opaque envelope in place of the plaintext
// text; routing fields stay readable.
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
	// named chats: sender must be a member, delivery expands to members.
	if len(m.Recipient) > 5 && m.Recipient[:5] == "chat:" {
		ok, err := h.isChatMember(ctx, f.Sender, m.Recipient)
		if err != nil || !ok {
			if err == nil {
				err = errors.New("not a chat member")
			}
			return rec, err
		}
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
	recips, _ := h.expandMessageRecipients(ctx, m.Recipient)
	h.deliver(b, recips, f.Sender)
	return rec, nil
}

func (h *Hub) handleAck(ctx context.Context, f protocol.Frame) {
	var a struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(f.Data, &a); err != nil {
		return
	}
	_ = h.st.MarkDelivered(ctx, a.IDs, f.Sender)
}

// IngestMessageUpdate replaces the body of a message the sender authored.
// The target message is addressed by `target` (the nonce stored at creation);
// `n` is a fallback for plaintext clients. E2EE updates carry the new body as
// an opaque envelope, exactly like IngestMessage.
func (h *Hub) IngestMessageUpdate(ctx context.Context, f protocol.Frame) (db.Message, error) {
	var m struct {
		Target string          `json:"target"`
		Body   string          `json:"body"`
		N      string          `json:"n"`
		Enc    json.RawMessage `json:"enc"`
	}
	var rec db.Message
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	tn := m.Target
	if tn == "" {
		tn = m.N
	}
	cur, err := h.st.MessageByNonce(ctx, f.Sender, tn)
	if err != nil {
		return rec, err
	}
	body := m.Body
	if enc, ok := encCargo(f.Data); ok {
		body = enc
	}
	if body == "" {
		return rec, errors.New("empty body")
	}
	if err := h.st.UpdateMessageBody(ctx, cur.ID, body); err != nil {
		return rec, err
	}
	rec = cur
	rec.Body = body
	rec.Edited = 1
	h.journal(ctx, f, cur.Recipient)
	b, _ := json.Marshal(out{Kind: "message_updated", Data: rec})
	recips, _ := h.expandMessageRecipients(ctx, cur.Recipient)
	h.deliver(b, recips, f.Sender)
	return rec, nil
}

// IngestMessageDelete removes a message (author or admin). The signed delete
// packet stays in the journal for audit, like marker deletes.
func (h *Hub) IngestMessageDelete(ctx context.Context, f protocol.Frame, role string) error {
	var m struct {
		Target string `json:"target"`
		N      string `json:"n"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return err
	}
	tn := m.Target
	if tn == "" {
		tn = m.N
	}
	cur, err := h.st.MessageByNonce(ctx, f.Sender, tn)
	if err != nil {
		return err
	}
	if cur.Sender != f.Sender && role != "admin" {
		return errors.New("not the author")
	}
	if err := h.st.DeleteMessage(ctx, cur.ID); err != nil {
		return err
	}
	h.journal(ctx, f, cur.Recipient)
	h.broadcastJSON(out{Kind: "message_deleted", Data: map[string]any{"sender": cur.Sender, "n": cur.Nonce, "id": cur.ID}})
	return nil
}

// fileBlobMaxBytes caps one E2EE file (decoded ciphertext): photos and voice
// notes fit, the journal stays replicable over sneaker-net.
const fileBlobMaxBytes = 8 << 20 // 8 MiB

// IngestFile stores one E2EE file/voice attachment opaque (blob + key
// envelope) and routes it like a message ("" = broadcast, callsign / JSON
// array / "chat:<id>" = addressed). Plaintext metadata (name/mime/size) is
// validated; the bytes themselves are never inspected.
func (h *Hub) IngestFile(ctx context.Context, f protocol.Frame) (db.File, error) {
	var m struct {
		Recipient string          `json:"recipient"`
		Name      string          `json:"name"`
		Mime      string          `json:"mime"`
		Size      int64           `json:"size"`
		Blob      string          `json:"blob"`
		N         string          `json:"n"`
		Enc       json.RawMessage `json:"enc"`
	}
	var rec db.File
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	if len(m.Recipient) > 5 && m.Recipient[:5] == "chat:" {
		ok, err := h.isChatMember(ctx, f.Sender, m.Recipient)
		if err != nil || !ok {
			if err == nil {
				err = errors.New("not a chat member")
			}
			return rec, err
		}
	}
	enc, ok := encCargo(f.Data)
	if !ok {
		return rec, errors.New("file must carry E2EE envelope")
	}
	if m.Blob == "" {
		return rec, errors.New("empty file")
	}
	if int64(len(m.Blob)) > fileBlobMaxBytes*4/3+4096 {
		return rec, errors.New("file too large")
	}
	name := m.Name
	if name == "" {
		name = "файл"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	mime := m.Mime
	if mime == "" {
		mime = "application/octet-stream"
	}
	if len(mime) > 64 || !strings.Contains(mime, "/") {
		return rec, errors.New("bad mime")
	}
	id, err := h.st.AddFile(ctx, f.Sender, m.Recipient, name, mime, m.Size, m.Blob, enc, m.N)
	if err != nil {
		return rec, err
	}
	rec = db.File{ID: id, Sender: f.Sender, Recipient: m.Recipient, Name: name, Mime: mime, Size: m.Size, Blob: m.Blob, Enc: enc, Nonce: m.N, Created: now()}
	h.journal(ctx, f, m.Recipient)
	b, _ := json.Marshal(out{Kind: "file", Data: rec})
	recips, _ := h.expandMessageRecipients(ctx, m.Recipient)
	h.deliver(b, recips, f.Sender)
	return rec, nil
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

// IngestZoneUpdate renames/recolours a zone the sender authored. The target
// zone is addressed by `target` (nonce from creation), `n` is a fallback for
// plaintext clients — same fresh-envelope reason as IngestMarkerUpdate.
// E2EE updates carry the full polygon content encrypted; geometry comes from
// the envelope.
func (h *Hub) IngestZoneUpdate(ctx context.Context, f protocol.Frame) (db.Zone, error) {
	var m struct {
		Name   string          `json:"name"`
		Color  string          `json:"color"`
		Target string          `json:"target"`
		N      string          `json:"n"`
		Enc    json.RawMessage `json:"enc"`
	}
	var rec db.Zone
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	nonce := m.Target
	if nonce == "" {
		nonce = m.N
	}
	cur, err := h.st.ZoneByNonce(ctx, f.Sender, nonce)
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
