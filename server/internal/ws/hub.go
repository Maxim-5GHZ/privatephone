package ws

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
)

const (
	writeTimeout = 10 * time.Second
	readTimeout  = 90 * time.Second
	sendBuffer   = 256
	pingEvery    = 30 * time.Second
)

// Hub fans out signed, verified packets to connected clients and persists them
// to the store-and-forward journal. Delivery honours the recipient mode:
// "" broadcasts to everyone, a single callsign or a JSON array is direct/group.
type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
	st      *db.Store
	ver     *protocol.Verifier
}

func NewHub(st *db.Store, ver *protocol.Verifier) *Hub {
	return &Hub{clients: make(map[*client]struct{}), st: st, ver: ver}
}

// Handle upgrades an HTTP request to a client socket.
func (h *Hub) Handle(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusGoingAway, "bye")

	c := &client{hub: h, conn: conn, send: make(chan []byte, sendBuffer)}

	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
		h.broadcastPresence()
	}()

	go c.writePump()

	ctx := r.Context()
	pingTick := time.NewTicker(pingEvery)
	defer pingTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTick.C:
			pingCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		default:
			rctx, cancel := context.WithTimeout(ctx, readTimeout)
			_, data, err := conn.Read(rctx)
			cancel()
			if err != nil {
				return
			}
			h.dispatch(ctx, c, data)
		}
	}
}

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

// Online returns the currently connected subscribers (authenticated by hello).
func (h *Hub) Online() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	set := map[string]struct{}{}
	for c := range h.clients {
		if id := c.getID(); id != "" {
			set[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	return out
}

func (h *Hub) broadcastPresence() {
	online := h.Online()
	b, _ := json.Marshal(out{Kind: "presence", Data: map[string][]string{"online": online}})
	if b != nil {
		h.broadcast(b)
	}
}

func (h *Hub) pushBacklog(ctx context.Context, c *client) {
	me := c.getID()
	if me == "" {
		return
	}
	markers, err := h.st.ListMarkers(ctx)
	if err != nil {
		return
	}
	messages, err := h.st.ListMessagesFor(ctx, me)
	if err != nil {
		return
	}
	alerts, err := h.st.ListActiveAlerts(ctx)
	if err != nil {
		return
	}
	zones, err := h.st.ListZones(ctx)
	if err != nil {
		return
	}
	snap := outSnap{Kind: "snapshot", Data: Snapshot{Markers: markers, Messages: messages, Alerts: alerts, Zones: zones, Online: h.Online()}}
	if b, err := json.Marshal(snap); err == nil {
		c.enqueue(b)
	}
	undelivered, err := h.st.UndeliveredPacketsFor(ctx, me)
	if err != nil {
		return
	}
	if b, err := json.Marshal(outPackets{Kind: "packets", Data: packets{Items: undelivered}}); err == nil {
		c.enqueue(b)
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
	return string(probe.Enc), true
}

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
	var recips []string
	if len(m.To) > 0 && m.To[0] == '[' {
		_ = json.Unmarshal(m.To, &recips)
	}
	if len(recips) == 0 {
		var one string
		if json.Unmarshal(m.To, &one) == nil && one != "" {
			recips = []string{one}
		}
	}
	if len(recips) == 0 {
		return
	}
	b, _ := json.Marshal(f)
	if b != nil {
		h.deliver(b, recips, f.Sender)
	}
}

func (h *Hub) findClient(id string) *client {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		if c.getID() == id {
			return c
		}
	}
	return nil
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
// the recipient list is empty (broadcast).
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
		if len(recips) == 0 {
			c.tryEnqueue(b)
			continue
		}
		id := c.getID()
		if _, ok := to[id]; ok {
			c.tryEnqueue(b)
		}
	}
}

// journal stores the signed original packet for store-and-forward replay. The
// id is deterministic (sender|kind|nonce|ts) so re-imported bags deduplicate.
func (h *Hub) journal(ctx context.Context, f protocol.Frame, recipient string) {
	id := db.PacketID(f.Sender, f.Kind, f.Nonce, f.TS)
	if err := h.st.AddPacket(ctx, id, f.Sender, f.Kind, string(f.Data), f.Signature, f.Nonce, recipient, f.TS); err != nil &&
		!errors.Is(err, db.ErrDuplicate) {
		log.Printf("journal packet: %v", err)
	}
}

// Journal persists an already-verified packet into the tamper-evident journal
// (used by REST handlers, e.g. admin CRL commands).
func (h *Hub) Journal(ctx context.Context, f protocol.Frame, recipient string) {
	h.journal(ctx, f, recipient)
}

// ImportReport summarizes a journal bag import (sneaker-net).
type ImportReport struct {
	AddedJournal int    `json:"added_journal"`
	SkippedDup   int    `json:"skipped_duplicates"`
	SkippedCtx   int    `json:"skipped_context"`
	Rejected     bool   `json:"rejected"`
	RejectedAt   int    `json:"rejected_at"`
	RejectedWhy  string `json:"rejected_why"`
	Head         string `json:"head"`
}

// ImportBag replays an exported journal bag onto this node. The whole bag is
// validated before any write: it must continue the local chain (or be a full
// seed bag), its internal hash chain must be intact, and every packet's
// signature must verify against the local subscriber registry (identical
// operator keypairs are provisioned on every node). Bags that were already
// ingested are skipped idempotently via the deterministic packet id.
func (h *Hub) ImportBag(ctx context.Context, entries []db.JournalEntry) (ImportReport, error) {
	r := ImportReport{RejectedAt: -1}
	if len(entries) == 0 {
		head, _ := h.st.JournalHead(ctx)
		r.Head = head
		return r, nil
	}

	ex, err := h.st.PacketExists(ctx, entries[0].ID)
	if err != nil {
		return r, err
	}
	if ex {
		r.SkippedDup = len(entries)
		head, _ := h.st.JournalHead(ctx)
		r.Head = head
		return r, nil
	}

	head, err := h.st.JournalHead(ctx)
	if err != nil {
		return r, err
	}
	if head != entries[0].PrevHash {
		r.Rejected, r.RejectedAt, r.RejectedWhy = true, 0,
			"bag does not continue this node's journal chain (local head differs); import into an empty node or the immediate successor of the previous bag"
		return r, nil
	}
	if bad := db.VerifyBag(entries); bad >= 0 {
		r.Rejected, r.RejectedAt, r.RejectedWhy = true, bad, "bag internal hash chain is broken at this index"
		return r, nil
	}

	// Signature check against local pubkeys. Revoked callers still verify their
	// pre-revocation packets, so an imported CRL bag converges cleanly.
	ver := &protocol.Verifier{Subs: func(ctx context.Context, callsign string) (string, string, error) {
		sub, err := h.st.SubscriberByCallsign(ctx, callsign)
		if err != nil {
			return "", "", err
		}
		return sub.PubKey, sub.Role, nil
	}}
	for i, e := range entries {
		f := entryFrame(e)
		if _, err := ver.VerifyStored(ctx, f.Envelope()); err != nil {
			r.Rejected, r.RejectedAt, r.RejectedWhy = true, i,
				"signature does not verify against the local registry: "+err.Error()
			return r, nil
		}
	}

	for i, e := range entries {
		role, _ := ver.Role(ctx, e.Sender)
		appended, ctxSkipped, err := h.replayImport(ctx, e, role)
		if err != nil {
			log.Printf("import row %d (%s by %s): %v", i, e.Kind, e.Sender, err)
		}
		if appended {
			r.AddedJournal++
		}
		if ctxSkipped {
			r.SkippedCtx++
		}
	}
	head, _ = h.st.JournalHead(ctx)
	r.Head = head
	return r, nil
}

// entryFrame rebuilds the original signed frame from a stored journal row.
func entryFrame(e db.JournalEntry) protocol.Frame {
	return protocol.Frame{
		Sender:    e.Sender,
		TS:        e.TS,
		Nonce:     e.Nonce,
		Kind:      e.Kind,
		Signature: e.Signature,
		Data:      json.RawMessage(e.Payload),
	}
}

// replayImport applies one journal row's side effects (locations, messages,
// alarms, zones, CRL) and appends the audit row. appended reports whether the
// row entered the local journal; ctxSkipped reports a side effect that could
// not be applied because its target object is absent locally (the row itself is
// still journaled, so the audit trail converges completely).
func (h *Hub) replayImport(ctx context.Context, e db.JournalEntry, role string) (appended, ctxSkipped bool, err error) {
	f := entryFrame(e)
	switch e.Kind {
	case "marker":
		_, err = h.IngestMarker(ctx, f)
	case "marker_update":
		_, err = h.IngestMarkerUpdate(ctx, f)
	case "marker_delete":
		err = h.IngestMarkerDelete(ctx, f, role)
	case "message":
		_, err = h.IngestMessage(ctx, f)
	case "alert":
		_, err = h.IngestAlert(ctx, f)
	case "alert_ack":
		_, err = h.IngestAlertAck(ctx, f)
	case "alert_clear":
		_, err = h.IngestAlertClear(ctx, f, role)
	case "zone":
		_, err = h.IngestZone(ctx, f)
	case "zone_update":
		_, err = h.IngestZoneUpdate(ctx, f)
	case "zone_delete":
		err = h.IngestZoneDelete(ctx, f, role)
	case "revoke_subscriber", "unrevoke_subscriber":
		err = h.replayRevoke(ctx, f, role)
		return err == nil, false, err
	default:
		h.journal(ctx, f, e.Recipient)
		return true, false, nil
	}
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			h.journal(ctx, f, e.Recipient)
			return true, true, nil
		}
		return false, false, err
	}
	return true, false, nil
}

// replayRevoke applies a CRL entry to the local subscriber registry and keeps
// the audit row. A target that is unknown on this node causes no side effect,
// but the row is still journaled so chains stay identical across nodes.
func (h *Hub) replayRevoke(ctx context.Context, f protocol.Frame, role string) error {
	if role != "admin" {
		return errors.New("revoke/unrevoke requires an admin signer")
	}
	var m struct {
		Callsign string `json:"callsign"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil || m.Callsign == "" {
		return errors.New("revoke/unrevoke entry: callsign required")
	}
	apply := h.st.RevokeSubscriber
	if f.Kind == "unrevoke_subscriber" {
		apply = h.st.UnrevokeSubscriber
	}
	if err := apply(ctx, m.Callsign); err != nil && !errors.Is(err, db.ErrNotFound) {
		return err
	}
	h.journal(ctx, f, "@system")
	return nil
}

// Kick forces any live connection of a callsign to close and refreshes the
// presence roster (CRL enforcement for already-connected clients).
func (h *Hub) Kick(callsign string) {
	c := h.findClient(callsign)
	if c == nil {
		return
	}
	_ = c.conn.Close(websocket.StatusPolicyViolation, "revoked")
}

func (h *Hub) broadcast(b []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		c.tryEnqueue(b)
	}
}

func (h *Hub) broadcastJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.broadcast(b)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
