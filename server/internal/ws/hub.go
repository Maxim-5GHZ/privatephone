package ws

import (
	"context"
	"encoding/json"
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
	// revoked tracks callsigns on the CRL so delivery can skip them even before
	// their live connection is torn down (defense-in-depth: revoked subscribers
	// must never receive fresh ciphertext, even a frame already in flight).
	revoked map[string]struct{}
}

func NewHub(st *db.Store, ver *protocol.Verifier) *Hub {
	return &Hub{clients: make(map[*client]struct{}), st: st, ver: ver, revoked: make(map[string]struct{})}
}

// MarkRevoked updates the in-memory CRL roster used by deliver. The authoritative
// registry state lives in the store; this is an enforcement cache.
func (h *Hub) MarkRevoked(callsign string, revoked bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if revoked {
		h.revoked[callsign] = struct{}{}
	} else {
		delete(h.revoked, callsign)
	}
}

func (h *Hub) isRevoked(callsign string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.revoked[callsign]
	return ok
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

// pushBacklog replays the snapshot and undelivered store-and-forward packets to
// a client that just authenticated with hello.
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
