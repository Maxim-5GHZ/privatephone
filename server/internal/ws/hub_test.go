package ws

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
)

func newTestHub(t *testing.T) (*Hub, *db.Store, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	bobPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	charliePriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bobPubPEM, _ := crypto.PublicKeyToPEM(&bobPriv.PublicKey)
	charliePubPEM, _ := crypto.PublicKeyToPEM(&charliePriv.PublicKey)

	st, err := db.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(ctx) })
	if err := st.AddSubscriber(ctx, "id1", "bob", "operator", string(bobPubPEM)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddSubscriber(ctx, "id2", "charlie", "operator", string(charliePubPEM)); err != nil {
		t.Fatal(err)
	}

	ver := &protocol.Verifier{
		Guard: crypto.NewReplayGuard(10000),
		Subs: func(ctx context.Context, callsign string) (string, string, error) {
			sub, err := st.SubscriberByCallsign(ctx, callsign)
			if err != nil {
				return "", "", err
			}
			if sub.Revoked != 0 {
				return "", "", protocol.ErrRevoked
			}
			return sub.PubKey, sub.Role, nil
		},
	}
	return NewHub(st, ver), st, bobPriv, charliePriv
}

func signedFrame(t *testing.T, priv *ecdsa.PrivateKey, callsign, kind string, data any) []byte {
	t.Helper()
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := crypto.NewID()
	ts := time.Now().Unix()
	sig, err := crypto.Sign(priv, crypto.Canonical(kind, callsign, nonce, ts, body))
	if err != nil {
		t.Fatal(err)
	}
	f := protocol.Frame{Sender: callsign, TS: ts, Nonce: nonce, Kind: kind, Signature: sig, Data: body}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func attachHubClient(t *testing.T, h *Hub, id string) *client {
	t.Helper()
	c := &client{hub: h, send: make(chan []byte, 64)}
	c.setID(id)
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	t.Cleanup(func() { c.close() })
	return c
}

func drainFrame(t *testing.T, c *client) string {
	t.Helper()
	select {
	case b, ok := <-c.send:
		if !ok {
			return ""
		}
		return string(b)
	case <-time.After(1 * time.Second):
		t.Fatal("expected a queued frame")
		return ""
	}
}

func TestDispatchAllKinds(t *testing.T) {
	ctx := context.Background()
	h, st, bob, _ := newTestHub(t)

	bobC := attachHubClient(t, h, "")
	charlieC := attachHubClient(t, h, "charlie")
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "hello", map[string]any{}))
	if bobC.getID() != "bob" {
		t.Fatal("hello must register the caller's id")
	}

	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "marker", map[string]any{"lat": 55.1, "lon": 37.2, "type": "own", "n": "mk1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "marker_update", map[string]any{"n": "mk1", "type": "own", "desc": "обновлённая"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "marker_delete", map[string]any{"n": "mk1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "message", map[string]any{"recipient": "charlie", "body": "привет", "n": "m1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "ack", map[string]any{"ids": []string{"nope"}}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "alert", map[string]any{"type": "sos", "text": "Помогите", "n": "a1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "alert_ack", map[string]any{"author": "bob", "n": "a1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "alert_clear", map[string]any{"author": "bob", "n": "a1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "zone", map[string]any{"name": "Зона", "color": "#f00", "points": [][2]float64{{0, 0}, {1, 1}, {2, 0}}, "n": "z1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "zone_update", map[string]any{"n": "z1", "name": "Прострел 2"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "zone_delete", map[string]any{"n": "z1"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "call_invite", map[string]any{"to": "charlie"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "call_invite", map[string]any{"to": "ghost"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "ptt_start", map[string]any{"to": "charlie"}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "ptt_talking", map[string]any{"to": []string{"charlie"}}))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "ptt_end", map[string]any{"to": []string{"ghost"}}))
	h.dispatch(ctx, bobC, []byte(`{"sender":"bob","kind":"unknown_kind"}`))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "bob", "alert", map[string]any{"type": "weird", "n": "bad"}))

	seen := map[string]bool{}
	for i := 0; i < 14; i++ {
		frame := drainFrame(t, bobC)
		for _, kind := range []string{"presence", "snapshot", "packets", "marker", "marker_updated", "marker_deleted", "alert", "alert_acks", "alert_cleared", "zone", "zone_updated", "zone_deleted", "call_error"} {
			if strings.Contains(frame, `"kind":"`+kind+`"`) {
				seen[kind] = true
			}
		}
	}
	for _, want := range []string{"presence", "snapshot", "packets", "marker", "marker_updated", "marker_deleted", "alert", "alert_acks", "alert_cleared", "zone", "zone_updated", "zone_deleted", "call_error"} {
		if !seen[want] {
			t.Fatalf("bob never received kind %q; got %v", want, seen)
		}
	}

	charlieSeen := map[string]bool{}
	for i := 0; i < 14; i++ {
		frame := drainFrame(t, charlieC)
		for _, kind := range []string{"presence", "marker", "marker_updated", "marker_deleted", "message", "alert", "alert_acks", "alert_cleared", "zone", "zone_updated", "zone_deleted", "call_invite", "ptt_start", "ptt_talking"} {
			if strings.Contains(frame, `"kind":"`+kind+`"`) {
				charlieSeen[kind] = true
			}
		}
	}
	for _, want := range []string{"message", "call_invite", "ptt_start", "ptt_talking"} {
		if !charlieSeen[want] {
			t.Fatalf("charlie never received kind %q; got %v", want, charlieSeen)
		}
	}

	mk, err := st.MarkerByNonce(ctx, "bob", "mk1")
	if err != nil || mk == nil {
		t.Fatalf("marker must be ingested and updated then deleted: %v", err)
	}
	if _, err := st.ZoneByNonce(ctx, "bob", "z1"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("zone must be deactivated after zone_delete, got %v", err)
	}
}

func TestDispatchRejectsMalformedAndImpostors(t *testing.T) {
	h, _, bob, _ := newTestHub(t)
	ctx := context.Background()
	bobC := attachHubClient(t, h, "")
	h.dispatch(ctx, bobC, []byte(`this is not json`))
	h.dispatch(ctx, bobC, signedFrame(t, bob, "zorp", "marker", map[string]any{"lat": 0, "lon": 0}))
	f := signedFrame(t, bob, "bob", "marker", map[string]any{"lat": 0, "lon": 0})
	h.dispatch(ctx, bobC, f[:len(f)-4])
	if bobC.getID() != "" {
		t.Fatal("malformed and impostor frames must be dropped before identity is set")
	}
	if _, err := h.st.MarkerByNonce(ctx, "bob", ""); err == nil {
		t.Fatal("no marker may be persisted")
	}
}

func TestClientDropOnFullBuffer(t *testing.T) {
	h, _, _, _ := newTestHub(t)

	c := &client{hub: h, send: make(chan []byte, 1)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	t.Cleanup(func() { c.close() })

	h.deliver([]byte(`{"kind":"a"}`), nil, "x")
	if c.dead {
		t.Fatal("first broadcast with free buffer must not close the client")
	}
	_ = drainFrame(t, c)

	c.send <- []byte(`{"kind":"b"}`)
	h.deliver([]byte(`{"kind":"c"}`), nil, "x")
	if !c.dead {
		t.Fatal("full buffer must drop the client")
	}
	if got, ok := <-c.send; !ok || !strings.Contains(string(got), `"kind":"b"`) {
		t.Fatalf("queued frame must drain first, ok=%v got=%s", ok, got)
	}
	if got, ok := <-c.send; ok {
		t.Fatalf("send channel must be closed after drop, got %s", got)
	}
	c.close()
	c.close()

	fresh := &client{hub: h, send: make(chan []byte, 1)}
	h.mu.Lock()
	h.clients[fresh] = struct{}{}
	h.mu.Unlock()
	fresh.enqueue([]byte(`{"kind":"d"}`))
	if len(fresh.send) != 1 {
		t.Fatal("enqueue must deliver to a roomy buffer")
	}
	_ = drainFrame(t, fresh)
}
