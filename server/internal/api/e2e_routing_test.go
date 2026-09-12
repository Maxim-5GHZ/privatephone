package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"privatephone/server/internal/ca"
	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
)

// signAs builds a canonical packet signed with a specific subscriber's private
// key (not just the admin key from the test context).
func signAs(t *testing.T, callsign, privPEM, kind string, data any) *signed {
	t.Helper()
	priv, err := crypto.ParsePrivateKeyPEM([]byte(privPEM))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("n%d", time.Now().UnixNano())
	ts := time.Now().Unix()
	sig, err := crypto.Sign(priv, crypto.Canonical(kind, callsign, nonce, ts, body))
	if err != nil {
		t.Fatal(err)
	}
	return &signed{
		Headers: map[string]string{
			"X-Sender": callsign, "X-Kind": kind, "X-TS": fmt.Sprintf("%d", ts),
			"X-Nonce": nonce, "X-Signature": sig,
		},
		Body: string(body),
	}
}

func register(t *testing.T, ctx *testCtx, callsign, role string) string {
	t.Helper()
	res, err := ca.Create(context.Background(), ctx.st, callsign, role)
	if err != nil {
		t.Fatal(err)
	}
	return res.PrivatePEM
}

func snapshotMessages(t *testing.T, ctx *testCtx, priv, callsign string) []db.Message {
	t.Helper()
	p := signAs(t, callsign, priv, "snapshot", map[string]any{})
	resp, body := doSigned(t, ctx, http.MethodGet, "/api/v1/snapshot", p)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshot(%s): %d %s", callsign, resp.StatusCode, body)
	}
	var snap struct {
		Messages []db.Message `json:"messages"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatal(err)
	}
	return snap.Messages
}

func sendMessageAs(t *testing.T, ctx *testCtx, priv, callsign, recipient, body string) {
	t.Helper()
	p := signAs(t, callsign, priv, "message", map[string]any{"recipient": recipient, "body": body})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("send message: %d %s", resp.StatusCode, b)
	}
}

func containsRecipient(msgs []db.Message, recipient, body string) bool {
	for _, m := range msgs {
		if m.Recipient == recipient && m.Body == body {
			return true
		}
	}
	return false
}

func TestMessageRoutingDirect(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")
	carol := register(t, ctx, "carol", "operator")

	sendMessageAs(t, ctx, string(ctx.priv), "admin", "bob", "секрет бобу")

	msgsBob := snapshotMessages(t, ctx, bob, "bob")
	if !containsRecipient(msgsBob, "bob", "секрет бобу") {
		t.Fatalf("bob must see his direct message, got %+v", msgsBob)
	}
	msgsCarol := snapshotMessages(t, ctx, carol, "carol")
	if containsRecipient(msgsCarol, "bob", "секрет бобу") {
		t.Fatalf("carol must NOT see bob's direct message, got %+v", msgsCarol)
	}
	msgsAdmin := snapshotMessages(t, ctx, string(ctx.priv), "admin")
	if !containsRecipient(msgsAdmin, "bob", "секрет бобу") {
		t.Fatalf("author must see his own copy, got %+v", msgsAdmin)
	}
}

func TestMessageRoutingGroup(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")
	carol := register(t, ctx, "carol", "operator")
	dave := register(t, ctx, "dave", "operator")

	recipients := `["bob","carol"]`
	sendMessageAs(t, ctx, string(ctx.priv), "admin", recipients, "группе")

	for _, tc := range []struct{ priv, who string }{{bob, "bob"}, {carol, "carol"}} {
		msgs := snapshotMessages(t, ctx, tc.priv, tc.who)
		if !containsRecipient(msgs, recipients, "группе") {
			t.Fatalf("group member must see the message, got %+v", msgs)
		}
	}
	msgsDave := snapshotMessages(t, ctx, dave, "dave")
	if containsRecipient(msgsDave, recipients, "группе") {
		t.Fatalf("non-member must not see the group message, got %+v", msgsDave)
	}
}

func TestBroadcastVisibleToAll(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	sendMessageAs(t, ctx, string(ctx.priv), "admin", "", "всем")

	for _, tc := range []struct{ priv, who string }{{string(ctx.priv), "admin"}, {bob, "bob"}} {
		msgs := snapshotMessages(t, ctx, tc.priv, tc.who)
		if !containsRecipient(msgs, "", "всем") {
			t.Fatalf("%s must see broadcast, got %+v", tc.who, msgs)
		}
	}
}

func TestMarkerUpdateDeleteAuth(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	// admin creates a marker
	p := signPacket(t, ctx, "admin", "marker", map[string]any{"lat": 55.9, "lon": 37.9, "type": "own", "n": "md1"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var mk db.Marker
	if err := json.Unmarshal(b, &mk); err != nil {
		t.Fatal(err)
	}

	// bob cannot delete admin's marker
	pDel := signAs(t, "bob", bob, "marker_delete", map[string]any{"n": mk.Nonce})
	resp2, b2 := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", pDel)
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("bob must not delete admin's marker: %d %s", resp2.StatusCode, b2)
	}

	// wrong nonce → not found
	pBad := signPacket(t, ctx, "admin", "marker_delete", map[string]any{"n": "nope"})
	resp3, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", pBad)
	if resp3.StatusCode != http.StatusForbidden && resp3.StatusCode != http.StatusInternalServerError {
		t.Fatalf("wrong nonce: got %d", resp3.StatusCode)
	}

	// admin (author) deletes → success, marker gone from snapshot
	pDel2 := signPacket(t, ctx, "admin", "marker_delete", map[string]any{"n": mk.Nonce})
	resp4, b4 := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", pDel2)
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("author delete: %d %s", resp4.StatusCode, b4)
	}
	pSnap := signPacket(t, ctx, "admin", "snapshot", map[string]any{})
	resp5, b5 := doSigned(t, ctx, http.MethodGet, "/api/v1/snapshot", pSnap)
	if resp5.StatusCode != 200 {
		t.Fatalf("snapshot: %d", resp5.StatusCode)
	}
	var snap struct {
		Markers []db.Marker `json:"markers"`
	}
	if err := json.Unmarshal(b5, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Markers) != 0 {
		t.Fatalf("marker should be deleted, got %+v", snap.Markers)
	}
}

func frameFrom(p *signed) []byte {
	return []byte(fmt.Sprintf(
		`{"sender":%q,"ts":%s,"nonce":%q,"kind":%q,"signature":%q,"data":%s}`,
		p.Headers["X-Sender"], p.Headers["X-TS"], p.Headers["X-Nonce"],
		p.Headers["X-Kind"], p.Headers["X-Signature"], p.Body,
	))
}

func wsDial(t *testing.T, ctx *testCtx) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.Dial(context.Background(), ctx.srv.URL+"/api/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func wsHello(t *testing.T, ctx *testCtx, conn *websocket.Conn, priv, callsign string) {
	t.Helper()
	p := signAs(t, callsign, priv, "hello", map[string]any{})
	if err := conn.Write(context.Background(), websocket.MessageText, frameFrom(p)); err != nil {
		t.Fatal(err)
	}
	// drain snapshot + packets backlog; a presence broadcast may follow, so
	// keep draining until we see no more unsolicited frames before the tests'
	// own expectations.
	for {
		rctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, msg, err := conn.Read(rctx)
		cancel()
		if err != nil {
			return
		}
		var f struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(msg, &f); err != nil {
			t.Fatalf("hello drain: %v (%s)", err, msg)
		}
		if f.Kind != "presence" {
			return
		}
	}
}

// readUntilKind consumes frames until the wanted kind arrives (skipping
// presence/hello broadcasts that may be interleaved), failing on timeout.
func readUntilKind(t *testing.T, conn *websocket.Conn, want string) []byte {
	t.Helper()
	for {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, msg, err := conn.Read(rctx)
		cancel()
		if err != nil {
			t.Fatalf("waiting for %q: %v", want, err)
		}
		var f struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(msg, &f); err != nil {
			t.Fatalf("readUntilKind: %v (%s)", err, msg)
		}
		if f.Kind == want {
			return msg
		}
	}
}

func TestSignalingRelayOnlyToRecipient(t *testing.T) {
	ctx := setup(t)
	alice := register(t, ctx, "alice", "operator")
	bob := register(t, ctx, "bob", "operator")

	cA := wsDial(t, ctx)
	defer cA.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cA, alice, "alice")

	cB := wsDial(t, ctx)
	defer cB.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cB, bob, "bob")

	// alice invites bob → only bob's socket receives the relayed frame
	inv := signAs(t, "alice", alice, "call_invite", map[string]any{"to": "bob", "sdp": map[string]string{"type": "offer", "sdp": "SDP_A"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(inv)); err != nil {
		t.Fatal(err)
	}

	msg := readUntilKind(t, cB, "call_invite")
	var f struct {
		Kind   string `json:"kind"`
		Sender string `json:"sender"`
		Data   struct {
			To string `json:"to"`
		} `json:"data"`
	}
	if err := json.Unmarshal(msg, &f); err != nil {
		t.Fatalf("relay: %v (%s)", err, msg)
	}
	if f.Kind != "call_invite" || f.Sender != "alice" || f.Data.To != "bob" {
		t.Fatalf("bob must receive alice's invite, got %s", msg)
	}

	// invite to an offline subscriber → the caller gets call_error
	p := signAs(t, "alice", alice, "call_invite", map[string]any{"to": "offline_carol", "sdp": map[string]string{"type": "offer", "sdp": "SDP_X"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(p)); err != nil {
		t.Fatal(err)
	}
	_ = readUntilKind(t, cA, "call_error")
}
