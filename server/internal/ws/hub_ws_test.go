package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func dialWS(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func writeFrame(t *testing.T, conn *websocket.Conn, b []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func readMsg(t *testing.T, conn *websocket.Conn, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		return nil, false
	}
	return data, true
}

func awaitKind(t *testing.T, conn *websocket.Conn, kind string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, ok := readMsg(t, conn, time.Until(deadline))
		if !ok {
			break
		}
		var m struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.Kind == kind {
			return
		}
	}
	t.Fatalf("never received frame kind %q", kind)
}

func awaitPresence(t *testing.T, conn *websocket.Conn, online ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	want := map[string]struct{}{}
	for _, s := range online {
		want[s] = struct{}{}
	}
	for time.Now().Before(deadline) {
		data, ok := readMsg(t, conn, time.Until(deadline))
		if !ok {
			break
		}
		var m struct {
			Kind string `json:"kind"`
			Data struct {
				Online []string `json:"online"`
			} `json:"data"`
		}
		if json.Unmarshal(data, &m) != nil || m.Kind != "presence" {
			continue
		}
		seen := make(map[string]struct{}, len(m.Data.Online))
		for _, s := range m.Data.Online {
			seen[s] = struct{}{}
		}
		all := true
		for s := range want {
			if _, has := seen[s]; !has {
				all = false
				break
			}
		}
		if all {
			return
		}
	}
	t.Fatalf("never received presence with %v", online)
}

// TestHandleOverWebsocketIntegration drives the full Hub.Handle accept loop over
// a real websocket: hello/backlog, presence fan-out, urgent broadcasts, SFrame
// call/PTT relay and CRL kick enforcement.
func TestHandleOverWebsocketIntegration(t *testing.T) {
	ctx := context.Background()
	h, st, bob, charlie := newTestHub(t)
	srv := httptest.NewServer(http.HandlerFunc(h.Handle))
	t.Cleanup(srv.Close)

	bobWS := dialWS(t, srv)
	t.Cleanup(func() { _ = bobWS.Close(websocket.StatusNormalClosure, "bye") })
	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "hello", map[string]any{}))
	awaitKind(t, bobWS, "snapshot")
	awaitPresence(t, bobWS, "bob")

	charlieWS := dialWS(t, srv)
	t.Cleanup(func() { _ = charlieWS.Close(websocket.StatusNormalClosure, "bye") })
	writeFrame(t, charlieWS, signedFrame(t, charlie, "charlie", "hello", map[string]any{}))
	awaitPresence(t, bobWS, "bob", "charlie")

	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "marker", map[string]any{"lat": 55.1, "lon": 37.2, "n": "wsmk"}))
	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "message", map[string]any{"recipient": "charlie", "body": "hi", "n": "wsmsg"}))
	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "call_invite", map[string]any{"to": "charlie", "enc": "sealed"}))
	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "call_invite", map[string]any{"to": "ghost"}))
	writeFrame(t, bobWS, signedFrame(t, bob, "bob", "ptt_start", map[string]any{"to": []string{"charlie"}, "enc": "sealed"}))

	awaitKind(t, charlieWS, "marker")
	awaitKind(t, charlieWS, "message")
	awaitKind(t, charlieWS, "call_invite")
	awaitKind(t, charlieWS, "ptt_start")
	awaitKind(t, bobWS, "call_error")

	deadline := time.Now().Add(5 * time.Second)
	for {
		mk, err := st.MarkerByNonce(ctx, "bob", "wsmk")
		if err == nil && mk != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("marker was never persisted: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	h.MarkRevoked("charlie", true)
	// Kick blocks until the websocket close handshake completes, so drive it
	// from a goroutine while the client reads to respond to the close frame.
	kickDone := make(chan bool, 1)
	go func() {
		h.Kick("charlie")
		kickDone <- true
	}()
	kc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _ = charlieWS.Read(kc) // returns when the server's close frame lands
	select {
	case <-kickDone:
	case <-time.After(3 * time.Second):
		t.Fatal("kick close handshake stalled")
	}
	// the server enforcement contract: the kicked peer leaves the roster.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		online := h.Online()
		if len(online) == 1 && online[0] == "bob" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if online := h.Online(); len(online) != 1 || online[0] != "bob" {
		t.Fatalf("roster must drop the kicked charlie, got %v", online)
	}

	h.Kick("ghost")
}

// TestHandleRejectsPlainHTTP verifies the upgrade-only accept path errors out.
func TestHandleRejectsPlainHTTP(t *testing.T) {
	h, _, _, _ := newTestHub(t)
	srv := httptest.NewServer(http.HandlerFunc(h.Handle))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode < 400 {
		t.Fatalf("plain HTTP GET to the websocket endpoint must fail, got %d", resp.StatusCode)
	}
}