package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"privatephone/server/internal/api"
	"privatephone/server/internal/ca"
	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

func randKey(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type testCtx struct {
	st   *db.Store
	srv  *httptest.Server
	priv []byte // admin private PEM for signing
}

func setup(t *testing.T) *testCtx {
	t.Helper()
	key := randKey(t)
	st, err := db.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })

	ctx := context.Background()
	res, err := ca.Create(ctx, st, "admin", "admin")
	if err != nil {
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
	hub := ws.NewHub(st, ver)
	apiSrv := api.New(st, hub, ver, "127.0.0.1:0")
	ts := httptest.NewServer(apiSrv.Handler())
	return &testCtx{st: st, srv: ts, priv: []byte(res.PrivatePEM)}
}

type signed struct {
	Headers map[string]string
	Body    string
}

// sign builds a canonical packet like the frontend WebCrypto flow does.
func signPacket(t *testing.T, ctx *testCtx, callsign, kind string, data any) *signed {
	t.Helper()
	priv, err := crypto.ParsePrivateKeyPEM(ctx.priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("n%d", time.Now().UnixNano())
	ts := time.Now().Unix()
	canonical := crypto.Canonical(kind, callsign, nonce, ts, body)
	sig, err := crypto.Sign(priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	return &signed{
		Headers: map[string]string{
			"X-Sender":    callsign,
			"X-Kind":      kind,
			"X-TS":        fmt.Sprintf("%d", ts),
			"X-Nonce":     nonce,
			"X-Signature": sig,
		},
		Body: string(body),
	}
}

func doSigned(t *testing.T, ctx *testCtx, method, path string, p *signed) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ctx.srv.URL+path, bytes.NewBufferString(p.Body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestHealthOpen(t *testing.T) {
	ctx := setup(t)
	resp, err := http.Get(ctx.srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	ctx := setup(t)
	resp, err := http.Post(ctx.srv.URL+"/api/v1/markers", "application/json",
		strings.NewReader(`{"lat":1,"lon":2}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned request must be 401, got %d", resp.StatusCode)
	}
}

func TestFullSignedFlow(t *testing.T) {
	ctx := setup(t)
	ctx2 := setup(t)
	_ = ctx2

	// admin signs home marker
	marker := map[string]any{"lat": 55.5, "lon": 37.5, "type": "own", "desc": "НП", "n": "m1"}
	p := signPacket(t, ctx, "admin", "marker", marker)
	resp, body := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("marker: %d %s", resp.StatusCode, body)
	}

	// snapshot must contain it
	p2 := signPacket(t, ctx, "admin", "snapshot", nil)
	resp2, body2 := doSigned(t, ctx, http.MethodGet, "/api/v1/snapshot", p2)
	if resp2.StatusCode != 200 {
		t.Fatalf("snapshot: %d %s", resp2.StatusCode, body2)
	}
	var snap struct {
		Markers []db.Marker `json:"markers"`
	}
	if err := json.Unmarshal(body2, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Markers) != 1 || snap.Markers[0].Sender != "admin" {
		t.Fatalf("snapshot markers: %+v", snap.Markers)
	}

	// tampered signature rejected
	p3 := signPacket(t, ctx, "admin", "marker", map[string]any{"lat": 0, "lon": 0, "type": "bad"})
	p3.Headers["X-Signature"] = "AAAA"
	resp3, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/markers", p3)
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered signature must be 401, got %d", resp3.StatusCode)
	}
}

func TestCARequiresAdmin(t *testing.T) {
	ctx := setup(t)
	// create an operator
	res, err := ca.Create(context.Background(), ctx.st, "bravo", "operator")
	if err != nil {
		t.Fatal(err)
	}

	// operator (not admin) tries to create subscriber → forbidden
	opPriv := res.PrivatePEM
	sub, err := crypto.ParsePrivateKeyPEM([]byte(opPriv))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"callsign":"charlie","role":"operator"}`)
	canon := crypto.Canonical("create_subscriber", "bravo", "nc", time.Now().Unix(), body)
	sig, _ := crypto.Sign(sub, canon)
	req, _ := http.NewRequest(http.MethodPost, ctx.srv.URL+"/api/v1/ca/subscribers", bytes.NewBuffer(body))
	req.Header.Set("X-Sender", "bravo")
	req.Header.Set("X-Kind", "create_subscriber")
	req.Header.Set("X-TS", fmt.Sprint(time.Now().Unix()))
	req.Header.Set("X-Nonce", "nc")
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator must not create subscribers, got %d", resp.StatusCode)
	}

	// admin succeeds
	adminCtx := ctx
	p := signPacket(t, adminCtx, "admin", "create_subscriber", map[string]any{"callsign": "charlie", "role": "operator"})
	resp2, b2 := doSigned(t, adminCtx, http.MethodPost, "/api/v1/ca/subscribers", p)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("admin create: %d %s", resp2.StatusCode, b2)
	}
	var out struct {
		Subscriber db.Subscriber `json:"subscriber"`
		Private    string        `json:"private_pem"`
	}
	if err := json.Unmarshal(b2, &out); err != nil {
		t.Fatal(err)
	}
	if out.Private == "" || out.Subscriber.Callsign != "charlie" {
		t.Fatal("expected created subscriber + private pem")
	}
}

func TestWebSocketBroadcast(t *testing.T) {
	ctx := setup(t)

	// frameFrom builds a WS message embedding data as raw JSON so the canonical
	// bytes signed by the client equal exactly what the server verifies.
	frameFrom := func(p *signed) []byte {
		return []byte(fmt.Sprintf(
			`{"sender":%q,"ts":%s,"nonce":%q,"kind":%q,"signature":%q,"data":%s}`,
			p.Headers["X-Sender"], p.Headers["X-TS"], p.Headers["X-Nonce"],
			p.Headers["X-Kind"], p.Headers["X-Signature"], p.Body,
		))
	}

	conn1, _, err := websocket.Dial(context.Background(), ctx.srv.URL+"/api/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close(websocket.StatusNormalClosure, "")

	if err := conn1.Write(context.Background(), websocket.MessageText, frameFrom(signPacket(t, ctx, "admin", "hello", map[string]any{}))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn1.Read(context.Background()); err != nil {
		t.Fatal(err) // snapshot or packets arrives
	}

	conn2, _, err := websocket.Dial(context.Background(), ctx.srv.URL+"/api/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")

	if err := conn2.Write(context.Background(), websocket.MessageText, frameFrom(signPacket(t, ctx, "admin", "hello", map[string]any{}))); err != nil {
		t.Fatal(err)
	}
	// drain both backlog frames from conn2
	for i := 0; i < 2; i++ {
		if _, _, err := conn2.Read(context.Background()); err != nil {
			t.Fatalf("conn2 read %d: %v", i, err)
		}
	}

	// conn1 sends a marker → conn2 must receive the broadcast (live + its own)
	m1 := frameFrom(signPacket(t, ctx, "admin", "marker", map[string]any{"lat": 55.1, "lon": 37.1, "type": "own", "n": "wsm1"}))
	if err := conn1.Write(context.Background(), websocket.MessageText, m1); err != nil {
		t.Fatal(err)
	}
	m2 := frameFrom(signPacket(t, ctx, "admin", "marker", map[string]any{"lat": 55.2, "lon": 37.2, "type": "own", "n": "wsm2"}))
	if err := conn2.Write(context.Background(), websocket.MessageText, m2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := conn2.Read(context.Background()); err != nil {
			t.Fatalf("conn2 live read %d: %v", i, err)
		}
	}
}
