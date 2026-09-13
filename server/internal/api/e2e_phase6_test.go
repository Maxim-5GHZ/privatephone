package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"privatephone/server/internal/api"
	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

// TestPendingThenAckClearsBacklog covers the store-and-forward REST projection
// (GET /api/v1/pending) plus the WS ack lifecycle that marks rows delivered.
func TestPendingThenAckClearsBacklog(t *testing.T) {
	ctx := context.Background()
	srv := setup(t)
	bobPriv := register(t, srv, "bob", "operator")
	charliePriv := register(t, srv, "charlie", "operator")

	postSigned(t, srv, "admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "body": "для боба", "n": "p6-m1"}, http.StatusCreated)
	postSigned(t, srv, "admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "charlie", "body": "для шарли", "n": "p6-m2"}, http.StatusCreated)
	postSigned(t, srv, "admin", "", "marker", "/api/v1/markers", map[string]any{"lat": 55.0, "lon": 37.0, "type": "own", "n": "p6-mk"}, http.StatusCreated)

	pending := func(priv, callsign string) (int, []db.Packet) {
		p := signAs(t, callsign, priv, "pending", map[string]any{})
		resp, body := doSigned(t, srv, http.MethodGet, "/api/v1/pending", p)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pending %s: %d %s", callsign, resp.StatusCode, body)
		}
		var got struct {
			Items []db.Packet `json:"items"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		return len(got.Items), got.Items
	}

	n, items := pending(bobPriv, "bob")
	if n != 2 {
		t.Fatalf("bob should see broadcast marker + own direct, got %d items", n)
	}
	seen := map[string]bool{}
	for _, it := range items {
		seen[it.Kind] = true
	}
	if !seen["message"] || !seen["marker"] {
		t.Fatalf("bob's pending must contain the direct message and the broadcast marker: %v", seen)
	}
	for _, it := range items {
		if strings.Contains(it.Payload, "p6-m2") {
			t.Fatalf("bob's pending must filter out charlie's direct: %s", it.Payload)
		}
	}

	n, items = pending(charliePriv, "charlie")
	if n != 2 {
		t.Fatalf("charlie should see broadcast marker + own direct, got %d", n)
	}
	for _, it := range items {
		if strings.Contains(it.Payload, "p6-m1") {
			t.Fatalf("charlie's pending must filter out bob's direct: %s", it.Payload)
		}
	}

	// bob connects over WS, hello replays the backlog; he acks the ids.
	conn := wsDial(t, srv)
	defer conn.Close(websocket.StatusNormalClosure, "")
	hello := signAs(t, "bob", bobPriv, "hello", map[string]any{})
	if err := conn.Write(ctx, websocket.MessageText, frameFrom(hello)); err != nil {
		t.Fatal(err)
	}
	msg := readUntilKind(t, conn, "packets")
	var pk struct {
		Data struct {
			Items []db.Packet `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(msg, &pk); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(pk.Data.Items))
	for _, it := range pk.Data.Items {
		ids = append(ids, it.ID)
	}
	if len(ids) != 2 {
		t.Fatalf("ws backlog for bob: want 2 packets, got %d", len(ids))
	}
	ack := signAs(t, "bob", bobPriv, "ack", map[string]any{"ids": ids})
	if err := conn.Write(ctx, websocket.MessageText, frameFrom(ack)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		n, _ = pending(bobPriv, "bob")
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bob's pending still has %d items after ack", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCreateSubscriberBranches(t *testing.T) {
	srv := setup(t)

	dup := signPacket(t, srv, "admin", "create_subscriber", map[string]any{"callsign": "admin", "role": "admin"})
	resp, _ := doSigned(t, srv, http.MethodPost, "/api/v1/ca/subscribers", dup)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate callsign: want 409 got %d", resp.StatusCode)
	}

	badRole := signPacket(t, srv, "admin", "create_subscriber", map[string]any{"callsign": "neo", "role": "root"})
	resp, _ = doSigned(t, srv, http.MethodPost, "/api/v1/ca/subscribers", badRole)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid role: want 400 got %d", resp.StatusCode)
	}

	empty := signPacket(t, srv, "admin", "create_subscriber", map[string]any{"callsign": ""})
	resp, _ = doSigned(t, srv, http.MethodPost, "/api/v1/ca/subscribers", empty)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty callsign: want 400 got %d", resp.StatusCode)
	}
}

func TestHealthAfterStoreClosed(t *testing.T) {
	srv := setup(t)
	if err := srv.st.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health after close: want 503 got %d", resp.StatusCode)
	}
}

func TestSpaFallback(t *testing.T) {
	srv := setup(t)

	resp, err := http.Get(srv.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `<div id="root">`) {
		t.Fatalf("SPA index: %d body=%s", resp.StatusCode, body)
	}

	resp, err = http.Get(srv.srv.URL + "/api/v1/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	body = readAll(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown API path must 404, got %d: %s", resp.StatusCode, body)
	}

	resp, err = http.Get(srv.srv.URL + "/route/server")
	if err != nil {
		t.Fatal(err)
	}
	body = readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `<div id="root">`) {
		t.Fatalf("client route must be served index.html, got %d", resp.StatusCode)
	}
}

// TestE2eeNegativeCrypto pins the Go reference implementation's failure modes:
// a non-recipient must not open an envelope, tampered ciphertext must fail for
// everyone, and a single corrupted wrapped key must fall through to the next.
func TestE2eeNegativeCrypto(t *testing.T) {
	ctx := context.Background()
	srv := setup(t)
	bobPriv := register(t, srv, "bob", "operator")
	charliePriv := register(t, srv, "charlie", "operator")

	adminKey, err := crypto.ParsePrivateKeyPEM(srv.priv)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := crypto.ParsePrivateKeyPEM([]byte(bobPriv))
	if err != nil {
		t.Fatal(err)
	}
	charlieKey, err := crypto.ParsePrivateKeyPEM([]byte(charliePriv))
	if err != nil {
		t.Fatal(err)
	}
	bobSub, err := srv.st.SubscriberByCallsign(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	adminPub, err := crypto.PublicKeyToPEM(&adminKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	env := encrypt(t, adminKey, []testSub{
		{callsign: "bob", pubPEM: bobSub.PubKey},
		{callsign: "admin", pubPEM: string(adminPub)},
	}, "секрет")

	if got, ok := tryOpen(t, bobKey, &adminKey.PublicKey, env); !ok || got != "секрет" {
		t.Fatalf("bob must decrypt: ok=%v got=%q", ok, got)
	}
	if _, ok := tryOpen(t, charlieKey, &adminKey.PublicKey, env); ok {
		t.Fatal("charlie (not a recipient) must not decrypt")
	}

	if _, ok := tryOpen(t, bobKey, &adminKey.PublicKey, tamperField(t, env, "c")); ok {
		t.Fatal("tampered ciphertext must not decrypt")
	}

	if _, ok := tryOpen(t, bobKey, &adminKey.PublicKey, tamperField(t, env, "k0")); ok {
		t.Fatal("tampered key wrap must deny the recipient access")
	}
}

// TestServeTLS exercises the real HTTPS path: self-signed certificate, WithTLS,
// Serve + graceful shutdown, and an inbound health check that needs no auth.
func TestServeTLS(t *testing.T) {
	ctx := context.Background()
	srv := setup(t)
	certPath := filepath.Join(t.TempDir(), "tls.crt")
	keyPath := filepath.Join(t.TempDir(), "tls.key")
	if err := crypto.WriteSelfSignedTLSCert(certPath, keyPath, []string{"127.0.0.1"}, "test-org"); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(certPEM), "-----BEGIN CERTIFICATE-----") {
		t.Fatal("certificate file must be PEM")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ver := &protocol.Verifier{
		Guard: crypto.NewReplayGuard(10000, crypto.DefaultSkewWindow),
		Subs: func(ctx context.Context, callsign string) (string, string, error) {
			sub, err := srv.st.SubscriberByCallsign(ctx, callsign)
			if err != nil {
				return "", "", err
			}
			if sub.Revoked != 0 {
				return "", "", protocol.ErrRevoked
			}
			return sub.PubKey, sub.Role, nil
		},
	}
	apiSrv := api.New(srv.st, ws.NewHub(srv.st, ver), ver, fmt.Sprintf("127.0.0.1:%d", port))
	apiSrv.WithTLS(certPath, keyPath)

	srvCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- apiSrv.Serve(srvCtx) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	url := fmt.Sprintf("https://127.0.0.1:%d/api/v1/health", port)
	ok := false
	for i := 0; i < 50 && !ok; i++ {
		res, e := client.Get(url)
		if e == nil {
			ok = res.StatusCode == http.StatusOK
			res.Body.Close()
		}
		if !ok {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("https health never answered OK")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not shut down after cancel")
	}
}

// tryOpen is a non-fatal variant of the reference decrypt helper.
func tryOpen(t *testing.T, me *ecdsa.PrivateKey, senderPub *ecdsa.PublicKey, envJSON string) (string, bool) {
	t.Helper()
	var env encEnv
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		return "", false
	}
	shared, err := ecdhPriv(t, me).ECDH(ecdhPub(t, senderPub))
	if err != nil {
		return "", false
	}
	for _, k := range env.K {
		kek := kdf(t, shared, b64d(t, k.Salt))
		mk, err := gcm(t, kek).Open(nil, b64d(t, k.IV), b64d(t, k.EK), nil)
		if err != nil {
			continue
		}
		plain, err := gcm(t, mk).Open(nil, b64d(t, env.IV), b64d(t, env.C), nil)
		if err != nil {
			return "", false
		}
		return string(plain), true
	}
	return "", false
}

// tamperField flips a byte of the named field in the envelope JSON.
func tamperField(t *testing.T, envJSON, field string) string {
	t.Helper()
	var env encEnv
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		t.Fatal(err)
	}
	flip := func(s *string) {
		b, err := base64.StdEncoding.DecodeString(*s)
		if err != nil || len(b) == 0 {
			t.Fatalf("cannot decode %q", *s)
		}
		b[0] ^= 0xff
		*s = base64.StdEncoding.EncodeToString(b)
	}
	switch field {
	case "c":
		flip(&env.C)
	case "k0":
		if len(env.K) == 0 {
			t.Fatal("envelope has no wrapped keys")
		}
		flip(&env.K[0].EK)
	default:
		t.Fatalf("unknown field %q", field)
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSubscriberStatusErrorBranches(t *testing.T) {
	ctxA := setup(t)

	p := signAs(t, "admin", string(ctxA.priv), "not_a_status_kind", map[string]any{})
	resp, body := doSigned(t, ctxA, http.MethodPost, "/api/v1/ca/revoke", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong kind: want 400 got %d %s", resp.StatusCode, body)
	}

	p = signAs(t, "admin", string(ctxA.priv), "revoke_subscriber", map[string]any{})
	resp, _ = doSigned(t, ctxA, http.MethodPost, "/api/v1/ca/revoke", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing callsign: want 400 got %d", resp.StatusCode)
	}

	p = signAs(t, "admin", string(ctxA.priv), "unrevoke_subscriber", map[string]any{"callsign": "nobody"})
	resp, _ = doSigned(t, ctxA, http.MethodPost, "/api/v1/ca/revoke", p)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown callsign: want 404 got %d", resp.StatusCode)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestJournalImportErrorBranches drives the 400/500 arms of the REST importer.
func TestJournalImportErrorBranches(t *testing.T) {
	ctxA := setup(t)

	// struct-level decode failure: entries is not an array
	p := signAs(t, "admin", string(ctxA.priv), "journal_import", map[string]any{"entries": "not-an-array"})
	resp, body := doSigned(t, ctxA, http.MethodPost, "/api/v1/journal/import", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed bag: want 400 got %d %s", resp.StatusCode, body)
	}

	// an entry signed by an unknown sender must be rejected by the importer
	bad := []db.JournalEntry{{
		ID: "x1", Sender: "stranger", Kind: "message", Payload: `{"recipient":"bob"}`,
		Signature: "bm9wZQ==", Nonce: "bn1", TS: 1, Recipient: "bob",
	}}
	p = signAs(t, "admin", string(ctxA.priv), "journal_import", map[string]any{"entries": bad})
	resp, body = doSigned(t, ctxA, http.MethodPost, "/api/v1/journal/import", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unverifiable bag: want 200 got %d %s", resp.StatusCode, body)
	}
	var rep ws.ImportReport
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Rejected || rep.AddedJournal != 0 {
		t.Fatalf("unverifiable bag must reject everything: %+v", rep)
	}
}
