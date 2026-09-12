package api_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"

	"privatephone/server/internal/api"
	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

// ---- reference E2EE implementation (go), mirroring frontend WebCrypto ----

const e2eeInfo = "pp-e2ee/v1"

type encKey struct {
	To   string `json:"to"`
	Salt string `json:"salt"`
	IV   string `json:"iv"`
	EK   string `json:"ek"`
}

type encEnv struct {
	V   int      `json:"v"`
	Alg string   `json:"alg"`
	IV  string   `json:"iv"`
	C   string   `json:"c"`
	K   []encKey `json:"k"`
}

type testSub struct {
	callsign string
	pubPEM   string
}

func ecdhPriv(t *testing.T, k *ecdsa.PrivateKey) *ecdh.PrivateKey {
	t.Helper()
	scalar := make([]byte, 32)
	k.D.FillBytes(scalar)
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func ecdhPub(t *testing.T, pub *ecdsa.PublicKey) *ecdh.PublicKey {
	t.Helper()
	pt := make([]byte, 65)
	pt[0] = 4
	pub.X.FillBytes(pt[1:33])
	pub.Y.FillBytes(pt[33:])
	p, err := ecdh.P256().NewPublicKey(pt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pubFromPEM(t *testing.T, pem string) *ecdsa.PublicKey {
	t.Helper()
	k, err := crypto.ParsePublicKeyPEM([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func kdf(t *testing.T, secret, salt []byte) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, secret, salt, []byte(e2eeInfo))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func gcm(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// encrypt reference-implements the same envelope the frontend builds: a random
// message key AES-GCM-seals the plaintext under a fresh IV, and for each
// recipient the message key is wrapped under HKDF(ECDH(me, them)) derived from
// the operator's static P-256 keypair.
func encrypt(t *testing.T, me *ecdsa.PrivateKey, recipients []testSub, plaintext string) string {
	t.Helper()
	meECDH := ecdhPriv(t, me)
	msgKey := make([]byte, 32)
	if _, err := rand.Read(msgKey); err != nil {
		t.Fatal(err)
	}
	iv0 := make([]byte, 12)
	if _, err := rand.Read(iv0); err != nil {
		t.Fatal(err)
	}
	cph := gcm(t, msgKey).Seal(nil, iv0, []byte(plaintext), nil)

	env := encEnv{V: 1, Alg: "A256GCM", IV: b64(iv0), C: b64(cph), K: nil}
	for _, r := range recipients {
		shared, err := meECDH.ECDH(ecdhPub(t, pubFromPEM(t, r.pubPEM)))
		if err != nil {
			t.Fatal(err)
		}
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		kek := kdf(t, shared, salt)
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			t.Fatal(err)
		}
		env.K = append(env.K, encKey{To: r.callsign, Salt: b64(salt), IV: b64(iv), EK: b64(gcm(t, kek).Seal(nil, iv, msgKey, nil))})
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// decrypt opens the envelope for `me` using the sender's public key.
func decrypt(t *testing.T, me *ecdsa.PrivateKey, senderPub *ecdsa.PublicKey, envJSON string) string {
	t.Helper()
	var env encEnv
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		t.Fatalf("bad envelope: %v", err)
	}
	shared, err := ecdhPriv(t, me).ECDH(ecdhPub(t, senderPub))
	if err != nil {
		t.Fatal(err)
	}
	var msgKey []byte
	for _, k := range env.K {
		if k.To == "" {
			continue
		}
		kek := kdf(t, shared, b64d(t, k.Salt))
		mk, err := gcm(t, kek).Open(nil, b64d(t, k.IV), b64d(t, k.EK), nil)
		if err == nil {
			msgKey = mk
			break
		}
	}
	if msgKey == nil {
		t.Fatal("no wrapped key opened for the recipient")
	}
	plain, err := gcm(t, msgKey).Open(nil, b64d(t, env.IV), b64d(t, env.C), nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// ---- helpers ----

// serverFor builds a full API server around an existing store, reusing the
// given admin private PEM as the signing identity (sneaker-net parity).
func serverFor(t *testing.T, st *db.Store, adminPEM string) *testCtx {
	t.Helper()
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
	return &testCtx{st: st, srv: ts, priv: []byte(adminPEM)}
}

// postSigned posts and requires a specific status, unwrapping the response.
func postSigned(t *testing.T, ctx *testCtx, callsign, priv, kind, path string, body any, want int) []byte {
	t.Helper()
	var p *signed
	if priv == "" {
		p = signPacket(t, ctx, callsign, kind, body)
	} else {
		p = signAs(t, callsign, priv, kind, body)
	}
	resp, b := doSigned(t, ctx, http.MethodPost, path, p)
	if resp.StatusCode != want {
		t.Fatalf("%s: want %d got %d: %s", kind, want, resp.StatusCode, b)
	}
	return b
}

func TestE2eeServerStaysOpaque(t *testing.T) {
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	bobSub, _ := ctxA.st.SubscriberByCallsign(context.Background(), "bob")

	adminKey, err := crypto.ParsePrivateKeyPEM(ctxA.priv)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := crypto.ParsePrivateKeyPEM([]byte(bobPriv))
	if err != nil {
		t.Fatal(err)
	}
	adminPub, _ := crypto.PublicKeyToPEM(&adminKey.PublicKey)
	bobs := []testSub{{callsign: "bob", pubPEM: bobSub.PubKey}, {callsign: "admin", pubPEM: string(adminPub)}}

	// marker: geometry only inside the ciphertext
	markerPlain := `{"lat":55.771,"lon":37.684,"type":"own","desc":"секретная точка"}`
	markerEnv := encrypt(t, adminKey, bobs, markerPlain)
	b := postSigned(t, ctxA, "admin", "", "marker", "/api/v1/markers", map[string]any{"n": "em1", "enc": json.RawMessage(markerEnv)}, http.StatusCreated)
	var mk db.Marker
	if err := json.Unmarshal(b, &mk); err != nil {
		t.Fatal(err)
	}
	if mk.Type != "enc" || mk.Lat != 0 || mk.Lon != 0 {
		t.Fatalf("server must stay opaque: %+v", mk)
	}
	if strings.Contains(string(b), "секретная точка") {
		t.Fatal("ciphertext must not contain plaintext")
	}
	got := decrypt(t, bobKey, &adminKey.PublicKey, mk.Descr)
	if got != markerPlain {
		t.Fatalf("recipient must recover marker payload: %q vs %q", got, markerPlain)
	}

	// message to bob: body opaque, recipient decrypts
	msgPlain := `{"body":"план сбора в 22:00"}`
	msgEnv := encrypt(t, adminKey, []testSub{{callsign: "bob", pubPEM: bobSub.PubKey}}, msgPlain)
	b = postSigned(t, ctxA, "admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "n": "em1", "enc": json.RawMessage(msgEnv)}, http.StatusCreated)
	var m db.Message
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "22:00") {
		t.Fatal("server must not see the message text")
	}
	if got := decrypt(t, bobKey, &adminKey.PublicKey, m.Body); got != msgPlain {
		t.Fatalf("recipient must recover message: %q", got)
	}

	// alert with an out-of-whitelist type is still accepted (E2EE cargo)
	alertEnv := encrypt(t, adminKey, bobs, `{"type":"bogus","text":"ковид","lat":55.0,"lon":37.0}`)
	b = postSigned(t, ctxA, "admin", "", "alert", "/api/v1/alerts", map[string]any{"n": "ea1", "enc": json.RawMessage(alertEnv)}, http.StatusCreated)
	var al db.Alert
	if err := json.Unmarshal(b, &al); err != nil {
		t.Fatal(err)
	}
	if al.Type != "enc" {
		t.Fatalf("alert must stay opaque, got type %q", al.Type)
	}
	alerts, _ := ctxA.st.ListActiveAlerts(context.Background())
	if len(alerts) != 1 {
		t.Fatalf("encrypted alert must be active: %+v", alerts)
	}

	// zone with fewer than 3 points accepted (geometry is inside the cipher)
	zoneEnv := encrypt(t, adminKey, bobs, `{"name":"Район","color":"#ff3b30","points":[[1,1]]}`)
	b = postSigned(t, ctxA, "admin", "", "zone", "/api/v1/zones", map[string]any{"n": "ez1", "enc": json.RawMessage(zoneEnv)}, http.StatusCreated)
	var z db.Zone
	if err := json.Unmarshal(b, &z); err != nil {
		t.Fatal(err)
	}
	if z.Name != "enc" {
		t.Fatalf("zone must stay opaque, got name %q", z.Name)
	}

	// marker_update carries full encrypted content, no merge on the server
	updEnv := encrypt(t, adminKey, bobs, `{"lat":55.9,"lon":37.9,"type":"meet","desc":"обновлено"}`)
	b = postSigned(t, ctxA, "admin", "", "marker_update", "/api/v1/markers", map[string]any{"n": "em1", "enc": json.RawMessage(updEnv)}, http.StatusOK)
	var up db.Marker
	if err := json.Unmarshal(b, &up); err != nil {
		t.Fatal(err)
	}
	if up.Type != "enc" {
		t.Fatalf("update must stay opaque: %+v", up)
	}
	if got := decrypt(t, bobKey, &adminKey.PublicKey, up.Descr); got != `{"lat":55.9,"lon":37.9,"type":"meet","desc":"обновлено"}` {
		t.Fatalf("updated marker content: %q", got)
	}
}

func TestE2eeBagImportConverges(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	bobKey, err := crypto.ParsePrivateKeyPEM([]byte(bobPriv))
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := crypto.ParsePrivateKeyPEM(ctxA.priv)
	if err != nil {
		t.Fatal(err)
	}
	bobSub, _ := ctxA.st.SubscriberByCallsign(ctx, "bob")
	adminPub, _ := crypto.PublicKeyToPEM(&adminKey.PublicKey)
	all := func() []testSub {
		return []testSub{{callsign: "bob", pubPEM: bobSub.PubKey}, {callsign: "admin", pubPEM: string(adminPub)}}
	}

	markerEnv := encrypt(t, adminKey, all(), `{"lat":55.1,"lon":37.1,"type":"own","desc":"пункт"}`)
	postSigned(t, ctxA, "admin", "", "marker", "/api/v1/markers", map[string]any{"n": "bem1", "enc": json.RawMessage(markerEnv)}, http.StatusCreated)
	updEnv := encrypt(t, adminKey, all(), `{"lat":55.2,"lon":37.2,"type":"meet","desc":"сместился"}`)
	postSigned(t, ctxA, "admin", "", "marker_update", "/api/v1/markers", map[string]any{"n": "bem1", "enc": json.RawMessage(updEnv)}, http.StatusOK)
	msgEnv := encrypt(t, adminKey, all(), `{"body":"сбор на вокзале"}`)
	postSigned(t, ctxA, "admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "n": "bem2", "enc": json.RawMessage(msgEnv)}, http.StatusCreated)
	alertEnv := encrypt(t, adminKey, all(), `{"type":"gather","text":"тревога","lat":55.0,"lon":37.0}`)
	postSigned(t, ctxA, "admin", "", "alert", "/api/v1/alerts", map[string]any{"n": "bea1", "enc": json.RawMessage(alertEnv)}, http.StatusCreated)
	zoneEnv := encrypt(t, adminKey, all(), `{"name":"КПП","color":"#f00","points":[[54,36],[54.5,36.5],[55,36]]}`)
	postSigned(t, ctxA, "admin", "", "zone", "/api/v1/zones", map[string]any{"n": "bez1", "enc": json.RawMessage(zoneEnv)}, http.StatusCreated)

	entries := exportBag(t, ctxA)

	stB := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	rep := importInto(t, stB, entries)
	if rep.Rejected {
		t.Fatalf("encrypted bag rejected@%d: %s", rep.RejectedAt, rep.RejectedWhy)
	}
	if rep.AddedJournal != len(entries) {
		t.Fatalf("added %d rows, want %d", rep.AddedJournal, len(entries))
	}
	if bad, _, err := stB.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("imported encrypted journal must verify: bad=%d err=%v", bad, err)
	}
	srcHead, _ := ctxA.st.JournalHead(ctx)
	dstHead, _ := stB.JournalHead(ctx)
	if srcHead != dstHead {
		t.Fatalf("heads must converge: %s vs %s", srcHead, dstHead)
	}

	markers, _ := stB.ListMarkers(ctx)
	if len(markers) != 1 || markers[0].Type != "enc" {
		t.Fatalf("imported markers: %+v", markers)
	}
	if got := decrypt(t, bobKey, &adminKey.PublicKey, markers[0].Descr); strings.Contains(got, "сместился") == false {
		t.Fatalf("marker update must be stored as full content: %q", got)
	}
	msgs, _ := stB.ListMessages(ctx)
	if len(msgs) != 1 || msgs[0].Recipient != "bob" {
		t.Fatalf("imported messages: %+v", msgs)
	}
	if got := decrypt(t, bobKey, &adminKey.PublicKey, msgs[0].Body); got != `{"body":"сбор на вокзале"}` {
		t.Fatalf("imported message decrypt: %q", got)
	}
	alerts, _ := stB.ListActiveAlerts(ctx)
	if len(alerts) != 1 { // never cleared in this scenario
		t.Fatalf("imported alerts: %+v", alerts)
	}
	zones, _ := stB.ListZones(ctx)
	if len(zones) != 1 || zones[0].Name != "enc" {
		t.Fatalf("imported zones: %+v", zones)
	}
}

func TestAdminStatsAndRESTImport(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")

	stB := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	ctxB := serverFor(t, stB, string(ctxA.priv))

	// operator must be forbidden on admin endpoints
	p := signAs(t, "bob", bobPriv, "admin_stats", "")
	resp, _ := doSigned(t, ctxB, http.MethodGet, "/api/v1/admin/stats", p)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("operator stats: want 403 got %d", resp.StatusCode)
	}

	// empty bag import through REST is a clean no-op
	p = signAs(t, "admin", string(ctxA.priv), "journal_import", map[string]any{"entries": nil})
	resp, body := doSigned(t, ctxB, http.MethodPost, "/api/v1/journal/import", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty import: %d %s", resp.StatusCode, body)
	}
	var rep ws.ImportReport
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Rejected || rep.AddedJournal != 0 {
		t.Fatalf("empty import report: %+v", rep)
	}

	// cross-node REST import converges the whole bag
	adminKey, err := crypto.ParsePrivateKeyPEM(ctxA.priv)
	if err != nil {
		t.Fatal(err)
	}
	bobSub, _ := ctxA.st.SubscriberByCallsign(ctx, "bob")
	adminPub, _ := crypto.PublicKeyToPEM(&adminKey.PublicKey)
	env := encrypt(t, adminKey, []testSub{{callsign: "bob", pubPEM: bobSub.PubKey}, {callsign: "admin", pubPEM: string(adminPub)}}, `{"body":"по флешке"}`)
	postSigned(t, ctxA, "admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "n": "ri1", "enc": json.RawMessage(env)}, http.StatusCreated)
	entries := exportBag(t, ctxA)

	p = signAs(t, "admin", string(ctxA.priv), "journal_import", map[string]any{"entries": entries})
	resp, body = doSigned(t, ctxB, http.MethodPost, "/api/v1/journal/import", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rest import: %d %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Rejected || rep.AddedJournal != len(entries) {
		t.Fatalf("rest import report: %+v", rep)
	}
	if bad, _, err := stB.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("rest-imported journal must verify: bad=%d err=%v", bad, err)
	}

	// admin stats reflect the imported journal
	p = signAs(t, "admin", string(ctxA.priv), "admin_stats", "")
	resp, body = doSigned(t, ctxB, http.MethodGet, "/api/v1/admin/stats", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats: %d", resp.StatusCode)
	}
	var st struct {
		Subscribers int    `json:"subscribers"`
		Active      int    `json:"active"`
		Revoked     int    `json:"revoked"`
		Online      int    `json:"online"`
		Journal     int64  `json:"journal_entries"`
		Head        string `json:"journal_head"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Subscribers != 2 || st.Active != 2 || st.Journal != int64(len(entries)) {
		t.Fatalf("admin stats mismatch: %+v", st)
	}
	if st.Head == "" {
		t.Fatal("expected a journal head")
	}
}
