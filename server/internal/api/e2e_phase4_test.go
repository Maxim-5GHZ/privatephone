package api_test

import (
	"context"
	"net/http"
	"testing"

	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
	"privatephone/server/internal/ws"
)

// authorContent feeds a well-shaped journal: markers, a direct message, an
// alarm with acknowledgment and clearing, a zone and a marker lifecycle.
func authorContent(t *testing.T, ctxA *testCtx, bobPriv string) {
	t.Helper()
	post := func(callsign, priv, kind, path string, body any, want int) {
		var p *signed
		if priv == "" {
			p = signPacket(t, ctxA, callsign, kind, body)
		} else {
			p = signAs(t, callsign, priv, kind, body)
		}
		resp, b := doSigned(t, ctxA, http.MethodPost, path, p)
		if resp.StatusCode != want {
			t.Fatalf("%s: want %d got %d: %s", kind, want, resp.StatusCode, b)
		}
	}
	post("admin", "", "marker", "/api/v1/markers", map[string]any{"lat": 55.0, "lon": 37.0, "type": "own", "n": "phome"}, http.StatusCreated)
	post("bob", bobPriv, "marker", "/api/v1/markers", map[string]any{"lat": 55.1, "lon": 37.1, "type": "own", "n": "pbob"}, http.StatusCreated)
	post("bob", bobPriv, "message", "/api/v1/messages", map[string]any{"recipient": "admin", "body": "резерв подтверждён"}, http.StatusCreated)
	post("admin", "", "alert", "/api/v1/alerts", map[string]any{"type": "sos", "text": "Пожар", "lat": 55.2, "lon": 37.2, "n": "alarm1"}, http.StatusCreated)
	post("bob", bobPriv, "alert_ack", "/api/v1/alerts", map[string]any{"author": "admin", "n": "alarm1"}, http.StatusCreated)
	post("admin", "", "zone", "/api/v1/zones", map[string]any{
		"name": "КПП-1", "color": "#ff3b30",
		"points": [][2]float64{{54.0, 36.0}, {54.5, 36.5}, {55.0, 36.2}},
	}, http.StatusCreated)
	post("bob", bobPriv, "marker_update", "/api/v1/markers", map[string]any{"n": "pbob", "type": "own", "desc": "новая точка"}, http.StatusOK)
	post("bob", bobPriv, "marker_delete", "/api/v1/markers", map[string]any{"n": "pbob"}, http.StatusOK)
	post("admin", "", "alert_clear", "/api/v1/alerts", map[string]any{"author": "admin", "n": "alarm1"}, http.StatusOK)
}

func exportBag(t *testing.T, ctxA *testCtx) []db.JournalEntry {
	t.Helper()
	entries, err := ctxA.st.ListJournal(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("source journal is empty")
	}
	return entries
}

func provisionNode(t *testing.T, ctxA *testCtx, privs map[string]string) *db.Store {
	t.Helper()
	st, err := db.Open(t.TempDir(), randKey(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	ctx := context.Background()
	for callsign, privPEM := range privs {
		priv, err := crypto.ParsePrivateKeyPEM([]byte(privPEM))
		if err != nil {
			t.Fatal(err)
		}
		pubPEM, err := crypto.PublicKeyToPEM(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		role := "operator"
		if callsign == "admin" {
			role = "admin"
		}
		if err := st.AddSubscriber(ctx, "id-"+callsign, callsign, role, string(pubPEM)); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func importInto(t *testing.T, st *db.Store, entries []db.JournalEntry) ws.ImportReport {
	t.Helper()
	ver := &protocol.Verifier{Subs: func(ctx context.Context, callsign string) (string, string, error) {
		sub, err := st.SubscriberByCallsign(ctx, callsign)
		if err != nil {
			return "", "", err
		}
		return sub.PubKey, sub.Role, nil
	}}
	hub := ws.NewHub(st, ver)
	rep, err := hub.ImportBag(context.Background(), entries)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestJournalImportReplay(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	authorContent(t, ctxA, bobPriv)
	doRevoke(t, ctxA, "bob", true)
	entries := exportBag(t, ctxA)

	stB := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	rep := importInto(t, stB, entries)
	if rep.Rejected {
		t.Fatalf("import rejected@%d: %s", rep.RejectedAt, rep.RejectedWhy)
	}
	if rep.AddedJournal != len(entries) {
		t.Fatalf("added %d journal rows, want %d", rep.AddedJournal, len(entries))
	}

	if bad, _, err := stB.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("imported journal must verify: bad=%d err=%v", bad, err)
	}
	local, _ := stB.ListJournal(ctx, 0)
	if len(local) != len(entries) {
		t.Fatalf("local journal %d rows, want %d", len(local), len(entries))
	}

	msgs, _ := stB.ListMessages(ctx)
	if !containsRecipient(msgs, "admin", "резерв подтверждён") {
		t.Fatalf("imported message missing: %+v", msgs)
	}
	markers, _ := stB.ListMarkers(ctx)
	if len(markers) != 1 || markers[0].Sender != "admin" {
		t.Fatalf("imported active markers: %+v (bob's must be deleted)", markers)
	}
	alerts, _ := stB.ListActiveAlerts(ctx)
	if len(alerts) != 0 {
		t.Fatalf("imported alerts must be cleared: %+v", alerts)
	}
	zones, _ := stB.ListZones(ctx)
	if len(zones) != 1 || zones[0].Name != "КПП-1" {
		t.Fatalf("imported zones: %+v", zones)
	}
	bob, err := stB.SubscriberByCallsign(ctx, "bob")
	if err != nil || bob.Revoked != 1 {
		t.Fatalf("CRL must propagate: err=%v revoked=%d", err, bob.Revoked)
	}

	rep2 := importInto(t, stB, entries)
	if rep2.Rejected || rep2.AddedJournal != 0 || rep2.SkippedDup != len(entries) {
		t.Fatalf("re-import must be idempotent: %+v", rep2)
	}
	if head, _ := stB.JournalHead(ctx); head != rep.Head {
		t.Fatalf("head changed on re-import: %s", head)
	}
}

func TestJournalImportTwoHop(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	authorContent(t, ctxA, bobPriv)
	entries := exportBag(t, ctxA)

	st := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	m := len(entries) / 2
	if m == 0 {
		m = 1
	}
	rep1 := importInto(t, st, entries[:m])
	if rep1.Rejected || rep1.AddedJournal != m {
		t.Fatalf("first hop: %+v", rep1)
	}
	rep2 := importInto(t, st, entries[m:])
	if rep2.Rejected || rep2.AddedJournal != len(entries)-m {
		t.Fatalf("second hop: %+v", rep2)
	}
	if bad, _, err := st.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("two-hop journal must verify: bad=%d err=%v", bad, err)
	}
	srcHead, _ := ctxA.st.JournalHead(ctx)
	dstHead, _ := st.JournalHead(ctx)
	if srcHead != dstHead {
		t.Fatalf("heads must converge: src=%s dst=%s", srcHead, dstHead)
	}
}

func TestJournalImportRejectBadBag(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	authorContent(t, ctxA, bobPriv)
	entries := exportBag(t, ctxA)

	// tampered signature → nothing may be imported
	st1 := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	bad := make([]db.JournalEntry, len(entries))
	copy(bad, entries)
	bad[2].Signature = "BADSIG"
	rep := importInto(t, st1, bad)
	if !rep.Rejected || rep.RejectedAt < 0 {
		t.Fatalf("tampered bag must be rejected: %+v", rep)
	}
	if n, _ := st1.ListJournal(ctx, 0); len(n) != 0 {
		t.Fatalf("rejected bag must write nothing, journal has %d rows", len(n))
	}

	// suffix without prefix → discontinuity rejected at index 0
	st2 := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	rep2 := importInto(t, st2, entries[1:])
	if !rep2.Rejected || rep2.RejectedAt != 0 {
		t.Fatalf("discontinuous bag must be rejected@0: %+v", rep2)
	}

	// sender not in the local registry → whole bag refused
	st3 := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv)})
	rep3 := importInto(t, st3, entries)
	if !rep3.Rejected || rep3.RejectedAt != 1 {
		t.Fatalf("unregistered sender must be rejected at his first row: %+v", rep3)
	}
	if n, _ := st3.ListJournal(ctx, 0); len(n) != 0 {
		t.Fatalf("rejected bag must write nothing, journal has %d rows", len(n))
	}
}
