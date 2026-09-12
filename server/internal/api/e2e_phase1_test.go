package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func doRevoke(t *testing.T, ctx *testCtx, callsign string, revoke bool) (*http.Response, []byte) {
	t.Helper()
	kind := "unrevoke_subscriber"
	if revoke {
		kind = "revoke_subscriber"
	}
	p := signPacket(t, ctx, "admin", kind, map[string]any{"callsign": callsign})
	return doSigned(t, ctx, http.MethodPost, "/api/v1/ca/revoke", p)
}

func listSubscribers(t *testing.T, ctx *testCtx) []map[string]any {
	t.Helper()
	p := signPacket(t, ctx, "admin", "list_subscribers", map[string]any{})
	resp, body := doSigned(t, ctx, http.MethodGet, "/api/v1/subscribers", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list subscribers: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Subscribers []map[string]any `json:"subscribers"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Subscribers
}

func TestCRLRevokeRejectsOldKey(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	// before revocation bob can read the snapshot
	snapshotMessages(t, ctx, bob, "bob")

	// admin revokes bob
	resp, b := doRevoke(t, ctx, "bob", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}

	// bob's credentials are dead everywhere
	p := signAs(t, "bob", bob, "snapshot", map[string]any{})
	r2, b2 := doSigned(t, ctx, http.MethodGet, "/api/v1/snapshot", p)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked bob must get 401, got %d %s", r2.StatusCode, b2)
	}

	// list shows the revoked flag
	for _, sub := range listSubscribers(t, ctx) {
		if sub["callsign"] == "bob" {
			if sub["revoked"] != float64(1) {
				t.Fatalf("bob must be flagged revoked, got %v", sub["revoked"])
			}
		}
	}

	// admin can lift the ban
	resp3, b3 := doRevoke(t, ctx, "bob", false)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("unrevoke: %d %s", resp3.StatusCode, b3)
	}
	snapshotMessages(t, ctx, bob, "bob")
}

func TestCRLRevokeRequiresAdmin(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	p := signAs(t, "bob", bob, "revoke_subscriber", map[string]any{"callsign": "admin"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/revoke", p)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin revoke must be 403, got %d", resp.StatusCode)
	}

	// revoking an unknown callsign -> 404
	resp2, _ := doRevoke(t, ctx, "nobody", true)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("revoking unknown callsign must be 404, got %d", resp2.StatusCode)
	}
}

func TestCRLRevokeKicksWS(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	c := wsDial(t, ctx)
	defer c.Close(websocket.StatusGoingAway, "")
	wsHello(t, ctx, c, bob, "bob")
	drainUntilQuiet(t, c)

	resp, _ := doRevoke(t, ctx, "bob", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}

	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := c.Read(rctx); err == nil {
		t.Fatal("revoked subscriber's socket must be closed")
	}
}

// drainUntilQuiet consumes frames until the queue runs dry, so the next Read
// reflects genuine server behaviour rather than leftover buffers.
func drainUntilQuiet(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	for {
		rctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, _, err := conn.Read(rctx)
		cancel()
		if err != nil {
			return
		}
	}
}

func TestJournalExportVerify(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	sendMessageAs(t, ctx, string(ctx.priv), "admin", "bob", "секрет")
	doRevoke(t, ctx, "bob", true)

	// export the journal (admin only, GET)
	p := signPacket(t, ctx, "admin", "journal_export", map[string]any{})
	resp, body := doSigned(t, ctx, http.MethodGet, "/api/v1/journal", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("journal export: %d %s", resp.StatusCode, body)
	}
	var jr struct {
		Head    string            `json:"head"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(body, &jr); err != nil {
		t.Fatal(err)
	}
	if len(jr.Entries) == 0 || jr.Head == "" {
		t.Fatalf("journal must contain entries and a head: %s", body)
	}

	// verify (admin only, POST)
	pv := signPacket(t, ctx, "admin", "journal_verify", map[string]any{})
	resp2, b2 := doSigned(t, ctx, http.MethodPost, "/api/v1/journal/verify", pv)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("journal verify: %d %s", resp2.StatusCode, b2)
	}
	var vr struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(b2, &vr); err != nil || !vr.OK {
		t.Fatalf("journal must verify OK: %s", b2)
	}

	// non-admin cannot read the journal
	pb := signAs(t, "bob", bob, "journal_export", map[string]any{})
	resp3, _ := doSigned(t, ctx, http.MethodGet, "/api/v1/journal", pb)
	if resp3.StatusCode != http.StatusForbidden && resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin journal read must fail, got %d", resp3.StatusCode)
	}
}

func TestJournalSystemEntriesNotBacklogged(t *testing.T) {
	ctx := setup(t)
	register(t, ctx, "bob", "operator")

	doRevoke(t, ctx, "bob", true)

	// the revoke action is journaled for the audit trail...
	p := signPacket(t, ctx, "admin", "journal_export", map[string]any{})
	resp, body := doSigned(t, ctx, http.MethodGet, "/api/v1/journal", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("journal export: %d", resp.StatusCode)
	}
	var jr struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(body, &jr); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range jr.Entries {
		if e["kind"] == "revoke_subscriber" {
			found = true
			if e["recipient"] != "@system" {
				t.Fatalf("revoke journal must use @system recipient, got %v", e["recipient"])
			}
		}
	}
	if !found {
		t.Fatal("revoke must be present in the journal")
	}

	// ...but is NOT re-delivered as store-and-forward backlog to subscribers:
	// the per-client backlog filter scopes to the caller's own recipient matches.
	undelivered, err := ctx.st.UndeliveredPacketsFor(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range undelivered {
		if p.Kind == "revoke_subscriber" {
			t.Fatalf("system entries must not be replayed via backlog: %+v", p)
		}
	}
}
