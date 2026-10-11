package api_test

import (
	"context"
	"net/http"
	"testing"
)

// Overlapping sneaker-net bags must not lose rows: a bag whose prefix is
// already known imports only the new suffix (ImportBag prefix-strip).
func TestJournalImportOverlap(t *testing.T) {
	ctx := context.Background()
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")
	authorContent(t, ctxA, bobPriv)
	entries := exportBag(t, ctxA)

	stB := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	rep := importInto(t, stB, entries)
	if rep.Rejected || rep.AddedJournal != len(entries) {
		t.Fatalf("seed import: rejected=%v added=%d want=%d", rep.Rejected, rep.AddedJournal, len(entries))
	}

	// Exact re-import stays a clean no-op.
	rep = importInto(t, stB, entries)
	if rep.Rejected || rep.AddedJournal != 0 || rep.SkippedDup != len(entries) {
		t.Fatalf("re-import must be all-dup: %+v", rep)
	}

	// One more row on A, then import the whole journal again: the known
	// prefix must be skipped and only the new row added.
	p := signPacket(t, ctxA, "admin", "marker", map[string]any{"lat": 56.0, "lon": 38.0, "type": "own", "n": "extra1"})
	resp, b := doSigned(t, ctxA, http.MethodPost, "/api/v1/markers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("extra marker: %d %s", resp.StatusCode, b)
	}
	entries2 := exportBag(t, ctxA)
	if len(entries2) != len(entries)+1 {
		t.Fatalf("source journal %d rows, want %d", len(entries2), len(entries)+1)
	}
	rep = importInto(t, stB, entries2)
	if rep.Rejected {
		t.Fatalf("overlap import rejected@%d: %s", rep.RejectedAt, rep.RejectedWhy)
	}
	if rep.AddedJournal != 1 {
		t.Fatalf("overlap import added=%d, want 1: %+v", rep.AddedJournal, rep)
	}
	if rep.SkippedDup != len(entries) {
		t.Fatalf("overlap import skippedDup=%d, want %d", rep.SkippedDup, len(entries))
	}

	if bad, _, err := stB.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("imported journal must verify: bad=%d err=%v", bad, err)
	}
	local, _ := stB.ListJournal(ctx, 0)
	if len(local) != len(entries2) {
		t.Fatalf("local journal %d rows, want %d", len(local), len(entries2))
	}
	markers, _ := stB.ListMarkers(ctx)
	found := false
	for _, m := range markers {
		if m.Nonce == "extra1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("overlapping import lost the new marker: %+v", markers)
	}
}
