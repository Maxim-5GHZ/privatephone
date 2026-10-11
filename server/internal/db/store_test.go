package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func TestPersistReload(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	key := testKey(t)

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMarker(ctx, "alpha", 55.1, 37.2, "own", "cp", "k1"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPacket(ctx, "k-1", "alpha", "message", `{"n":"k1"}`, "sig", "k1", "bob", 7); err != nil {
		t.Fatal(err)
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatalf("first seal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.db")); err != nil {
		t.Fatalf("vault.db must exist after Persist: %v", err)
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close(ctx)
	m, err := st2.MarkerByNonce(ctx, "alpha", "k1")
	if err != nil || m == nil || m.Descr != "cp" {
		t.Fatalf("reopened store lost the marker: %v %+v", err, m)
	}
	up, err := st2.UndeliveredPackets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 1 || up[0].ID != "k-1" {
		t.Fatalf("reopened store lost the packet: %+v", up)
	}
}

func TestPersistentEveryRunsUntilCancel(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	key := testKey(t)

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st.PersistentEvery(pctx, time.Millisecond)

	if _, err := st.AddMessage(ctx, "alpha", "bob", "m", "k2"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "vault.db")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PersistentEvery did not seal the vault")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMarkerByID(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	id, err := st.AddMarker(ctx, "alpha", 55.1, 37.2, "own", "desc", "mid1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.MarkerByID(ctx, id)
	if err != nil || got == nil || got.Nonce != "mid1" {
		t.Fatalf("MarkerByID: %v %+v", err, got)
	}
	if _, err := st.MarkerByID(ctx, id+99999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing marker must be ErrNotFound, got %v", err)
	}
	if _, err := st.MarkerByNonce(ctx, "alpha", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty nonce must be ErrNotFound, got %v", err)
	}
}

func TestUndeliveredDeliveredFilters(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	mk := func(id, sender, recipient string) string {
		return `{"sender":"` + sender + `","recipient":"` + recipient + `"}`
	}
	add := func(id, sender, recipient string) {
		if err := st.AddPacket(ctx, id, sender, "message", mk(id, sender, recipient), "sig", id, recipient, time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	add("p-broadcast", "alice", "")
	add("p-bob", "alice", "bob")
	add("p-charlie", "alice", "charlie")
	add("p-group", "alice", `["bob","carol"]`)
	add("p-own", "bob", "")
	add("p-carol", "carol", "carol")

	all, err := st.UndeliveredPackets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 {
		t.Fatalf("UndeliveredPackets want 6 got %d", len(all))
	}

	ids := func(ps []Packet) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.ID)
		}
		sort.Strings(out)
		return out
	}
	want := []string{"p-bob", "p-broadcast", "p-group", "p-own"}
	bp, err := st.UndeliveredPacketsFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	got := ids(bp)
	if !equal(got, want) {
		t.Fatalf("bob's backlog: want %v got %v", want, got)
	}

	if err := st.MarkDelivered(ctx, []string{"p-broadcast", "p-charlie", "missing-id"}, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkDelivered(ctx, nil, "bob"); err != nil {
		t.Fatalf("empty ack must be a no-op: %v", err)
	}
	if err := st.MarkDelivered(ctx, []string{"p-broadcast"}, ""); err != nil {
		t.Fatalf("anonymous ack must be a no-op: %v", err)
	}
	bp, err = st.UndeliveredPacketsFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	after := ids(bp)
	if !equal(after, []string{"p-bob", "p-group", "p-own"}) {
		t.Fatalf("after ack want [p-bob p-group p-own] got %v", after)
	}
	// Per-recipient semantics: bob's ack must not wipe carol's backlog.
	cp, err := st.UndeliveredPacketsFor(ctx, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(cp), []string{"p-broadcast", "p-carol", "p-group", "p-own"}; !equal(got, want) {
		t.Fatalf("carol backlog after bob's ack: want %v got %v", want, got)
	}
}

func TestAddPacketDuplicate(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	if err := st.AddPacket(ctx, "dup", "alice", "message", "{}", "sig", "d1", "bob", 1); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPacket(ctx, "dup", "alice", "message", "{}", "sig", "d1", "bob", 1); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate packet id must be ErrDuplicate, got %v", err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRecipientExactMatch guards routing precision. Callsigns are free-form
// (cyrillic allowed, no charset validation), so the SQL LIKE prefilter must
// not decide delivery: "_" and "%" inside a callsign are LIKE wildcards, and
// only the exact Go-side check in visibleTo may admit a row.
func TestRecipientExactMatch(t *testing.T) {
	ctx := context.Background()
	st, err := Open(t.TempDir(), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	addP := func(id, sender, recipient string) {
		if err := st.AddPacket(ctx, id, sender, "message", "{}", "sig", id, recipient, time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	addP("p-bobby-group", "alice", `["bobby"]`)
	addP("p-bob-group", "alice", `["bob"]`)
	addP("p-bob-direct", "alice", "bob")
	// LIKE wildcard trap: "b_b" must not match the group ["bxb"].
	addP("p-bxb-group", "alice", `["bxb"]`)

	ids := func(ps []Packet) []string {
		var out []string
		for _, p := range ps {
			out = append(out, p.ID)
		}
		sort.Strings(out)
		return out
	}
	bp, err := st.UndeliveredPacketsFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(bp), []string{"p-bob-direct", "p-bob-group"}; !equal(got, want) {
		t.Fatalf("bob backlog: want %v got %v", want, got)
	}
	by, err := st.UndeliveredPacketsFor(ctx, "bobby")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(by), []string{"p-bobby-group"}; !equal(got, want) {
		t.Fatalf("bobby backlog: want %v got %v", want, got)
	}
	wild, err := st.UndeliveredPacketsFor(ctx, "b_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(wild) != 0 {
		t.Fatalf("b_b must see nothing (wildcard trap): %+v", wild)
	}

	if _, err := st.AddMessage(ctx, "alice", `["bobby"]`, "{}", "m1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(ctx, "alice", `["bob"]`, "{}", "m2"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMessage(ctx, "alice", `["bxb"]`, "{}", "m3"); err != nil {
		t.Fatal(err)
	}
	msgs, err := st.ListMessagesFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Nonce == "m1" {
			t.Fatalf("bob must not see bobby's group message: %+v", msgs)
		}
	}
	seen := false
	for _, m := range msgs {
		if m.Nonce == "m2" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("bob must see his own group message: %+v", msgs)
	}
	msgsW, err := st.ListMessagesFor(ctx, "b_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgsW) != 0 {
		t.Fatalf("b_b must see nothing (wildcard trap): %+v", msgsW)
	}
}
