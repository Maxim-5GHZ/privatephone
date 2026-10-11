package db

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.AddMarker(ctx, "alpha", 55.1, 37.2, "own", "checkpoint", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected a marker id")
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(dir, key)
	if err != nil {
		t.Fatalf("reopen with same key: %v", err)
	}
	defer st2.Close(ctx)
	markers, err := st2.ListMarkers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(markers) != 1 || markers[0].Sender != "alpha" {
		t.Fatalf("expected 1 marker from alpha, got %+v", markers)
	}
}

func TestVaultWrongKey(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddSubscriber(ctx, "id1", "alpha", "operator", "pk"); err != nil {
		t.Fatal(err)
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	wrong := testKey(t)
	if _, err := Open(dir, wrong); err == nil {
		t.Fatal("wrong master key must fail to open the vault")
	}
}

func TestDuplicateCallsign(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)
	if err := st.AddSubscriber(ctx, "id1", "alpha", "operator", "pk1"); err != nil {
		t.Fatal(err)
	}
	err = st.AddSubscriber(ctx, "id2", "alpha", "admin", "pk2")
	if err == nil || !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestVaultTampered(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	blob := filepath.Join(dir, "vault.db")
	if err := mutateFile(blob); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, key); err == nil {
		t.Fatal("tampered vault must fail to open")
	}
}

func mutateFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	b[len(b)-1] ^= 0xff
	return os.WriteFile(path, b, 0o600)
}

func TestOpenRejectsBadKeyLength(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, []byte("short")); err == nil {
		t.Fatal("a non-32-byte key must be rejected")
	}
}

func TestPersistNoOpPaths(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Persist(ctx); err != nil {
		t.Fatalf("persist before any write must be a no-op, got %v", err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// After a clean Close the store is sealed and clean: Open+Close again takes
	// the finalSeal no-op path (dirty=false, sealed=true).
	st2, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Close(ctx); err != nil {
		t.Fatalf("clean reopen close: %v", err)
	}
}

func TestPersistentEveryCancels(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	st.PersistentEvery(ctx, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	cancel()
	if _, err := st.ListZones(context.Background()); err != nil {
		t.Fatalf("store must stay usable after the persist loop stops: %v", err)
	}
	if err := st.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestEscrowColumnDropped simulates a pre-removal vault that still carries
// subscribers.privkey: reopening must destroy the escrow copies (DROP COLUMN)
// while keeping the subscriber rows themselves intact.
func TestEscrowColumnDropped(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	ctx := context.Background()
	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddSubscriber(ctx, "id1", "bob", "operator", "pub-bob"); err != nil {
		t.Fatal(err)
	}
	// Forge the legacy column as an old binary would have left it.
	if _, err := st.db.Exec(`ALTER TABLE subscribers ADD COLUMN privkey TEXT NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE subscribers SET privkey = 'PRIVATE-ESCROW' WHERE callsign = 'bob'`); err != nil {
		t.Fatal(err)
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
	rows, err := st2.db.Query(`PRAGMA table_info(subscribers)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "privkey" {
			t.Fatal("legacy escrow column must be dropped on open")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sub, err := st2.SubscriberByCallsign(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if sub.PubKey != "pub-bob" || sub.Role != "operator" {
		t.Fatalf("subscriber row must survive escrow removal: %+v", sub)
	}
}
