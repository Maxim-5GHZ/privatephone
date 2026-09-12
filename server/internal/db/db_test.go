package db

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
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
