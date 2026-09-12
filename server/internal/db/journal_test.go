package db

import (
	"context"
	"errors"
	"testing"
)

func seedJournal(t *testing.T, st *Store) {
	t.Helper()
	for i := 0; i < 3; i++ {
		nonce := "n" + string(rune('0'+i))
		if _, err := st.AddMessage(context.Background(), "admin", "bob", "m", nonce); err != nil {
			t.Fatal(err)
		}
		if err := st.AddPacket(context.Background(),
			PacketID("admin", "message", nonce, int64(1000+i)),
			"admin", "message", `{"recipient":"bob","body":"m","n":"`+nonce+`"}`, "sig", nonce, "bob", int64(1000+i)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJournalChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := Open(dir, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	seedJournal(t, st)
	bad, head, err := st.VerifyJournal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != -1 {
		t.Fatalf("intact chain reported bad index %d", bad)
	}
	if head == "" {
		t.Fatal("expected non-empty chain head")
	}

	// tamper with a stored payload; the chain must break at the next row
	if _, err := st.db.ExecContext(ctx, `UPDATE packets SET payload = '{"tampered":true}' WHERE kind = 'message' AND sender = 'admin' AND nonce = 'n1'`); err != nil {
		t.Fatal(err)
	}
	bad, _, _ = st.VerifyJournal(ctx)
	if bad < 0 {
		t.Fatal("tampered chain must be detected")
	}
}

func TestPacketIDDeterministicDedups(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := Open(dir, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(ctx)

	id := PacketID("admin", "message", "n", 1000)
	if id != PacketID("admin", "message", "n", 1000) {
		t.Fatal("packet id not deterministic")
	}
	args := []any{id, "admin", "message", `{}`, "sig", "n", "bob", int64(1000)}
	if err := st.AddPacket(ctx, args[0].(string), args[1].(string), args[2].(string), args[3].(string), args[4].(string), args[5].(string), args[6].(string), args[7].(int64)); err != nil {
		t.Fatal(err)
	}
	err = st.AddPacket(ctx, args[0].(string), args[1].(string), args[2].(string), args[3].(string), args[4].(string), args[5].(string), args[6].(string), args[7].(int64))
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
}

func TestBackfillChainOnReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	key := testKey(t)

	st, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	// Insert a journal row WITHOUT a chain value (simulates a pre-chain vault).
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO packets (id, sender, kind, payload, signature, nonce, ts) VALUES ('legacy1', 'admin', 'message', '{}', 'sig', 'nl', 1000)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO packets (id, sender, kind, payload, signature, nonce, ts) VALUES ('legacy2', 'admin', 'message', '{}', 'sig', 'nl2', 1001)`); err != nil {
		t.Fatal(err)
	}
	if bad, _, _ := st.VerifyJournal(ctx); bad < 0 {
		t.Fatal("un-chained rows must be reported as broken")
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close(ctx)
	bad, _, err := st2.VerifyJournal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bad != -1 {
		t.Fatalf("backfill must chain legacy rows, bad index %d", bad)
	}
}
