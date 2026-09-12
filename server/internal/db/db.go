package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	rawName = "vault.raw"
	snapExt = ".snap"
)

// Store is a transparently-encrypted SQLite store. The encrypted blob lives at
// <dataDir>/vault.db; the live plaintext database works off a temp file in RAM
// (/dev/shm when available, for Linux), persisted back as a sealed snapshot.
type Store struct {
	db       *sql.DB
	dataDir  string
	rawPath  string
	tmpDir   string
	key      []byte
	dirty    atomic.Bool
	sealed   atomic.Bool
	mu       sync.Mutex
	migrated bool
}

// plaintextDir picks a RAM-backed location for the working copy when possible.
func plaintextDir(dataDir string) string {
	if runtime.GOOS == "linux" {
		if shm, err := os.Stat("/dev/shm"); err == nil && shm.IsDir() {
			dir := filepath.Join("/dev/shm", "pp-vault")
			if os.MkdirAll(dir, 0o700) == nil {
				return dir
			}
		}
	}
	_ = os.MkdirAll(dataDir, 0o700)
	return dataDir
}

// Open decrypts the vault (or creates an empty one on first run), migrates the
// schema and hands back a working handle. The caller owns key material.
func Open(dataDir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("db: key must be 32 bytes")
	}

	blob := sealPath(dataDir)
	plain, err := unseal(blob, key)
	if err != nil {
		return nil, err
	}

	tmpDir := plaintextDir(dataDir)
	rawPath := filepath.Join(tmpDir, fmt.Sprintf("%s-%d-%s", rawName, os.Getpid(), randSuffix()))
	if len(plain) == 0 {
		if err := os.WriteFile(rawPath, nil, 0o600); err != nil {
			return nil, err
		}
	} else {
		if err := os.WriteFile(rawPath, plain, 0o600); err != nil {
			return nil, err
		}
		clear(plain)
	}

	database, err := sql.Open("sqlite", rawPath)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)

	if err := database.Ping(); err != nil {
		database.Close()
		os.Remove(rawPath)
		return nil, err
	}

	// Keep our own copy so Close() can zero it without clobbering the caller's
	// (the MasterKey owns its buffer and must destroy it itself).
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)

	s := &Store{
		db:      database,
		dataDir: dataDir,
		rawPath: rawPath,
		tmpDir:  tmpDir,
		key:     keyCopy,
	}
	if err := s.migrate(); err != nil {
		database.Close()
		os.Remove(rawPath)
		return nil, err
	}
	return s, nil
}

func randSuffix() string {
	b := [6]byte{}
	_ = b
	t := time.Now().UnixNano()
	return fmt.Sprintf("%x", t&0xffffff)
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS subscribers (
	id         TEXT PRIMARY KEY,
	callsign   TEXT NOT NULL UNIQUE,
	role       TEXT NOT NULL DEFAULT 'operator',
	pubkey     TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribers_callsign ON subscribers(callsign);
CREATE TABLE IF NOT EXISTS markers (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	sender     TEXT NOT NULL,
	lat        REAL NOT NULL,
	lon        REAL NOT NULL,
	mtype      TEXT NOT NULL,
	descr      TEXT,
	n          TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	sender     TEXT NOT NULL,
	recipient  TEXT,
	body       TEXT NOT NULL,
	n          TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS packets (
	id         TEXT PRIMARY KEY,
	sender     TEXT NOT NULL,
	kind       TEXT NOT NULL,
	payload    TEXT NOT NULL,
	signature  TEXT NOT NULL,
	nonce      TEXT NOT NULL,
	ts         INTEGER NOT NULL,
	recv_at    TEXT NOT NULL DEFAULT (datetime('now')),
	delivered  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	sender     TEXT NOT NULL,
	type       TEXT NOT NULL,
	text       TEXT,
	lat        REAL,
	lon        REAL,
	n          TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	cleared_by TEXT,
	cleared_at TEXT
);
CREATE TABLE IF NOT EXISTS alerts_acks (
	alert_id   INTEGER NOT NULL,
	sender     TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	UNIQUE(alert_id, sender)
);
CREATE INDEX IF NOT EXISTS idx_alerts_acks_alert ON alerts_acks(alert_id);
CREATE TABLE IF NOT EXISTS zones (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	sender     TEXT NOT NULL,
	name       TEXT NOT NULL,
	color      TEXT NOT NULL DEFAULT '#3388ff',
	points     TEXT NOT NULL,
	n          TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	inactive   INTEGER NOT NULL DEFAULT 0
);`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := s.ensureColumn("packets", "recipient", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("markers", "inactive", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("packets", "prev_hash", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("subscribers", "revoked", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.backfillRecipient(context.Background()); err != nil {
		return err
	}
	if err := s.backfillChain(context.Background()); err != nil {
		return err
	}
	s.migrated = true
	s.dirty.Store(true)
	return nil
}

// ensureColumn adds a column when it is missing (idempotent migration).
func (s *Store) ensureColumn(table, column, ddl string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("migrate %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl); err != nil {
		return fmt.Errorf("migrate %s.%s: %w", table, column, err)
	}
	return nil
}

// backfillRecipient fills packets.recipient from the payload for pre-existing
// message journals (recipient was previously ignored / not stored).
func (s *Store) backfillRecipient(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, payload FROM packets WHERE recipient = '' AND kind = 'message'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var updates []struct{ id, rec string }
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return err
		}
		var m struct {
			Recipient string `json:"recipient"`
		}
		if err := json.Unmarshal([]byte(payload), &m); err == nil {
			updates = append(updates, struct {
				id  string
				rec string
			}{id, m.Recipient})
		}
	}
	for _, u := range updates {
		if _, err := s.db.ExecContext(ctx, `UPDATE packets SET recipient = ? WHERE id = ?`, u.rec, u.id); err != nil {
			return err
		}
	}
	return rows.Err()
}

// backfillChain builds the tamper-evident hash chain for pre-existing packets
// (idempotent: rows that already carry the correct prev_hash are left intact).
func (s *Store) backfillChain(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, kind, payload, signature, nonce, recipient, ts, prev_hash FROM packets ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type fix struct {
		id   string
		prev string
	}
	var fixes []fix
	var prevValue string // chain value of the previous row
	for rows.Next() {
		var id, sender, kind, payload, signature, nonce, recipient, storedPrev string
		var ts int64
		if err := rows.Scan(&id, &sender, &kind, &payload, &signature, &nonce, &recipient, &ts, &storedPrev); err != nil {
			return err
		}
		if storedPrev != prevValue {
			storedPrev = prevValue
			fixes = append(fixes, fix{id, storedPrev})
		}
		prevValue = chainHash(storedPrev, id, sender, kind, ts, nonce, recipient, signature, payload)
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	for _, f := range fixes {
		if _, err := s.db.ExecContext(ctx, `UPDATE packets SET prev_hash = ? WHERE id = ?`, f.prev, f.id); err != nil {
			return err
		}
	}
	if len(fixes) > 0 {
		s.markDirty()
	}
	return nil
}

// Persist makes a consistent snapshot (VACUUM INTO) and re-seals the vault.
// No-op unless there were writes since the last seal.
func (s *Store) Persist(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.migrated {
		return nil
	}
	if !s.dirty.Load() && s.sealed.Load() {
		return nil
	}

	snap := filepath.Join(s.tmpDir, fmt.Sprintf("%s-%d%s", rawName, os.Getpid(), snapExt))
	_ = os.Remove(snap)
	q := fmt.Sprintf("VACUUM INTO '%s'", sqlEscape(filepath.ToSlash(snap)))
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}

	blob, err := os.ReadFile(snap)
	os.Remove(snap)
	if err != nil {
		return err
	}
	if err := seal(sealPath(s.dataDir), s.key, blob); err != nil {
		clear(blob)
		return err
	}
	clear(blob)
	s.sealed.Store(true)
	s.dirty.Store(false)
	return nil
}

// PersistentEvery runs Persist in a loop until ctx is cancelled.
func (s *Store) PersistentEvery(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := s.Persist(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "persist: %v\n", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Close performs a final persist, removes the plaintext working copy and
// releases the connection. Errors during persist are reported, not fatal.
func (s *Store) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.migrated {
		if err := s.finalSeal(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.db.Close(); err != nil {
		errs = append(errs, err)
	}
	os.Remove(s.rawPath)
	clear(s.key)
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *Store) finalSeal(ctx context.Context) error {
	if !s.dirty.Load() && s.sealed.Load() {
		return nil
	}
	snap := filepath.Join(s.tmpDir, fmt.Sprintf("%s-%d%s", rawName, os.Getpid(), snapExt))
	_ = os.Remove(snap)
	q := fmt.Sprintf("VACUUM INTO '%s'", sqlEscape(filepath.ToSlash(snap)))
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	blob, err := os.ReadFile(snap)
	os.Remove(snap)
	if err != nil {
		return err
	}
	err = seal(sealPath(s.dataDir), s.key, blob)
	clear(blob)
	if err != nil {
		return err
	}
	s.sealed.Store(true)
	s.dirty.Store(false)
	return nil
}

func sqlEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\'' {
			out = append(out, '\'', '\'')
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}

// markDirtySuffix is applied after any writing query.
func (s *Store) markDirty() { s.dirty.Store(true) }
