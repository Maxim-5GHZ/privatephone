package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// ErrNotFound marks a missing row.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is mapped for UNIQUE constraint conflicts.
var ErrDuplicate = errors.New("duplicate")

// ErrRevoked marks a subscriber whose credentials were revoked (CRL).
var ErrRevoked = errors.New("revoked")

type Subscriber struct {
	ID       string `json:"id"`
	Callsign string `json:"callsign"`
	Role     string `json:"role"`
	PubKey   string `json:"pubkey"`
	Revoked  int64  `json:"revoked"`
}

type Marker struct {
	ID       int64   `json:"id"`
	Sender   string  `json:"sender"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Type     string  `json:"type"`
	Descr    string  `json:"desc"`
	Nonce    string  `json:"n"`
	Created  string  `json:"created_at"`
	Inactive int64   `json:"inactive"`
}

// Alert is an active engagement alarm (SOS/сбор) broadcast to everyone.
// Clear state is carried as cleared_*; Acks are filled by ListActiveAlerts.
type Alert struct {
	ID        int64    `json:"id"`
	Sender    string   `json:"sender"`
	Type      string   `json:"type"`
	Text      string   `json:"text,omitempty"`
	Lat       float64  `json:"lat,omitempty"`
	Lon       float64  `json:"lon,omitempty"`
	Nonce     string   `json:"n"`
	Created   string   `json:"created_at"`
	ClearedBy string   `json:"cleared_by,omitempty"`
	ClearedAt string   `json:"cleared_at,omitempty"`
	Acks      []string `json:"acks"`
}

// Zone is a shared polygon (danger/collection area) drawn on the map by anyone.
// Points holds the raw JSON string "[[lat,lon],...]".
type Zone struct {
	ID       int64  `json:"id"`
	Sender   string `json:"sender"`
	Name     string `json:"name"`
	Color    string `json:"color"`
	Points   string `json:"points"`
	Nonce    string `json:"n"`
	Created  string `json:"created_at"`
	Inactive int64  `json:"inactive"`
}

type Message struct {
	ID        int64  `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Body      string `json:"body"`
	Nonce     string `json:"n"`
	Created   string `json:"created_at"`
	// Edited is 1 when the author changed the body via message_update.
	Edited int64 `json:"edited,omitempty"`
}

// File is one E2EE file/voice attachment. The node stores both parts opaque:
// Blob is base64(AES-GCM(fileKey, bytes)), Enc is the e2ee v2 envelope JSON
// wrapping fileKey (+name/mime/size) per recipient. Journal payload carries
// the same fields, so sneaker-net bags replicate files like messages.
type File struct {
	ID        int64  `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Name      string `json:"name"`
	Mime      string `json:"mime"`
	Size      int64  `json:"size"`
	// Blob is base64 ciphertext; empty in snapshot metadata (fetch on demand).
	Blob    string `json:"blob,omitempty"`
	Enc     string `json:"enc"`
	Nonce   string `json:"n"`
	Created string `json:"created_at"`
}

// Chat is a named group channel created by an admin. Members is a JSON array
// of callsigns, e.g. ["alice","bob"]. Messages addressed to the chat use
// recipient "chat:<id>" and are visible only to members (plus admin).
type Chat struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Creator string   `json:"creator"`
	Created string   `json:"created_at"`
}

type Packet struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Kind      string `json:"kind"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Nonce     string `json:"nonce"`
	TS        int64  `json:"ts"`
	Recipient string `json:"recipient"`
	PrevHash  string `json:"prev_hash"`
}

// JournalEntry is one row of the tamper-evident packet journal, chained via
// prev_hash over the strictly monotonic insertion order (rowid).
type JournalEntry struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Kind      string `json:"kind"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Nonce     string `json:"nonce"`
	TS        int64  `json:"ts"`
	Recipient string `json:"recipient"`
	PrevHash  string `json:"prev_hash"`
	RecvAt    string `json:"recv_at"`
}

func (s *Store) AddSubscriber(ctx context.Context, id, callsign, role, pubkey string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subscribers (id, callsign, role, pubkey) VALUES (?, ?, ?, ?)`,
		id, callsign, role, pubkey)
	if err != nil {
		if isUniqueViolation(err) {
			return errors.Join(ErrDuplicate, err)
		}
		return err
	}
	s.markDirty()
	return nil
}

func (s *Store) SubscriberByCallsign(ctx context.Context, callsign string) (*Subscriber, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, callsign, role, pubkey, revoked FROM subscribers WHERE callsign = ?`, callsign)
	sub := &Subscriber{}
	err := row.Scan(&sub.ID, &sub.Callsign, &sub.Role, &sub.PubKey, &sub.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *Store) ListSubscribers(ctx context.Context) ([]Subscriber, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, callsign, role, pubkey, revoked, created_at FROM subscribers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subscriber
	for rows.Next() {
		var sub Subscriber
		var created string
		if err := rows.Scan(&sub.ID, &sub.Callsign, &sub.Role, &sub.PubKey, &sub.Revoked, &created); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// RevokeSubscriber bans a callsign: the verifier stops accepting its signature
// and any open connection is kicked.
func (s *Store) RevokeSubscriber(ctx context.Context, callsign string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE subscribers SET revoked = 1 WHERE callsign = ?`, callsign)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

// UnrevokeSubscriber lifts a revocation (admin mistake recovery).
func (s *Store) UnrevokeSubscriber(ctx context.Context, callsign string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE subscribers SET revoked = 0 WHERE callsign = ?`, callsign)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

func (s *Store) AddMarker(ctx context.Context, sender string, lat, lon float64, mtype, desc, nonce string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO markers (sender, lat, lon, mtype, descr, n) VALUES (?, ?, ?, ?, ?, ?)`,
		sender, lat, lon, mtype, desc, nonce)
	if err != nil {
		return 0, err
	}
	s.markDirty()
	return res.LastInsertId()
}

// MarkerByNonce finds a marker by its original signed nonce (unique per sender).
func (s *Store) MarkerByNonce(ctx context.Context, sender, nonce string) (*Marker, error) {
	if nonce == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sender, lat, lon, mtype, descr, n, created_at, inactive FROM markers WHERE sender = ? AND n = ?`, sender, nonce)
	m := &Marker{}
	err := row.Scan(&m.ID, &m.Sender, &m.Lat, &m.Lon, &m.Type, &m.Descr, &m.Nonce, &m.Created, &m.Inactive)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) MarkerByID(ctx context.Context, id int64) (*Marker, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sender, lat, lon, mtype, descr, n, created_at, inactive FROM markers WHERE id = ?`, id)
	m := &Marker{}
	err := row.Scan(&m.ID, &m.Sender, &m.Lat, &m.Lon, &m.Type, &m.Descr, &m.Nonce, &m.Created, &m.Inactive)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateMarkerText edits the type/description of an existing (active) marker.
func (s *Store) UpdateMarkerText(ctx context.Context, id int64, mtype, desc string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE markers SET mtype = ?, descr = ? WHERE id = ? AND inactive = 0`, mtype, desc, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

// DeactivateMarker soft-deletes a marker (keeps provenance, hides from everyone).
func (s *Store) DeactivateMarker(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE markers SET inactive = 1 WHERE id = ? AND inactive = 0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

func (s *Store) ListMarkers(ctx context.Context) ([]Marker, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, lat, lon, mtype, descr, n, created_at, inactive FROM markers WHERE inactive = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Marker
	for rows.Next() {
		var m Marker
		if err := rows.Scan(&m.ID, &m.Sender, &m.Lat, &m.Lon, &m.Type, &m.Descr, &m.Nonce, &m.Created, &m.Inactive); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) AddAlert(ctx context.Context, sender, atype, text string, lat, lon float64, nonce string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO alerts (sender, type, text, lat, lon, n) VALUES (?, ?, ?, ?, ?, ?)`,
		sender, atype, text, lat, lon, nonce)
	if err != nil {
		return 0, err
	}
	s.markDirty()
	return res.LastInsertId()
}

// AlertByNonce finds an active alert by its original signed nonce (unique per author).
func (s *Store) AlertByNonce(ctx context.Context, sender, nonce string) (*Alert, error) {
	if nonce == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sender, type, text, lat, lon, n, created_at, cleared_by, cleared_at FROM alerts WHERE sender = ? AND n = ? AND cleared_at IS NULL`,
		sender, nonce)
	a := &Alert{}
	var cby, cat sql.NullString
	err := row.Scan(&a.ID, &a.Sender, &a.Type, &a.Text, &a.Lat, &a.Lon, &a.Nonce, &a.Created, &cby, &cat)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Acks = []string{}
	return a, nil
}

func (s *Store) AckAlert(ctx context.Context, alertID int64, sender string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO alerts_acks (alert_id, sender) VALUES (?, ?)`, alertID, sender)
	if err != nil {
		return err
	}
	s.markDirty()
	return nil
}

func (s *Store) AlertAcks(ctx context.Context, alertID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sender FROM alerts_acks WHERE alert_id = ? ORDER BY rowid`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClearAlert marks an active alert as cleared by `by`.
func (s *Store) ClearAlert(ctx context.Context, id int64, by string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET cleared_by = ?, cleared_at = datetime('now') WHERE id = ? AND cleared_at IS NULL`, by, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

// ListActiveAlerts returns live alerts with their acks filled in.
func (s *Store) ListActiveAlerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, type, text, lat, lon, n, created_at FROM alerts WHERE cleared_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.Sender, &a.Type, &a.Text, &a.Lat, &a.Lon, &a.Nonce, &a.Created); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		acks, err := s.AlertAcks(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Acks = acks
	}
	return out, nil
}

func (s *Store) AddZone(ctx context.Context, sender, name, color, points, nonce string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO zones (sender, name, color, points, n) VALUES (?, ?, ?, ?, ?)`,
		sender, name, color, points, nonce)
	if err != nil {
		return 0, err
	}
	s.markDirty()
	return res.LastInsertId()
}

func (s *Store) ZoneByNonce(ctx context.Context, sender, nonce string) (*Zone, error) {
	if nonce == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT id, sender, name, color, points, n, created_at, inactive FROM zones WHERE sender = ? AND n = ? AND inactive = 0`, sender, nonce)
	z := &Zone{}
	err := row.Scan(&z.ID, &z.Sender, &z.Name, &z.Color, &z.Points, &z.Nonce, &z.Created, &z.Inactive)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return z, nil
}

// UpdateZoneText renames/recolours an existing active zone by its author.
func (s *Store) UpdateZoneText(ctx context.Context, id int64, name, color string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE zones SET name = ?, color = ? WHERE id = ? AND inactive = 0`, name, color, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

func (s *Store) DeactivateZone(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE zones SET inactive = 1 WHERE id = ? AND inactive = 0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

func (s *Store) ListZones(ctx context.Context) ([]Zone, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, name, color, points, n, created_at, inactive FROM zones WHERE inactive = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Zone
	for rows.Next() {
		var z Zone
		if err := rows.Scan(&z.ID, &z.Sender, &z.Name, &z.Color, &z.Points, &z.Nonce, &z.Created, &z.Inactive); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// recipientMaybe is a SQL prefilter for group recipients (stored as a JSON
// array like ["bob","admin"]). LIKE metacharacters in the callsign are
// escaped so the prefilter stays tight; exact membership is enforced in Go by
// visibleTo, because a substring match would also hit ["bobby"] for "bob".
func recipientMaybe(callsign string) string {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return `%"` + esc.Replace(callsign) + `"%`
}

// visibleTo reports whether a stored row is really addressed to callsign.
// The SQL LIKE prefilter above is not exact: callsigns are free-form, so
// LIKE wildcards inside them ("_" or "%") would match foreign groups.
// The exact check happens here: broadcast, own sends, direct address, exact
// JSON-array membership, or a named chat the caller belongs to.
func visibleTo(sender, recipient, callsign string, chats map[string]bool) bool {
	if recipient == "" || sender == callsign || recipient == callsign {
		return true
	}
	if chats[recipient] {
		return true
	}
	if strings.HasPrefix(recipient, "[") {
		var members []string
		if err := json.Unmarshal([]byte(recipient), &members); err != nil {
			return false
		}
		for _, m := range members {
			if m == callsign {
				return true
			}
		}
	}
	return false
}

func (s *Store) AddMessage(ctx context.Context, sender, recipient, body, nonce string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO messages (sender, recipient, body, n) VALUES (?, ?, ?, ?)`,
		sender, recipient, body, nonce)
	if err != nil {
		return 0, err
	}
	s.markDirty()
	return res.LastInsertId()
}

func (s *Store) ListMessages(ctx context.Context) ([]Message, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, recipient, body, n, created_at, edited FROM messages ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Sender, &m.Recipient, &m.Body, &m.Nonce, &m.Created, &m.Edited); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListMessagesFor returns only the messages the caller may see: broadcast,
// direct/group addressed to them, messages in named chats they belong to,
// or their own sends.
func (s *Store) ListMessagesFor(ctx context.Context, callsign string) ([]Message, error) {
	chatRecipients, err := s.chatRecipientsFor(ctx, callsign)
	if err != nil {
		return nil, err
	}
	query := `SELECT id, sender, recipient, body, n, created_at, edited FROM messages
		 WHERE recipient = '' OR sender = ? OR recipient = ? OR recipient LIKE ? ESCAPE '\'`
	args := []any{callsign, callsign, recipientMaybe(callsign)}
	if len(chatRecipients) > 0 {
		placeholders := make([]string, len(chatRecipients))
		for i, r := range chatRecipients {
			placeholders[i] = "?"
			args = append(args, r)
		}
		query += ` OR recipient IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chats := make(map[string]bool, len(chatRecipients))
	for _, r := range chatRecipients {
		chats[r] = true
	}
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Sender, &m.Recipient, &m.Body, &m.Nonce, &m.Created, &m.Edited); err != nil {
			return nil, err
		}
		if !visibleTo(m.Sender, m.Recipient, callsign, chats) {
			continue
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListMessagesPaged returns messages visible to callsign older than beforeID
// (0 = latest), newest-first, capped at limit (clamped 1..200). Powers the
// "load older history" endpoint; the live snapshot carries the newest slice.
func (s *Store) ListMessagesPaged(ctx context.Context, callsign string, beforeID int64, limit int) ([]Message, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	chatRecipients, err := s.chatRecipientsFor(ctx, callsign)
	if err != nil {
		return nil, false, err
	}
	query := `SELECT id, sender, recipient, body, n, created_at, edited FROM messages
		 WHERE (recipient = '' OR sender = ? OR recipient = ? OR recipient LIKE ? ESCAPE '\'`
	args := []any{callsign, callsign, recipientMaybe(callsign)}
	if len(chatRecipients) > 0 {
		placeholders := make([]string, len(chatRecipients))
		for i, r := range chatRecipients {
			placeholders[i] = "?"
			args = append(args, r)
		}
		query += ` OR recipient IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += `)`
	if beforeID > 0 {
		query += ` AND id < ?`
		args = append(args, beforeID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	chats := make(map[string]bool, len(chatRecipients))
	for _, r := range chatRecipients {
		chats[r] = true
	}
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Sender, &m.Recipient, &m.Body, &m.Nonce, &m.Created, &m.Edited); err != nil {
			return nil, false, err
		}
		if !visibleTo(m.Sender, m.Recipient, callsign, chats) {
			continue
		}
		// oldest-first for the UI list
		out = append([]Message{m}, out...)
	}
	more := len(out) > limit
	if more {
		out = out[len(out)-limit:]
	}
	return out, more, rows.Err()
}

// MessageByNonce fetches one message by author + creation nonce (edit/delete
// addressing; the envelope `n` is always fresh, like markers/zones).
func (s *Store) MessageByNonce(ctx context.Context, sender, nonce string) (Message, error) {
	var m Message
	err := s.db.QueryRowContext(ctx,
		`SELECT id, sender, recipient, body, n, created_at, edited FROM messages WHERE sender = ? AND n = ?`,
		sender, nonce).Scan(&m.ID, &m.Sender, &m.Recipient, &m.Body, &m.Nonce, &m.Created, &m.Edited)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// UpdateMessageBody replaces the body and marks the row edited.
func (s *Store) UpdateMessageBody(ctx context.Context, id int64, body string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE messages SET body = ?, edited = 1 WHERE id = ?`, body, id)
	if err == nil {
		s.markDirty()
	}
	return err
}

// DeleteMessage removes the row (the signed journal packet stays for audit).
func (s *Store) DeleteMessage(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, id)
	if err == nil {
		s.markDirty()
	}
	return err
}

// AddFile stores one E2EE file record (blob + key envelope opaque).
func (s *Store) AddFile(ctx context.Context, sender, recipient, name, mime string, size int64, blob, enc, nonce string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO files (sender, recipient, name, mime, size, blob, enc, n) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sender, recipient, name, mime, size, blob, enc, nonce)
	if err != nil {
		return 0, err
	}
	s.markDirty()
	return res.LastInsertId()
}

// FileByNonce fetches one file by author + creation nonce.
func (s *Store) FileByNonce(ctx context.Context, sender, nonce string) (File, error) {
	var f File
	err := s.db.QueryRowContext(ctx,
		`SELECT id, sender, recipient, name, mime, size, blob, enc, n, created_at FROM files WHERE sender = ? AND n = ?`,
		sender, nonce).Scan(&f.ID, &f.Sender, &f.Recipient, &f.Name, &f.Mime, &f.Size, &f.Blob, &f.Enc, &f.Nonce, &f.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

// fileVisible reuses the message visibility rules (files ride the same
// recipient addressing: broadcast / direct / group / named chat).
func fileVisible(sender, recipient, callsign string, chats map[string]bool) bool {
	return visibleTo(sender, recipient, callsign, chats)
}

// ListFilesFor returns file records visible to callsign. Blobs are stripped
// (metadata only) — fetch the bytes on demand via FileByNonce.
func (s *Store) ListFilesFor(ctx context.Context, callsign string) ([]File, error) {
	chatRecipients, err := s.chatRecipientsFor(ctx, callsign)
	if err != nil {
		return nil, err
	}
	query := `SELECT id, sender, recipient, name, mime, size, enc, n, created_at FROM files
		 WHERE recipient = '' OR sender = ? OR recipient = ? OR recipient LIKE ? ESCAPE '\'`
	args := []any{callsign, callsign, recipientMaybe(callsign)}
	if len(chatRecipients) > 0 {
		placeholders := make([]string, len(chatRecipients))
		for i, r := range chatRecipients {
			placeholders[i] = "?"
			args = append(args, r)
		}
		query += ` OR recipient IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chats := make(map[string]bool, len(chatRecipients))
	for _, r := range chatRecipients {
		chats[r] = true
	}
	var out []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.Sender, &f.Recipient, &f.Name, &f.Mime, &f.Size, &f.Enc, &f.Nonce, &f.Created); err != nil {
			return nil, err
		}
		if !fileVisible(f.Sender, f.Recipient, callsign, chats) {
			continue
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// PacketID derives the deterministic journal id from the signed-unique tuple.
// Re-importing the same signed packet (sneaker-net) therefore deduplicates.
func PacketID(sender, kind, nonce string, ts int64) string {
	sum := sha256.Sum256([]byte("pp-packet-v1\x00" + sender + "\x00" + kind + "\x00" + nonce + "\x00" + strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(sum[:16])
}

// chainHash is the hash that binds packet rows in insertion order. Each row
// stores the hash of the previous row in prev_hash; the row's own value is the
// hash over (prev_hash, row fields). Empty prev_hash marks the genesis row.
func chainHash(prevHash, id, sender, kind string, ts int64, nonce, recipient, signature, payload string) string {
	joined := strings.Join([]string{
		prevHash, id, sender, kind, strconv.FormatInt(ts, 10), nonce, recipient, signature, payload,
	}, "\x00")
	sum := sha256.Sum256([]byte("pp-journal-v1\x00" + joined))
	return hex.EncodeToString(sum[:])
}

// AddPacket appends a signed packet to the tamper-evident journal, computing
// its chain hash transactionally so concurrent writers cannot interleave.
func (s *Store) AddPacket(ctx context.Context, id, sender, kind, payload, signature, nonce, recipient string, ts int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	prev, err := chainHeadOf(tx, ctx)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO packets (id, sender, kind, payload, signature, nonce, recipient, ts, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, sender, kind, payload, signature, nonce, recipient, ts, prev)
	if err != nil {
		_ = tx.Rollback()
		if isUniqueViolation(err) {
			return errors.Join(ErrDuplicate, err)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.markDirty()
	return nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// chainHeadOf reads the last row and returns its chain value (the hash over
// it). Empty when the journal is empty.
func chainHeadOf(q queryer, ctx context.Context) (string, error) {
	row := q.QueryRowContext(ctx,
		`SELECT id, sender, kind, payload, signature, nonce, recipient, ts, prev_hash FROM packets ORDER BY rowid DESC LIMIT 1`)
	var id, sender, kind, payload, signature, nonce, recipient, prev string
	var ts int64
	err := row.Scan(&id, &sender, &kind, &payload, &signature, &nonce, &recipient, &ts, &prev)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return chainHash(prev, id, sender, kind, ts, nonce, recipient, signature, payload), nil
}

// JournalHead returns the chain value of the most recently appended packet.
func (s *Store) JournalHead(ctx context.Context) (string, error) {
	return chainHeadOf(s.db, ctx)
}

// ListJournal returns ordered journal rows (strict insertion order), optionally
// only those with ts >= afterTS. Used for export (sneaker-net) and inspection.
func (s *Store) ListJournal(ctx context.Context, afterTS int64) ([]JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, kind, payload, signature, nonce, recipient, ts, prev_hash, recv_at FROM packets
		 WHERE ts >= ? ORDER BY rowid`, afterTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JournalEntry
	for rows.Next() {
		var e JournalEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Sender, &e.Kind, &e.Payload, &e.Signature, &e.Nonce, &e.Recipient, &ts, &e.PrevHash, &e.RecvAt); err != nil {
			return nil, err
		}
		e.TS = ts
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyJournal recomputes the hash chain over stored rows and reports the
// first index that breaks continuity, or -1 when the chain is intact. The
// returned head is the recomputed chain value of the last row.
func (s *Store) VerifyJournal(ctx context.Context) (badIndex int, head string, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, kind, payload, signature, nonce, recipient, ts, prev_hash FROM packets ORDER BY rowid`)
	if err != nil {
		return -1, "", err
	}
	defer rows.Close()
	var prevValue string // chain value of the previous row (new row's expected prev_hash)
	i := 0
	for rows.Next() {
		var id, sender, kind, payload, signature, nonce, recipient, storedPrev string
		var ts int64
		if err := rows.Scan(&id, &sender, &kind, &payload, &signature, &nonce, &recipient, &ts, &storedPrev); err != nil {
			return -1, "", err
		}
		if storedPrev != prevValue {
			return i, "", nil
		}
		prevValue = chainHash(storedPrev, id, sender, kind, ts, nonce, recipient, signature, payload)
		i++
	}
	return -1, prevValue, rows.Err()
}

// PacketExists reports whether a deterministic packet id is already stored.
// Used by sneaker-net import to deduplicate bags without re-inserting.
func (s *Store) PacketExists(ctx context.Context, id string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM packets WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// JournalCount returns the number of rows in the tamper-evident journal.
func (s *Store) JournalCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM packets`).Scan(&n)
	return n, err
}

// VerifyBag validates the internal hash chain of an exported journal bag
// (entries, strictly in insertion order, as produced by ListJournal). The bag
// may be a full export (first row with empty prev_hash, a source genesis) or a
// suffix export produced with ?after; the first row's prev_hash anchors the
// chain and must be validated separately against the importing node's head.
// It returns the index of the first row whose prev_hash does not match the
// value recomputed from the previous row, or -1 when the bag is consistent.
func VerifyBag(entries []JournalEntry) int {
	if len(entries) == 0 {
		return -1
	}
	prev := entries[0].PrevHash // anchor, checked against the local head by ImportBag
	for i := range entries {
		if entries[i].PrevHash != prev {
			return i
		}
		prev = chainHash(entries[i].PrevHash, entries[i].ID, entries[i].Sender, entries[i].Kind, entries[i].TS, entries[i].Nonce, entries[i].Recipient, entries[i].Signature, entries[i].Payload)
	}
	return -1
}

func (s *Store) UndeliveredPackets(ctx context.Context) ([]Packet, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, sender, kind, payload, signature, nonce, recipient, ts FROM packets WHERE delivered = 0 ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Packet
	for rows.Next() {
		var p Packet
		if err := rows.Scan(&p.ID, &p.Sender, &p.Kind, &p.Payload, &p.Signature, &p.Nonce, &p.Recipient, &p.TS); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UndeliveredPacketsFor limits the store-and-forward backlog to what the caller
// may see: broadcast, addressed to them, their own sends, or named chats they
// belong to.
func (s *Store) UndeliveredPacketsFor(ctx context.Context, callsign string) ([]Packet, error) {
	chatRecipients, err := s.chatRecipientsFor(ctx, callsign)
	if err != nil {
		return nil, err
	}
	query := `SELECT id, sender, kind, payload, signature, nonce, recipient, ts FROM packets
		 WHERE delivered = 0 AND id NOT IN (SELECT packet_id FROM packet_acks WHERE recipient = ?)
		 AND (recipient = '' OR sender = ? OR recipient = ? OR recipient LIKE ? ESCAPE '\'`
	args := []any{callsign, callsign, callsign, recipientMaybe(callsign)}
	if len(chatRecipients) > 0 {
		placeholders := make([]string, len(chatRecipients))
		for i, r := range chatRecipients {
			placeholders[i] = "?"
			args = append(args, r)
		}
		query += ` OR recipient IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += `) ORDER BY ts`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chats := make(map[string]bool, len(chatRecipients))
	for _, r := range chatRecipients {
		chats[r] = true
	}
	var out []Packet
	for rows.Next() {
		var p Packet
		if err := rows.Scan(&p.ID, &p.Sender, &p.Kind, &p.Payload, &p.Signature, &p.Nonce, &p.Recipient, &p.TS); err != nil {
			return nil, err
		}
		if !visibleTo(p.Sender, p.Recipient, callsign, chats) {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkDelivered records a store-and-forward acknowledgment for one recipient.
// Delivery state is per-recipient (packet_acks): one client's ack never wipes
// the backlog of the others. Rows already flagged delivered = 1 by the legacy
// global ack stay consumed for everyone.
func (s *Store) MarkDelivered(ctx context.Context, ids []string, callsign string) error {
	if len(ids) == 0 || callsign == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO packet_acks (packet_id, recipient) VALUES (?, ?)`, id, callsign); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.markDirty()
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// DataDir returns the vault directory (used for runtime tile overrides).
func (s *Store) DataDir() string { return s.dataDir }

// CreateChat persists a named channel created by an admin.
func (s *Store) CreateChat(ctx context.Context, id, name string, members []string, creator string) error {
	raw, _ := json.Marshal(members)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO chats (id, name, members, creator) VALUES (?, ?, ?, ?)`,
		id, name, string(raw), creator)
	if err != nil {
		if isUniqueViolation(err) {
			return errors.Join(ErrDuplicate, err)
		}
		return err
	}
	s.markDirty()
	return nil
}

// ChatByID returns a single chat by id.
func (s *Store) ChatByID(ctx context.Context, id string) (*Chat, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, members, creator, created_at FROM chats WHERE id = ? AND archived = 0`, id)
	var c Chat
	var membersRaw string
	err := row.Scan(&c.ID, &c.Name, &membersRaw, &c.Creator, &c.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(membersRaw), &c.Members)
	if c.Members == nil {
		c.Members = []string{}
	}
	return &c, nil
}

// ListChats returns all active chats (admin view).
func (s *Store) ListChats(ctx context.Context) ([]Chat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, members, creator, created_at FROM chats WHERE archived = 0 ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Chat
	for rows.Next() {
		var c Chat
		var membersRaw string
		if err := rows.Scan(&c.ID, &c.Name, &membersRaw, &c.Creator, &c.Created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(membersRaw), &c.Members)
		if c.Members == nil {
			c.Members = []string{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListChatsFor returns chats visible to callsign (member or creator).
func (s *Store) ListChatsFor(ctx context.Context, callsign string) ([]Chat, error) {
	all, err := s.ListChats(ctx)
	if err != nil {
		return nil, err
	}
	var out []Chat
	for _, c := range all {
		for _, m := range c.Members {
			if m == callsign {
				out = append(out, c)
				break
			}
		}
	}
	return out, nil
}

// chatRecipientsFor returns ["chat:<id>", ...] for chats containing callsign.
func (s *Store) chatRecipientsFor(ctx context.Context, callsign string) ([]string, error) {
	chats, err := s.ListChatsFor(ctx, callsign)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(chats))
	for _, c := range chats {
		out = append(out, "chat:"+c.ID)
	}
	return out, nil
}

// UpdateChat renames a chat and/or replaces its member list.
func (s *Store) UpdateChat(ctx context.Context, id, name string, members []string) (*Chat, error) {
	raw, _ := json.Marshal(members)
	res, err := s.db.ExecContext(ctx,
		`UPDATE chats SET name = ?, members = ? WHERE id = ? AND archived = 0`, name, string(raw), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	s.markDirty()
	return s.ChatByID(ctx, id)
}

// DeleteChat archives a chat (messages stay in the journal for audit).
func (s *Store) DeleteChat(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE chats SET archived = 1 WHERE id = ? AND archived = 0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.markDirty()
	return nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (contains(err.Error(), "UNIQUE constraint failed") ||
		contains(err.Error(), "constraint failed"))
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
