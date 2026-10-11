package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"

	"privatephone/server/internal/db"
)

// Messages are editable/deletable by the author (delete also by admin); the
// address is the creation nonce via `target`, like markers/zones.
func TestMessageEditDelete(t *testing.T) {
	ctx := setup(t)

	post := func(callsign, kind string, body any) (int, []byte) {
		p := signPacket(t, ctx, callsign, kind, body)
		resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", p)
		return resp.StatusCode, b
	}

	if code, b := post("admin", "message", map[string]any{"recipient": "", "body": "исходник", "n": "med1"}); code != http.StatusCreated {
		t.Fatalf("message create: %d %s", code, b)
	}
	code, b := post("admin", "message_update", map[string]any{"target": "med1", "body": "правда"})
	if code != http.StatusOK {
		t.Fatalf("message update: %d %s", code, b)
	}
	var m struct {
		Body   string `json:"body"`
		N      string `json:"n"`
		Edited int64  `json:"edited"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Body != "правда" || m.N != "med1" || m.Edited != 1 {
		t.Fatalf("message not updated in place: %s", b)
	}
	if code, _ := post("admin", "message_update", map[string]any{"target": "nope", "body": "x"}); code != http.StatusForbidden {
		t.Fatalf("ghost target must be 403, got %d", code)
	}
	if code, _ := post("admin", "message_update", map[string]any{"target": "med1", "body": ""}); code != http.StatusForbidden {
		t.Fatalf("empty body must be 403, got %d", code)
	}
	// Another author cannot edit someone else's message: rows are addressed
	// per (sender, nonce), so bob's edit misses admin's row entirely.
	bobPriv := register(t, ctx, "bob", "operator")
	bp := signAs(t, "bob", bobPriv, "message_update", map[string]any{"target": "med1", "body": "подмена"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", bp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign edit must be 403, got %d", resp.StatusCode)
	}
	// Delete by author.
	if code, b := post("admin", "message_delete", map[string]any{"target": "med1"}); code != http.StatusOK {
		t.Fatalf("message delete: %d %s", code, b)
	}
	msgs, err := ctx.st.ListMessages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, mm := range msgs {
		if mm.Nonce == "med1" {
			t.Fatalf("message row survived delete")
		}
	}
}

// Files ride E2EE opaque (blob + key envelope), replicate via the journal and
// are listed/downloaded with the same visibility rules as messages.
func TestFileUploadDownload(t *testing.T) {
	ctx := setup(t)

	blob := "QUJD" // base64("ABC") — node never decrypts, only stores opaque
	code, b := func() (int, []byte) {
		p := signPacket(t, ctx, "admin", "file", map[string]any{
			"recipient": "bob", "name": "план.png", "mime": "image/png",
			"size": 3, "blob": blob, "n": "file1",
			"enc": map[string]any{"v": 2, "alg": "A256GCM"},
		})
		resp, bb := doSigned(t, ctx, http.MethodPost, "/api/v1/files", p)
		return resp.StatusCode, bb
	}()
	if code != http.StatusCreated {
		t.Fatalf("file upload: %d %s", code, b)
	}
	var f struct {
		Name  string `json:"name"`
		Blob  string `json:"blob"`
		N     string `json:"n"`
		Mime  string `json:"mime"`
		Enc   string `json:"enc"`
		Size  int64  `json:"size"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Blob != blob || f.N != "file1" || f.Mime != "image/png" {
		t.Fatalf("file not stored opaque: %s", b)
	}
	// No envelope, no file.
	p := signPacket(t, ctx, "admin", "file", map[string]any{"recipient": "bob", "name": "x", "blob": blob, "n": "file2"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/files", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext file must be 400, got %d", resp.StatusCode)
	}
	// Download by address.
	gp := signPacket(t, ctx, "admin", "file_get", "")
	resp, gb := doSigned(t, ctx, http.MethodGet, "/api/v1/files?sender=admin&n=file1", gp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("file download: %d %s", resp.StatusCode, gb)
	}
	var dl struct {
		Blob string `json:"blob"`
	}
	if err := json.Unmarshal(gb, &dl); err != nil {
		t.Fatal(err)
	}
	if dl.Blob != blob {
		t.Fatalf("file bytes changed in transit")
	}
	// Missing params, ghost file, and foreign recipient are rejected.
	for _, tc := range []struct {
		name, query string
		want        int
	}{
		{"no params", "", http.StatusBadRequest},
		{"ghost", "?sender=admin&n=nope", http.StatusNotFound},
	} {
		gp := signPacket(t, ctx, "admin", "file_get", "")
		resp, _ := doSigned(t, ctx, http.MethodGet, "/api/v1/files"+tc.query, gp)
		if resp.StatusCode != tc.want {
			t.Fatalf("file %s: want %d got %d", tc.name, tc.want, resp.StatusCode)
		}
	}
	// carol is not a recipient of the bob-addressed file.
	carolPriv := register(t, ctx, "carol", "operator")
	cp := signAs(t, "carol", carolPriv, "file_get", "")
	resp, _ = doSigned(t, ctx, http.MethodGet, "/api/v1/files?sender=admin&n=file1", cp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign file download must be 403, got %d", resp.StatusCode)
	}
}

// History pages older visible messages; the snapshot carries only the newest.
func TestMessageHistory(t *testing.T) {
	ctx := setup(t)

	bodies := []string{"раз", "два", "три"}
	for i, body := range bodies {
		p := signPacket(t, ctx, "admin", "message", map[string]any{"recipient": "", "body": body, "n": string(rune('a' + i))})
		resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", p)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("message %d: %d %s", i, resp.StatusCode, b)
		}
	}
	gp := signPacket(t, ctx, "admin", "history", "")
	resp, gb := doSigned(t, ctx, http.MethodGet, "/api/v1/messages?limit=2", gp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("history: %d %s", resp.StatusCode, gb)
	}
	var out struct {
		Messages []struct {
			Body string `json:"body"`
			ID   int64  `json:"id"`
		} `json:"messages"`
		More bool `json:"more"`
	}
	if err := json.Unmarshal(gb, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 2 || !out.More {
		t.Fatalf("history page: %+v", out)
	}
	if out.Messages[0].Body != "два" || out.Messages[1].Body != "три" {
		t.Fatalf("history order: %+v", out.Messages)
	}
	// Second page before the first id of this page.
	gp2 := signPacket(t, ctx, "admin", "history", "")
	resp, gb2 := doSigned(t, ctx, http.MethodGet, "/api/v1/messages?limit=10&before_id="+strconv.FormatInt(out.Messages[0].ID, 10), gp2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("history page2: %d %s", resp.StatusCode, gb2)
	}
	var out2 struct {
		Messages []struct {
			Body string `json:"body"`
		} `json:"messages"`
		More bool `json:"more"`
	}
	if err := json.Unmarshal(gb2, &out2); err != nil {
		t.Fatal(err)
	}
	if len(out2.Messages) != 1 || out2.Messages[0].Body != "раз" || out2.More {
		t.Fatalf("history page2: %+v", out2)
	}
}

// Typing indicators and read receipts relay only to the addressed online
// peer, unjournaled: presence-gated UX hints, never stored or replayed.
func TestEphemeralRelay(t *testing.T) {
	ctx := setup(t)
	alice := register(t, ctx, "alice", "operator")
	bob := register(t, ctx, "bob", "operator")
	carol := register(t, ctx, "carol", "operator")

	cA := wsDial(t, ctx)
	defer cA.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cA, alice, "alice")
	cB := wsDial(t, ctx)
	defer cB.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cB, bob, "bob")
	cC := wsDial(t, ctx)
	defer cC.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cC, carol, "carol")

	// NB: sockets are never read with a bare timeout here (a context-expired
	// Read closes a coder/websocket conn). readUntilKind skips interleaved
	// presence frames; the silence check below runs last on carol's socket,
	// which the test no longer needs afterwards.
	typing := signAs(t, "alice", alice, "typing", map[string]any{"to": "bob"})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(typing)); err != nil {
		t.Fatal(err)
	}
	msg := readUntilKind(t, cB, "typing")
	var f struct {
		Sender string `json:"sender"`
		Data   struct {
			To string `json:"to"`
		} `json:"data"`
	}
	if err := json.Unmarshal(msg, &f); err != nil {
		t.Fatal(err)
	}
	if f.Sender != "alice" || f.Data.To != "bob" {
		t.Fatalf("typing relay: %s", msg)
	}
	// carol's socket must never see the typing frame (leftover presence is
	// fine — only "typing" is a leak). The draining timeout-read closes
	// carol's conn; the test no longer needs it afterwards.
	for {
		rctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, msg, err := cC.Read(rctx)
		cancel()
		if err != nil {
			break
		}
		var f struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(msg, &f) == nil && f.Kind == "typing" {
			t.Fatalf("typing must not leak to carol: %s", msg)
		}
	}

	// read receipt bob -> alice arrives; offline dave gets nothing (no error).
	read := signAs(t, "bob", bob, "message_read", map[string]any{"to": "alice", "n": "m1"})
	if err := cB.Write(context.Background(), websocket.MessageText, frameFrom(read)); err != nil {
		t.Fatal(err)
	}
	rm := readUntilKind(t, cA, "message_read")
	var rf struct {
		Sender string `json:"sender"`
		Data   struct {
			To string `json:"to"`
			N  string `json:"n"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rm, &rf); err != nil {
		t.Fatal(err)
	}
	if rf.Sender != "bob" || rf.Data.To != "alice" || rf.Data.N != "m1" {
		t.Fatalf("read relay: %s", rm)
	}

	// Nothing was journaled for the ephemeral frames.
	msgs, err := ctx.st.ListMessages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("ephemeral frames must not persist: %+v", msgs)
	}

	// Journaled kinds also flow over WS: bob sees alice's live edit and file.
	mp := signAs(t, "alice", alice, "message", map[string]any{"recipient": "bob", "body": "черновик", "n": "wsm1"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", mp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ws-thread message: %d", resp.StatusCode)
	}
	upd := signAs(t, "alice", alice, "message_update", map[string]any{"target": "wsm1", "body": "чистовик"})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(upd)); err != nil {
		t.Fatal(err)
	}
	um := readUntilKind(t, cB, "message_updated")
	var uf struct {
		Data struct {
			Body   string `json:"body"`
			Edited int64  `json:"edited"`
		} `json:"data"`
	}
	if err := json.Unmarshal(um, &uf); err != nil {
		t.Fatal(err)
	}
	if uf.Data.Body != "чистовик" || uf.Data.Edited != 1 {
		t.Fatalf("live update: %s", um)
	}
	wf := signAs(t, "alice", alice, "file", map[string]any{
		"recipient": "bob", "name": "a.bin", "mime": "application/octet-stream",
		"size": 3, "blob": "QUJD", "n": "wsf1",
		"enc": map[string]any{"v": 2, "alg": "A256GCM"},
	})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(wf)); err != nil {
		t.Fatal(err)
	}
	fm := readUntilKind(t, cB, "file")
	var ff struct {
		Data struct {
			Name string `json:"name"`
			Blob string `json:"blob"`
		} `json:"data"`
	}
	if err := json.Unmarshal(fm, &ff); err != nil {
		t.Fatal(err)
	}
	if ff.Data.Name != "a.bin" || ff.Data.Blob != "QUJD" {
		t.Fatalf("live file: %s", fm)
	}
}

// Sneaker-net bags replicate edits, deletes and files: the whole lifecycle
// replays on the importing node from the journal alone.
func TestJournalImportFilesMessages(t *testing.T) {
	ctxA := setup(t)
	bobPriv := register(t, ctxA, "bob", "operator")

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
	post("admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "body": "черновик", "n": "bag1"}, http.StatusCreated)
	post("admin", "", "message_update", "/api/v1/messages", map[string]any{"target": "bag1", "body": "чистовик"}, http.StatusOK)
	post("admin", "", "message", "/api/v1/messages", map[string]any{"recipient": "bob", "body": "лишнее", "n": "bag2"}, http.StatusCreated)
	post("admin", "", "message_delete", "/api/v1/messages", map[string]any{"target": "bag2"}, http.StatusOK)
	post("bob", bobPriv, "file", "/api/v1/files", map[string]any{
		"recipient": "admin", "name": "схема.png", "mime": "image/png",
		"size": 3, "blob": "QUJD", "n": "bagf1",
		"enc": map[string]any{"v": 2, "alg": "A256GCM"},
	}, http.StatusCreated)

	entries := exportBag(t, ctxA)
	stB := provisionNode(t, ctxA, map[string]string{"admin": string(ctxA.priv), "bob": bobPriv})
	rep := importInto(t, stB, entries)
	if rep.Rejected {
		t.Fatalf("import rejected@%d: %s", rep.RejectedAt, rep.RejectedWhy)
	}

	ctx := context.Background()
	m, err := stB.MessageByNonce(ctx, "admin", "bag1")
	if err != nil || m.Body != "чистовик" || m.Edited != 1 {
		t.Fatalf("imported edit: %v %+v", err, m)
	}
	if _, err := stB.MessageByNonce(ctx, "admin", "bag2"); err != db.ErrNotFound {
		t.Fatalf("imported delete must hold, got %v", err)
	}
	f, err := stB.FileByNonce(ctx, "bob", "bagf1")
	if err != nil || f.Blob != "QUJD" || f.Name != "схема.png" {
		t.Fatalf("imported file: %v %+v", err, f)
	}
	if bad, _, err := stB.VerifyJournal(ctx); err != nil || bad >= 0 {
		t.Fatalf("imported journal must verify: bad=%d err=%v", bad, err)
	}
}
