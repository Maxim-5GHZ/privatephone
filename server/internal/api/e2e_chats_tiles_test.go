package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestChatCreateRequiresAdmin(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	// operator cannot create a chat
	p := signAs(t, "bob", bob, "chat_create", map[string]any{"name": "Штаб", "members": []string{"bob"}})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", p)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin chat_create must be 403, got %d", resp.StatusCode)
	}

	// admin creates
	p2 := signPacket(t, ctx, "admin", "chat_create", map[string]any{"name": "Штаб", "members": []string{"bob"}})
	resp2, b2 := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", p2)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("admin chat_create: %d %s", resp2.StatusCode, b2)
	}
	var chat struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(b2, &chat); err != nil {
		t.Fatal(err)
	}
	if chat.ID == "" || chat.Name != "Штаб" {
		t.Fatalf("bad chat: %s", b2)
	}
	// creator auto-added
	foundAdmin := false
	foundBob := false
	for _, m := range chat.Members {
		if m == "admin" {
			foundAdmin = true
		}
		if m == "bob" {
			foundBob = true
		}
	}
	if !foundAdmin || !foundBob {
		t.Fatalf("members must contain admin+bob, got %v", chat.Members)
	}
}

func TestChatMessagingVisibility(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")
	carol := register(t, ctx, "carol", "operator")

	p := signPacket(t, ctx, "admin", "chat_create", map[string]any{"name": "Группа", "members": []string{"bob"}})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var chat struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &chat); err != nil {
		t.Fatal(err)
	}
	recipient := "chat:" + chat.ID

	// bob (member) sends to chat
	pb := signAs(t, "bob", bob, "message", map[string]any{"recipient": recipient, "body": "привет"})
	resp2, b2 := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", pb)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("member send: %d %s", resp2.StatusCode, b2)
	}

	// member sees it, outsider does not
	msgsBob := snapshotMessages(t, ctx, bob, "bob")
	if !containsRecipient(msgsBob, recipient, "привет") {
		t.Fatalf("bob must see chat message, got %+v", msgsBob)
	}
	msgsCarol := snapshotMessages(t, ctx, carol, "carol")
	if containsRecipient(msgsCarol, recipient, "привет") {
		t.Fatalf("carol must NOT see foreign chat, got %+v", msgsCarol)
	}

	// outsider cannot write to chat
	pc := signAs(t, "carol", carol, "message", map[string]any{"recipient": recipient, "body": "взлом"})
	resp3, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/messages", pc)
	if resp3.StatusCode == http.StatusCreated {
		t.Fatal("non-member must not write to chat")
	}

	// list chats: bob sees, carol does not, admin sees all
	pb2 := signAs(t, "bob", bob, "list_chats", map[string]any{})
	resp4, b4 := doSigned(t, ctx, http.MethodGet, "/api/v1/chats", pb2)
	if resp4.StatusCode != 200 {
		t.Fatalf("list chats bob: %d %s", resp4.StatusCode, b4)
	}
	var lb struct {
		Chats []map[string]any `json:"chats"`
	}
	if err := json.Unmarshal(b4, &lb); err != nil {
		t.Fatal(err)
	}
	if len(lb.Chats) != 1 {
		t.Fatalf("bob must see 1 chat, got %s", b4)
	}
}

func TestChatUpdateDelete(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	p := signPacket(t, ctx, "admin", "chat_create", map[string]any{"name": "Штаб", "members": []string{"bob"}})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var chat struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &chat); err != nil {
		t.Fatal(err)
	}

	// operator cannot update
	po := signAs(t, "bob", bob, "chat_update", map[string]any{"id": chat.ID, "name": "X", "members": []string{"bob"}})
	respO, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", po)
	if respO.StatusCode != http.StatusForbidden {
		t.Fatalf("operator update must be 403, got %d", respO.StatusCode)
	}

	// admin updates
	pu := signPacket(t, ctx, "admin", "chat_update", map[string]any{"id": chat.ID, "name": "Штаб-2", "members": []string{"bob", "admin"}})
	respU, bU := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pu)
	if respU.StatusCode != http.StatusOK {
		t.Fatalf("update: %d %s", respU.StatusCode, bU)
	}
	var upd struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(bU, &upd); err != nil {
		t.Fatal(err)
	}
	if upd.Name != "Штаб-2" {
		t.Fatalf("name not updated: %s", bU)
	}

	// bad update rejected
	pb := signPacket(t, ctx, "admin", "chat_update", map[string]any{"id": chat.ID, "name": "", "members": []string{"bob"}})
	respB, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pb)
	if respB.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty name must be 400, got %d", respB.StatusCode)
	}

	// update ghost → 400 (not found)
	pg := signPacket(t, ctx, "admin", "chat_update", map[string]any{"id": "chat:nope", "name": "N", "members": []string{"bob"}})
	respG, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pg)
	if respG.StatusCode != http.StatusBadRequest {
		t.Fatalf("ghost update must be 400, got %d", respG.StatusCode)
	}

	// operator cannot delete
	pd := signAs(t, "bob", bob, "chat_delete", map[string]any{"id": chat.ID})
	respD, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pd)
	if respD.StatusCode != http.StatusForbidden {
		t.Fatalf("operator delete must be 403, got %d", respD.StatusCode)
	}

	// admin deletes; second delete rejected
	pdel := signPacket(t, ctx, "admin", "chat_delete", map[string]any{"id": chat.ID})
	respDel, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pdel)
	if respDel.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", respDel.StatusCode)
	}
	pdel2 := signPacket(t, ctx, "admin", "chat_delete", map[string]any{"id": chat.ID})
	respDel2, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/chats", pdel2)
	if respDel2.StatusCode != http.StatusBadRequest {
		t.Fatalf("double delete must be 400, got %d", respDel2.StatusCode)
	}
}

func TestTilesPutStatusClear(t *testing.T) {
	ctx := setup(t)
	// 1x1 PNG
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

	p := signPacket(t, ctx, "admin", "tiles_put", map[string]any{"z": 0, "x": 0, "y": 0, "png_b64": pngB64})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("tiles_put: %d %s", resp.StatusCode, b)
	}

	ps := signPacket(t, ctx, "admin", "tiles_status", map[string]any{})
	resp2, b2 := doSigned(t, ctx, http.MethodGet, "/api/v1/admin/tiles/status", ps)
	if resp2.StatusCode != 200 {
		t.Fatalf("tiles status: %d %s", resp2.StatusCode, b2)
	}
	var st struct {
		CustomTiles int `json:"custom_tiles"`
	}
	if err := json.Unmarshal(b2, &st); err != nil {
		t.Fatal(err)
	}
	if st.CustomTiles != 1 {
		t.Fatalf("want 1 custom tile, got %s", b2)
	}

	// non-PNG rejected
	pb := signPacket(t, ctx, "admin", "tiles_put", map[string]any{"z": 0, "x": 0, "y": 0, "png_b64": "aGVsbG8="})
	resp3, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles", pb)
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-PNG must be 400, got %d", resp3.StatusCode)
	}

	// clear
	pc := signPacket(t, ctx, "admin", "tiles_clear", map[string]any{})
	resp4, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles/clear", pc)
	if resp4.StatusCode != 200 {
		t.Fatalf("tiles clear: %d", resp4.StatusCode)
	}
	ps2 := signPacket(t, ctx, "admin", "tiles_status", map[string]any{})
	_, b5 := doSigned(t, ctx, http.MethodGet, "/api/v1/admin/tiles/status", ps2)
	var st2 struct {
		CustomTiles int `json:"custom_tiles"`
	}
	if err := json.Unmarshal(b5, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.CustomTiles != 0 {
		t.Fatalf("after clear want 0, got %s", b5)
	}
}
