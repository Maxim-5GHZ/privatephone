package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminCreatesSubscriber(t *testing.T) {
	ctx := setup(t)

	// admin создаёт юзера сам, через API (без CLI)
	p := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": "bob", "role": "operator"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Subscriber struct {
			Callsign string `json:"callsign"`
			Role     string `json:"role"`
		} `json:"subscriber"`
		Private string `json:"private_pem"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subscriber.Callsign != "bob" || out.Private == "" {
		t.Fatalf("bad create response: %s", b)
	}

	// новый юзер виден в списке и может работать (snapshot)
	bobPriv := register(t, ctx, "carol", "operator")
	_ = bobPriv
	msgs := snapshotMessages(t, ctx, out.Private, "bob")
	_ = msgs
}

func TestAdminCreateNormalizesCallsign(t *testing.T) {
	ctx := setup(t)

	// "  BoB " -> "bob"
	p := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": "  BoB ", "role": "operator"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("normalize create: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Subscriber struct {
			Callsign string `json:"callsign"`
		} `json:"subscriber"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subscriber.Callsign != "bob" {
		t.Fatalf("callsign must normalize to bob, got %q", out.Subscriber.Callsign)
	}

	// повторный "bob" / "BOB" -> 409
	p2 := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": "BOB", "role": "operator"})
	resp2, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", p2)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate must be 409, got %d", resp2.StatusCode)
	}

	// пустой / с пробелами / слишком длинный -> 400
	for _, bad := range []string{"", "   ", "a b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		pb := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": bad, "role": "operator"})
		respB, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", pb)
		if respB.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad callsign %q must be 400, got %d", bad, respB.StatusCode)
		}
	}
}

func TestAdminKeyIssuedOnce(t *testing.T) {
	ctx := setup(t)

	// Приватный ключ выдаётся ровно один раз — в ответе на создание.
	p := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": "bob", "role": "operator"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var created struct {
		Private string `json:"private_pem"`
	}
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	if created.Private == "" {
		t.Fatalf("create must issue the private key once: %s", b)
	}

	// В списке нет ни escrow-флага, ни приватного материала.
	pList := signPacket(t, ctx, "admin", "list_subscribers", map[string]any{})
	respL, bL := doSigned(t, ctx, http.MethodGet, "/api/v1/subscribers", pList)
	if respL.StatusCode != 200 {
		t.Fatalf("list: %d %s", respL.StatusCode, bL)
	}
	var ls struct {
		Subscribers []map[string]any `json:"subscribers"`
	}
	if err := json.Unmarshal(bL, &ls); err != nil {
		t.Fatal(err)
	}
	for _, s := range ls.Subscribers {
		if _, ok := s["has_key"]; ok {
			t.Fatalf("no escrow flag may be exposed: %v", s)
		}
	}
	if containsStr(string(bL), "PRIVATE KEY") {
		t.Fatal("subscriber list must not leak private keys")
	}

	// Ручка перевыпуска удалена: прошлого ключа на сервере нет.
	pk := signPacket(t, ctx, "admin", "get_subscriber_key", map[string]any{"callsign": "bob"})
	respK, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers/key", pk)
	if respK.StatusCode != http.StatusNotFound {
		t.Fatalf("reissue endpoint must be gone (404), got %d", respK.StatusCode)
	}

	// Процедура при утере флешки: revoke старого + выпуск нового позывного.
	doRevoke(t, ctx, "bob", true)
	p2 := signPacket(t, ctx, "admin", "create_subscriber", map[string]any{"callsign": "bob2", "role": "operator"})
	resp2, b2 := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers", p2)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("replacement create: %d %s", resp2.StatusCode, b2)
	}
	var created2 struct {
		Private string `json:"private_pem"`
	}
	if err := json.Unmarshal(b2, &created2); err != nil {
		t.Fatal(err)
	}
	if created2.Private == "" || created2.Private == created.Private {
		t.Fatal("replacement must get a fresh private key")
	}
	msgs := snapshotMessages(t, ctx, created2.Private, "bob2")
	_ = msgs
}

func containsStr(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
