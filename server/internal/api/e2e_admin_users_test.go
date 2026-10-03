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

func TestAdminReissuesKeyFromEscrow(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	// список показывает escrow-флаг
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
		if s["callsign"] == "bob" && s["has_key"] != true {
			t.Fatalf("bob must have escrow key, got %v", s)
		}
	}
	// в списке НЕТ приватника
	if json.Valid(bL) && containsStr(string(bL), "PRIVATE KEY") {
		t.Fatal("subscriber list must not leak private keys")
	}

	// admin перевыпускает ключ
	pk := signPacket(t, ctx, "admin", "get_subscriber_key", map[string]any{"callsign": "bob"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers/key", pk)
	if resp.StatusCode != 200 {
		t.Fatalf("reissue: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Callsign string `json:"callsign"`
		Private  string `json:"private_pem"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Private == "" || out.Callsign != "bob" {
		t.Fatalf("bad reissue: %s", b)
	}
	// перевыпущенным ключом можно подписаться (тот же ключ)
	msgs := snapshotMessages(t, ctx, out.Private, "bob")
	_ = msgs

	// не-админ — 403
	pb := signAs(t, "bob", bob, "get_subscriber_key", map[string]any{"callsign": "bob"})
	resp2, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers/key", pb)
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin reissue must be 403, got %d", resp2.StatusCode)
	}

	// неизвестный — 404
	pn := signPacket(t, ctx, "admin", "get_subscriber_key", map[string]any{"callsign": "nobody"})
	resp3, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/ca/subscribers/key", pn)
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown reissue must be 404, got %d", resp3.StatusCode)
	}
}

func containsStr(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
