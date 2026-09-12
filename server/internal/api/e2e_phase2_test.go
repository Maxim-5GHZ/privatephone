package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"privatephone/server/internal/db"
)

func snapshotPhase2(t *testing.T, ctx *testCtx, priv, callsign string) (zones []db.Zone, alerts []db.Alert) {
	t.Helper()
	p := signAs(t, callsign, priv, "snapshot", map[string]any{})
	resp, body := doSigned(t, ctx, http.MethodGet, "/api/v1/snapshot", p)
	if resp.StatusCode != 200 {
		t.Fatalf("snapshot(%s): %d %s", callsign, resp.StatusCode, body)
	}
	var snap struct {
		Zones  []db.Zone  `json:"zones"`
		Alerts []db.Alert `json:"alerts"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatal(err)
	}
	return snap.Zones, snap.Alerts
}

func TestAlertsLifecycle(t *testing.T) {
	ctx := setup(t)
	bpriv := register(t, ctx, "bravo", "operator")
	cpriv := register(t, ctx, "charlie", "operator")

	// unknown alert type rejected
	p := signPacket(t, ctx, "admin", "alert", map[string]any{"type": "foo", "n": "a0"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid alert type must be 400, got %d", resp.StatusCode)
	}

	// admin raises a SOS alarm
	p = signPacket(t, ctx, "admin", "alert", map[string]any{"type": "sos", "text": "Контакт севернее", "n": "alarm1"})
	resp, body := doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alert create: %d %s", resp.StatusCode, body)
	}
	var rec db.Alert
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Sender != "admin" || rec.Type != "sos" {
		t.Fatalf("alert rec: %+v", rec)
	}

	// bravo sees the alarm in snapshot and acks it
	if _, alerts := snapshotPhase2(t, ctx, bpriv, "bravo"); len(alerts) != 1 || alerts[0].Nonce != "alarm1" {
		t.Fatalf("bravo snapshot alerts: %+v", alerts)
	}
	p = signPacket(t, ctx, "admin", "alert_ack", map[string]any{"author": "admin", "n": "alarm1"})
	// ack must be signed by bravo, not admin
	p = signAs(t, "bravo", bpriv, "alert_ack", map[string]any{"author": "admin", "n": "alarm1"})
	resp, body = doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alert ack: %d %s", resp.StatusCode, body)
	}
	_, alerts := snapshotPhase2(t, ctx, bpriv, "bravo")
	if len(alerts) != 1 || len(alerts[0].Acks) != 1 || alerts[0].Acks[0] != "bravo" {
		t.Fatalf("bravo acks tally: %+v", alerts)
	}

	// charlie is not allowed to clear someone else's alarm
	p = signAs(t, "charlie", cpriv, "alert_clear", map[string]any{"author": "admin", "n": "alarm1"})
	resp, _ = doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-author clear must be 403, got %d", resp.StatusCode)
	}

	// acking an unknown alarm is rejected
	p = signAs(t, "bravo", bpriv, "alert_ack", map[string]any{"author": "admin", "n": "ghost"})
	resp, _ = doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown alert ack must be 400, got %d", resp.StatusCode)
	}

	// admin clears it → no active alerts anywhere
	p = signPacket(t, ctx, "admin", "alert_clear", map[string]any{"author": "admin", "n": "alarm1"})
	resp, body = doSigned(t, ctx, http.MethodPost, "/api/v1/alerts", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alert clear: %d %s", resp.StatusCode, body)
	}
	if _, alerts := snapshotPhase2(t, ctx, bpriv, "bravo"); len(alerts) != 0 {
		t.Fatalf("alerts after clear: %+v", alerts)
	}
}

func TestZonesLifecycle(t *testing.T) {
	ctx := setup(t)
	bpriv := register(t, ctx, "bravo", "operator")
	cpriv := register(t, ctx, "charlie", "operator")

	// too few points rejected
	p := signAs(t, "bravo", bpriv, "zone", map[string]any{"name": "bad", "color": "#000", "points": [][2]float64{{55, 37}, {56, 38}}, "n": "z0"})
	resp, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/zones", p)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short zone must be 400, got %d", resp.StatusCode)
	}

	// bravo draws a polygon
	p = signAs(t, "bravo", bpriv, "zone", map[string]any{
		"name": "Опасный район", "color": "#ff3b30",
		"points": [][2]float64{{55.1, 37.1}, {55.2, 37.2}, {55.15, 37.3}}, "n": "z1",
	})
	resp, body := doSigned(t, ctx, http.MethodPost, "/api/v1/zones", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("zone create: %d %s", resp.StatusCode, body)
	}
	zones, _ := snapshotPhase2(t, ctx, bpriv, "bravo")
	if len(zones) != 1 || zones[0].Name != "Опасный район" || zones[0].Sender != "bravo" {
		t.Fatalf("bravo zones: %+v", zones)
	}

	// bravo renames it
	p = signAs(t, "bravo", bpriv, "zone_update", map[string]any{"name": "Эвакуация 2", "color": "#2e7d32", "n": "z1"})
	resp, body = doSigned(t, ctx, http.MethodPost, "/api/v1/zones", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zone update: %d %s", resp.StatusCode, body)
	}
	zones, _ = snapshotPhase2(t, ctx, cpriv, "charlie")
	if len(zones) != 1 || zones[0].Name != "Эвакуация 2" || zones[0].Color != "#2e7d32" {
		t.Fatalf("charlie sees renamed zone: %+v", zones)
	}

	// charlie cannot delete bravo's zone
	p = signAs(t, "charlie", cpriv, "zone_delete", map[string]any{"n": "z1"})
	resp, _ = doSigned(t, ctx, http.MethodPost, "/api/v1/zones", p)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-author zone delete must be 403, got %d", resp.StatusCode)
	}

	// bravo deletes it
	p = signAs(t, "bravo", bpriv, "zone_delete", map[string]any{"n": "z1"})
	resp, body = doSigned(t, ctx, http.MethodPost, "/api/v1/zones", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zone delete: %d %s", resp.StatusCode, body)
	}
	zones, _ = snapshotPhase2(t, ctx, bpriv, "bravo")
	if len(zones) != 0 {
		t.Fatalf("zones after delete: %+v", zones)
	}
}
