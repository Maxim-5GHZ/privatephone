package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// E2EE updates arrive in a fresh envelope whose own `n` is new, so the server
// must address the edited object by the plaintext `target` field (the nonce
// stored at creation). `n` stays a fallback for plaintext clients.
func TestMarkerZoneUpdateByTarget(t *testing.T) {
	ctx := setup(t)

	post := func(callsign, kind string, body any) (int, []byte) {
		p := signPacket(t, ctx, callsign, kind, body)
		path := "/api/v1/markers"
		if len(kind) >= 4 && kind[:4] == "zone" {
			path = "/api/v1/zones"
		}
		resp, b := doSigned(t, ctx, http.MethodPost, path, p)
		return resp.StatusCode, b
	}

	code, _ := post("admin", "marker", map[string]any{"lat": 55.0, "lon": 37.0, "type": "own", "n": "tgt1"})
	if code != http.StatusCreated {
		t.Fatalf("marker create: %d", code)
	}
	// E2EE envelope shape: no "n" in body, only plaintext target.
	code, b := post("admin", "marker_update", map[string]any{"target": "tgt1", "type": "enc-new", "desc": "d"})
	if code != http.StatusOK {
		t.Fatalf("marker update by target: %d %s", code, b)
	}
	var mk struct {
		Type string `json:"type"`
		N    string `json:"n"`
	}
	if err := json.Unmarshal(b, &mk); err != nil {
		t.Fatal(err)
	}
	if mk.Type != "enc-new" || mk.N != "tgt1" {
		t.Fatalf("marker not updated in place: %s", b)
	}
	// Unknown target is rejected, not silently dropped.
	if code, _ := post("admin", "marker_update", map[string]any{"target": "nope"}); code != http.StatusForbidden {
		t.Fatalf("ghost target must be 403, got %d", code)
	}
	// Legacy plaintext path (n only) still works.
	code, _ = post("admin", "marker_update", map[string]any{"n": "tgt1", "type": "own", "desc": "legacy"})
	if code != http.StatusOK {
		t.Fatalf("marker update by n: %d", code)
	}

	code, _ = post("admin", "zone", map[string]any{
		"name": "Z", "color": "#fff",
		"points": [][2]float64{{54.0, 36.0}, {54.5, 36.5}, {55.0, 36.2}},
		"n":      "ztgt1",
	})
	if code != http.StatusCreated {
		t.Fatalf("zone create: %d", code)
	}
	code, b = post("admin", "zone_update", map[string]any{"target": "ztgt1", "name": "Z2"})
	if code != http.StatusOK {
		t.Fatalf("zone update by target: %d %s", code, b)
	}
	var z struct {
		Name string `json:"name"`
		N    string `json:"n"`
	}
	if err := json.Unmarshal(b, &z); err != nil {
		t.Fatal(err)
	}
	if z.Name != "Z2" || z.N != "ztgt1" {
		t.Fatalf("zone not updated in place: %s", b)
	}
	if code, _ := post("admin", "zone_update", map[string]any{"target": "nope"}); code != http.StatusForbidden {
		t.Fatalf("ghost zone target must be 403, got %d", code)
	}
}
