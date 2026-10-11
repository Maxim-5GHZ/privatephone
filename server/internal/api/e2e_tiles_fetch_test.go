package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestTilesFetchValidation(t *testing.T) {
	ctx := setup(t)

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"bad source", map[string]any{"source": "yandex", "lat": 55.75, "lon": 37.62, "zmin": 0, "zmax": 5, "span": 0.5}, http.StatusBadRequest},
		{"zoom over 16", map[string]any{"source": "osm", "lat": 55.75, "lon": 37.62, "zmin": 0, "zmax": 17, "span": 0.5}, http.StatusBadRequest},
		{"inverted zooms", map[string]any{"source": "osm", "lat": 55.75, "lon": 37.62, "zmin": 8, "zmax": 5, "span": 0.5}, http.StatusBadRequest},
		{"span too big", map[string]any{"source": "osm", "lat": 55.75, "lon": 37.62, "zmin": 0, "zmax": 5, "span": 50}, http.StatusBadRequest},
		{"lat out of range", map[string]any{"source": "osm", "lat": 91, "lon": 37.62, "zmin": 0, "zmax": 5, "span": 0.5}, http.StatusBadRequest},
		{"too many tiles", map[string]any{"source": "sat", "lat": 55.75, "lon": 37.62, "zmin": 0, "zmax": 16, "span": 5}, http.StatusBadRequest},
	}
	for _, c := range cases {
		p := signPacket(t, ctx, "admin", "tiles_fetch", c.body)
		resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles/fetch", p)
		if resp.StatusCode != c.want {
			t.Fatalf("%s: want %d, got %d %s", c.name, c.want, resp.StatusCode, b)
		}
	}

	// operator cannot fetch
	bob := register(t, ctx, "bob", "operator")
	po := signAs(t, "bob", bob, "tiles_fetch", map[string]any{"source": "osm", "lat": 55.75, "lon": 37.62, "zmin": 0, "zmax": 0, "span": 0.1})
	respO, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles/fetch", po)
	if respO.StatusCode != http.StatusForbidden {
		t.Fatalf("operator fetch must be 403, got %d", respO.StatusCode)
	}
}

func TestTilesFetchStatusIdle(t *testing.T) {
	ctx := setup(t)
	p := signPacket(t, ctx, "admin", "tiles_fetch_status", map[string]any{})
	resp, b := doSigned(t, ctx, http.MethodGet, "/api/v1/admin/tiles/fetch/status", p)
	if resp.StatusCode != 200 {
		t.Fatalf("fetch status: %d %s", resp.StatusCode, b)
	}
	var st struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.State != "idle" {
		t.Fatalf("fresh node must be idle, got %s", st.State)
	}
}

func TestTilesSourcesPutServe(t *testing.T) {
	ctx := setup(t)
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

	// put into sat source
	p := signPacket(t, ctx, "admin", "tiles_put", map[string]any{"z": 1, "x": 0, "y": 0, "png_b64": pngB64, "source": "sat"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles", p)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("sat put: %d %s", resp.StatusCode, b)
	}

	// bad source rejected
	pb := signPacket(t, ctx, "admin", "tiles_put", map[string]any{"z": 1, "x": 0, "y": 0, "png_b64": pngB64, "source": "yandex"})
	respB, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles", pb)
	if respB.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad source must be 400, got %d", respB.StatusCode)
	}

	get := func(path string) (*http.Response, []byte) {
		t.Helper()
		r, err := http.Get(ctx.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		return r, body
	}

	// sat tile served from custom dir
	r1, b1 := get("/tiles/sat/1/0/0.png")
	if r1.StatusCode != 200 || r1.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("sat tile: %d %s", r1.StatusCode, r1.Header.Get("Content-Type"))
	}
	if len(b1) == 0 || string(b1[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Fatal("sat tile must be PNG bytes")
	}

	// osm at same coords: embed fallback (z1 exists in bundle)
	r2, _ := get("/tiles/osm/1/0/0.png")
	if r2.StatusCode != 200 {
		t.Fatalf("osm embed fallback: %d", r2.StatusCode)
	}

	// missing zoom → transparent fallback PNG, not bare 404
	r3, b3 := get("/tiles/osm/15/10/10.png")
	if r3.StatusCode != 200 || r3.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("missing tile must be fallback PNG 200, got %d %s", r3.StatusCode, r3.Header.Get("Content-Type"))
	}
	if r3.Header.Get("Cache-Control") == "public, max-age=86400" {
		t.Fatal("fallback must not carry long cache")
	}
	if len(b3) == 0 {
		t.Fatal("fallback must be non-empty PNG")
	}

	// garbage path → fallback PNG
	r4, _ := get("/tiles/bogus")
	if r4.StatusCode != 200 {
		t.Fatalf("garbage tile path must be fallback 200, got %d", r4.StatusCode)
	}

	// status reports per-source
	ps := signPacket(t, ctx, "admin", "tiles_status", map[string]any{})
	_, b5 := doSigned(t, ctx, http.MethodGet, "/api/v1/admin/tiles/status", ps)
	var st struct {
		CustomTiles int         `json:"custom_tiles"`
		BySource    map[string]int `json:"by_source"`
	}
	if err := json.Unmarshal(b5, &st); err != nil {
		t.Fatal(err)
	}
	if st.CustomTiles != 1 || st.BySource["sat"] != 1 || st.BySource["osm"] != 0 {
		t.Fatalf("bad per-source status: %s", b5)
	}
}

func TestTilesBagWithSources(t *testing.T) {
	ctx := setup(t)
	rawPNG, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		t.Helper()
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add("2/1/1.png", rawPNG)        // legacy flat → request source (osm)
	add("sat/2/1/1.png", rawPNG)    // explicit source prefix
	add("notes.txt", []byte("hi"))  // skipped: not png
	add("9/9/9.png", []byte("no"))  // skipped: bad coords + not png
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	p := signPacket(t, ctx, "admin", "tiles_bag", map[string]any{"zip_b64": zipB64, "source": "osm"})
	resp, b := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles/bag", p)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bag: %d %s", resp.StatusCode, b)
	}
	var rep struct {
		Added   int `json:"added"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Added != 2 || rep.Skipped != 2 {
		t.Fatalf("bag report: %s", b)
	}

	// bad source rejected
	pb := signPacket(t, ctx, "admin", "tiles_bag", map[string]any{"zip_b64": zipB64, "source": "yandex"})
	respB, _ := doSigned(t, ctx, http.MethodPost, "/api/v1/admin/tiles/bag", pb)
	if respB.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad bag source must be 400, got %d", respB.StatusCode)
	}

	// both served
	for _, path := range []string{"/tiles/osm/2/1/1.png", "/tiles/sat/2/1/1.png"} {
		r, err := http.Get(ctx.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode != 200 || len(body) == 0 {
			t.Fatalf("%s: %d", path, r.StatusCode)
		}
	}
}
