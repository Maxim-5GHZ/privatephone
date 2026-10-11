package api

// White-box tests for the runtime tile downloader (mocked upstream).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privatephone/server/internal/db"
)

const testPNG1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

func testPNGBytes(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(testPNG1x1)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openTestStore(t *testing.T) *db.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	st, err := db.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close(context.Background()) })
	return st
}

func TestTilePathSourceErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := tilePathSource(dir, "yandex", 0, 0, 0); err == nil {
		t.Fatal("bad source must error")
	}
	if _, err := tilePathSource(dir, "osm", 99, 0, 0); err == nil {
		t.Fatal("bad coords must error")
	}
	if _, err := tilePathSource(dir, "sat", 1, 0, 1); err != nil {
		t.Fatalf("sat path: %v", err)
	}
	p, err := tilePathSource(dir, "sat", 1, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.ToSlash(p), "tiles/sat/1/0/1.png") {
		t.Fatalf("sat path layout: %s", p)
	}
	p2, err := tilePathSource(dir, "osm", 2, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filepath.ToSlash(p2), "tiles/osm/") {
		t.Fatalf("osm must keep legacy flat layout: %s", p2)
	}
}

func TestLatLonToTileKnown(t *testing.T) {
	x, y := latLonToTile(0, 0, 0)
	if x != 0 || y != 0 {
		t.Fatalf("z0 origin: got %d,%d", x, y)
	}
	// Moscow approx tile at z10: x=619, y=320 (spot-check web-mercator math)
	x10, y10 := latLonToTile(55.75, 37.62, 10)
	if x10 != 619 || y10 != 320 {
		t.Fatalf("moscow z10: got %d,%d want 619,320", x10, y10)
	}
	if clampInt(99, 0, 5) != 5 || clampInt(-3, 0, 5) != 0 || clampInt(3, 0, 5) != 3 {
		t.Fatal("clampInt broken")
	}
}

func TestFetchOneTileFormats(t *testing.T) {
	png := testPNGBytes(t)
	var gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("User-Agent") != fetchUA {
			t.Errorf("UA must be %q, got %q", fetchUA, r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}))
	defer up.Close()

	oldOSM, oldSAT := tileUpstreams[tileSourceOSM], tileUpstreams[tileSourceSAT]
	tileUpstreams[tileSourceOSM] = up.URL
	tileUpstreams[tileSourceSAT] = up.URL
	defer func() {
		tileUpstreams[tileSourceOSM] = oldOSM
		tileUpstreams[tileSourceSAT] = oldSAT
	}()

	dir := t.TempDir()
	dst := filepath.Join(dir, "0", "0", "0.png")
	if err := fetchOneTile(http.DefaultClient, "osm", 0, 0, 0, dst); err != nil {
		t.Fatalf("osm fetch: %v", err)
	}
	if gotPath != "/0/0/0.png" {
		t.Fatalf("osm path: %s", gotPath)
	}
	if st, err := os.Stat(dst); err != nil || st.Size() == 0 {
		t.Fatal("tile must be written")
	}

	// Esri order: tile/{z}/{y}/{x}
	dst2 := filepath.Join(dir, "s", "1.png")
	if err := fetchOneTile(http.DefaultClient, "sat", 5, 3, 7, dst2); err != nil {
		t.Fatalf("sat fetch: %v", err)
	}
	if gotPath != "/5/7/3" {
		t.Fatalf("esri y/x order: %s", gotPath)
	}

	// non-PNG rejected
	up2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello, not a png at all, just text bytes here"))
	}))
	defer up2.Close()
	tileUpstreams[tileSourceOSM] = up2.URL
	if err := fetchOneTile(http.DefaultClient, "osm", 0, 0, 0, filepath.Join(dir, "x.png")); err == nil {
		t.Fatal("non-PNG must error")
	}

	// upstream 500 → error
	up3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer up3.Close()
	tileUpstreams[tileSourceOSM] = up3.URL
	if err := fetchOneTile(http.DefaultClient, "osm", 0, 0, 0, filepath.Join(dir, "y.png")); err == nil {
		t.Fatal("500 must error")
	}
}

func TestRunFetchDoneAndSkip(t *testing.T) {
	png := testPNGBytes(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(png)
	}))
	defer up.Close()
	oldOSM := tileUpstreams[tileSourceOSM]
	tileUpstreams[tileSourceOSM] = up.URL
	defer func() { tileUpstreams[tileSourceOSM] = oldOSM }()

	st := openTestStore(t)
	s := &Server{st: st}
	// pre-seed one tile → skip-existing branch
	pre, err := tilePathSource(st.DataDir(), "osm", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(pre), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pre, png, 0o644); err != nil {
		t.Fatal(err)
	}

	job := &fetchJob{status: fetchStatus{State: "running"}, client: &http.Client{Timeout: 5 * time.Second}}
	_ = time.Now()
	s.runFetch(job, "osm", []tileXYZ{{z: 0, x: 0, y: 0}, {z: 1, x: 0, y: 0}})
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.status.State != "done" {
		t.Fatalf("state: %+v", job.status)
	}
	if job.status.Done != 2 {
		t.Fatalf("done: %+v", job.status)
	}
	got, err := tilePathSource(st.DataDir(), "osm", 1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("fetched tile missing: %v", err)
	}
}

func TestRunFetchUpstreamError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer up.Close()
	oldOSM := tileUpstreams[tileSourceOSM]
	tileUpstreams[tileSourceOSM] = up.URL
	defer func() { tileUpstreams[tileSourceOSM] = oldOSM }()

	st := openTestStore(t)
	s := &Server{st: st}
	job := &fetchJob{status: fetchStatus{State: "running"}, client: &http.Client{Timeout: 5 * time.Second}}
	s.runFetch(job, "osm", []tileXYZ{{z: 0, x: 0, y: 0}})
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.status.State != "error" || job.status.Error == "" {
		t.Fatalf("must end in error: %+v", job.status)
	}
}
