package api

// Runtime tile downloader: when the node has internet, admin asks the server
// to fetch an area (OSM and/or Esri satellite) into data/tiles/{source}/,
// then the node serves it offline to subscribers via GET /tiles/.
//
// OSM Tile Usage Policy: UA "privatephone/1.0", throttling, zoom <= 16,
// cap ~20k files per job.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"privatephone/server/internal/protocol"
)

const (
	tileSourceOSM = "osm"
	tileSourceSAT = "sat"

	fetchMaxZoom  = 16
	fetchMaxFiles = 20000
	fetchMaxSpan  = 5.0 // degrees
	fetchMinSpan  = 0.05
	fetchThrottle = 400 * time.Millisecond
	fetchTimeout  = 25 * time.Second
	fetchUA       = "privatephone/1.0 (offline map setup)"
)

var tileUpstreams = map[string]string{
	tileSourceOSM: "https://tile.openstreetmap.org",
	tileSourceSAT: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile",
}

func validTileSource(s string) bool { return s == tileSourceOSM || s == tileSourceSAT }

// tilesSourceDir: data/tiles/{z}/... for osm (legacy flat layout),
// data/tiles/sat/{z}/... for satellite.
func tilesSourceDir(dataDir, source string) string {
	if source == tileSourceSAT {
		return filepath.Join(tilesDir(dataDir), tileSourceSAT)
	}
	return tilesDir(dataDir)
}

func tilePathSource(dataDir, source string, z, x, y int) (string, error) {
	if !validTileSource(source) {
		return "", fmt.Errorf("source must be osm|sat")
	}
	if !validTileCoord(z, x, y) {
		return "", fmt.Errorf("bad tile coords z=%d x=%d y=%d", z, x, y)
	}
	p := filepath.Join(tilesSourceDir(dataDir, source), strconv.Itoa(z), strconv.Itoa(x), strconv.Itoa(y)+".png")
	// containment: must stay under tilesDir
	absRoot, err := filepath.Abs(tilesDir(dataDir))
	if err != nil {
		return "", err
	}
	absP, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if absP != absRoot && !strings.HasPrefix(absP, absRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("tile path escapes storage")
	}
	return p, nil
}

// --- fetch job state ---

type fetchStatus struct {
	State  string `json:"state"` // idle|running|done|error
	Source string `json:"source,omitempty"`
	Done   int    `json:"done"`
	Total  int    `json:"total"`
	Error  string `json:"error,omitempty"`
}

type fetchJob struct {
	mu     sync.Mutex
	status fetchStatus
	client *http.Client
}

func (s *Server) getFetchJob() *fetchJob {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	if s.fetcher == nil {
		s.fetcher = &fetchJob{
			status: fetchStatus{State: "idle"},
			client: &http.Client{Timeout: fetchTimeout},
		}
	}
	return s.fetcher
}

type tileXYZ struct{ z, x, y int }

// POST /api/v1/admin/tiles/fetch
// Body: {"source":"osm|sat","lat":..,"lon":..,"zmin":0,"zmax":14,"span":1.5}
func (s *Server) handleTilesFetch(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var req struct {
		Source string  `json:"source"`
		Lat    float64 `json:"lat"`
		Lon    float64 `json:"lon"`
		Zmin   int     `json:"zmin"`
		Zmax   int     `json:"zmax"`
		Span   float64 `json:"span"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad fetch JSON")
		return
	}
	if !validTileSource(req.Source) {
		writeErr(w, http.StatusBadRequest, "source must be osm|sat")
		return
	}
	if req.Zmax < req.Zmin || req.Zmin < 0 || req.Zmax > fetchMaxZoom {
		writeErr(w, http.StatusBadRequest, "zmin..zmax must be within 0..16")
		return
	}
	if req.Span < fetchMinSpan || req.Span > fetchMaxSpan {
		writeErr(w, http.StatusBadRequest, "span must be 0.05..5 degrees")
		return
	}
	if req.Lat < -85 || req.Lat > 85 || req.Lon < -180 || req.Lon > 180 {
		writeErr(w, http.StatusBadRequest, "lat/lon out of range")
		return
	}
	var list []tileXYZ
	for z := req.Zmin; z <= req.Zmax; z++ {
		x0, y0 := latLonToTile(req.Lat+req.Span/2, req.Lon-req.Span/2, z)
		x1, y1 := latLonToTile(req.Lat-req.Span/2, req.Lon+req.Span/2, z)
		if x0 > x1 {
			x0, x1 = x1, x0
		}
		if y0 > y1 {
			y0, y1 = y1, y0
		}
		n := 1 << uint(z)
		x0 = clampInt(x0, 0, n-1)
		x1 = clampInt(x1, 0, n-1)
		y0 = clampInt(y0, 0, n-1)
		y1 = clampInt(y1, 0, n-1)
		for x := x0; x <= x1; x++ {
			for y := y0; y <= y1; y++ {
				list = append(list, tileXYZ{z, x, y})
			}
		}
	}
	if len(list) == 0 || len(list) > fetchMaxFiles {
		writeErr(w, http.StatusBadRequest, "tile count 1..20000 (shrink span/zooms)")
		return
	}

	job := s.getFetchJob()
	job.mu.Lock()
	if job.status.State == "running" {
		job.mu.Unlock()
		writeErr(w, http.StatusConflict, "fetch already running")
		return
	}
	job.status = fetchStatus{State: "running", Source: req.Source, Total: len(list)}
	job.mu.Unlock()

	go s.runFetch(job, req.Source, list)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "total": len(list), "source": req.Source})
}

// GET /api/v1/admin/tiles/fetch/status
func (s *Server) handleTilesFetchStatus(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	job := s.getFetchJob()
	job.mu.Lock()
	st := job.status
	job.mu.Unlock()
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) runFetch(job *fetchJob, source string, list []tileXYZ) {
	done := 0
	var fetchErr string
	ticker := time.NewTicker(fetchThrottle)
	defer ticker.Stop()
	for i, t := range list {
		if i > 0 {
			<-ticker.C // OSM usage policy: throttle
		}
		p, err := tilePathSource(s.st.DataDir(), source, t.z, t.x, t.y)
		if err != nil {
			continue // validated upfront; skip defensively
		}
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			done++
			continue // keep existing (downloaded or uploaded)
		}
		if err := fetchOneTile(job.client, source, t.z, t.x, t.y, p); err != nil {
			// transient network error: stop job, keep what we got
			fetchErr = err.Error()
			break
		}
		done++
		job.mu.Lock()
		job.status.Done = done
		job.mu.Unlock()
	}
	job.mu.Lock()
	job.status.Done = done
	if fetchErr != "" {
		job.status.State = "error"
		job.status.Error = fetchErr
	} else {
		job.status.State = "done"
	}
	job.mu.Unlock()
}

func fetchOneTile(client *http.Client, source string, z, x, y int, dest string) error {
	var url string
	if source == tileSourceSAT {
		// NOTE: Esri order is tile/{z}/{y}/{x} — y and x swapped vs OSM!
		url = tileUpstreams[source] + "/" + strconv.Itoa(z) + "/" + strconv.Itoa(y) + "/" + strconv.Itoa(x)
	} else {
		url = tileUpstreams[source] + "/" + strconv.Itoa(z) + "/" + strconv.Itoa(x) + "/" + strconv.Itoa(y) + ".png"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fetchUA)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxTileBytes {
		return fmt.Errorf("bad tile body")
	}
	if len(data) < 8 || !bytes.Equal(data[:8], pngMagic) {
		return fmt.Errorf("not a PNG image")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func latLonToTile(lat, lon float64, z int) (x, y int) {
	n := math.Exp2(float64(z))
	x = int((lon + 180.0) / 360.0 * n)
	latR := lat * math.Pi / 180.0
	y = int((1.0 - math.Log(math.Tan(latR)+1.0/math.Cos(latR))/math.Pi) / 2.0 * n)
	return x, y
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
