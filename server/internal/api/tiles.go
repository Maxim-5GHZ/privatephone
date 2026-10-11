package api

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"privatephone/server/internal/protocol"
	"privatephone/server/internal/web"
)

const (
	maxTileBytes = 512 << 10      // 512 KiB per PNG
	maxBagBody   = 48 << 20       // 48 MiB JSON body for zip upload
	maxUnzipped  = 256 << 20      // 256 MiB unzip cap
	maxBagFiles  = 20000          // max PNGs per bag
)

var pngMagic = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

func tilesDir(dataDir string) string { return filepath.Join(dataDir, "tiles") }

// handleTilesStatus reports how many custom (uploaded/fetched) tiles override
// the embedded offline map, broken down by source.
func (s *Server) handleTilesStatus(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	count, size, err := countCustomTiles(s.st.DataDir())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tiles status")
		return
	}
	bySource := map[string]int{"osm": 0, "sat": 0}
	_ = filepath.Walk(tilesSourceDir(s.st.DataDir(), tileSourceSAT), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".png") {
			bySource["sat"]++
		}
		return nil
	})
	bySource["osm"] = count - bySource["sat"]
	if bySource["osm"] < 0 {
		bySource["osm"] = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"custom_tiles": count,
		"custom_bytes": size,
		"by_source":    bySource,
	})
}

func countCustomTiles(dataDir string) (int, int64, error) {
	root := tilesDir(dataDir)
	var n int
	var size int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".png") {
			n++
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	return n, size, nil
}

func validTileCoord(z, x, y int) bool {
	if z < 0 || z > 18 {
		return false
	}
	if x < 0 || y < 0 {
		return false
	}
	limit := 1 << uint(z)
	return x < limit && y < limit
}

// handleTilePut stores a single custom tile (admin only).
// Body: {"z":int,"x":int,"y":int,"png_b64":"...","source":"osm|sat"}
// source defaults to "osm" (legacy flat layout).
func (s *Server) handleTilePut(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var req struct {
		Z     int    `json:"z"`
		X     int    `json:"x"`
		Y     int    `json:"y"`
		PngB  string `json:"png_b64"`
		Src   string `json:"source"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad tile JSON")
		return
	}
	if req.Src == "" {
		req.Src = tileSourceOSM
	}
	if !validTileSource(req.Src) {
		writeErr(w, http.StatusBadRequest, "source must be osm|sat")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.PngB)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "png_b64 must be base64")
		return
	}
	if len(raw) == 0 || len(raw) > maxTileBytes {
		writeErr(w, http.StatusBadRequest, "tile size 1..512KiB")
		return
	}
	if len(raw) < 8 || !bytes.Equal(raw[:8], pngMagic) {
		writeErr(w, http.StatusBadRequest, "not a PNG image")
		return
	}
	p, err := tilePathSource(s.st.DataDir(), req.Src, req.Z, req.X, req.Y)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "tiles mkdir")
		return
	}
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "tiles write")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"z": req.Z, "x": req.X, "y": req.Y, "source": req.Src, "bytes": len(raw)})
}

// handleTilesBag imports a ZIP with {z}/{x}/{y}.png tree (admin only).
// Body: {"zip_b64":"...","source":"osm|sat"} — e.g. produced by scripts/fetch_tiles.sh + zip.
// Entries may also carry a source prefix: {source}/{z}/{x}/{y}.png.
func (s *Server) handleTilesBag(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	var req struct {
		ZipB string `json:"zip_b64"`
		Src  string `json:"source"`
	}
	if err := json.Unmarshal(ev.Data, &req); err != nil || req.ZipB == "" {
		writeErr(w, http.StatusBadRequest, "zip_b64 required")
		return
	}
	if req.Src == "" {
		req.Src = tileSourceOSM
	}
	if !validTileSource(req.Src) {
		writeErr(w, http.StatusBadRequest, "source must be osm|sat")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.ZipB)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "zip_b64 must be base64")
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "not a zip archive")
		return
	}
	var added, skipped int
	var totalUnzipped int64
	for _, f := range zr.File {
		if len(f.Name) == 0 || strings.HasSuffix(f.Name, "/") {
			continue
		}
		// only {z}/{x}/{y}.png, reject traversal
		clean := filepath.ToSlash(filepath.Clean(f.Name))
		if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "../") {
			skipped++
			continue
		}
		parts := strings.Split(clean, "/")
		src := req.Src
		if len(parts) == 4 {
			// optional {source}/{z}/{x}/{y}.png prefix wins over request source
			if !validTileSource(parts[0]) {
				skipped++
				continue
			}
			src = parts[0]
			parts = parts[1:]
		}
		if len(parts) != 3 {
			skipped++
			continue
		}
		if !strings.HasSuffix(strings.ToLower(parts[2]), ".png") {
			skipped++
			continue
		}
		z, err1 := strconv.Atoi(parts[0])
		x, err2 := strconv.Atoi(parts[1])
		y, err3 := strconv.Atoi(strings.TrimSuffix(parts[2], ".png"))
		if err1 != nil || err2 != nil || err3 != nil || !validTileCoord(z, x, y) {
			skipped++
			continue
		}
		if f.UncompressedSize64 > maxTileBytes {
			skipped++
			continue
		}
		totalUnzipped += int64(f.UncompressedSize64)
		if totalUnzipped > maxUnzipped {
			writeErr(w, http.StatusBadRequest, "zip too large (cap 256MiB uncompressed)")
			return
		}
		if added+skipped >= maxBagFiles {
			break
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxTileBytes+1))
		_ = rc.Close()
		if err != nil || len(data) == 0 || len(data) > maxTileBytes {
			skipped++
			continue
		}
		if len(data) < 8 || !bytes.Equal(data[:8], pngMagic) {
			skipped++
			continue
		}
		p, err := tilePathSource(s.st.DataDir(), src, z, x, y)
		if err != nil {
			skipped++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			skipped++
			continue
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			skipped++
			continue
		}
		added++
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped})
}

// handleTilesClear removes all custom tiles (admin only, embedded stay).
func (s *Server) handleTilesClear(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope) {
	root := tilesDir(s.st.DataDir())
	if err := os.RemoveAll(root); err != nil {
		writeErr(w, http.StatusInternalServerError, "tiles clear")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"cleared": true})
}

// signedAdminLarge is like signedAdmin but allows a bigger signed JSON body
// (tile bags). Signature still covers the exact raw bytes.
func (s *Server) signedAdminLarge(limit int, handler func(w http.ResponseWriter, r *http.Request, ev *protocol.Envelope)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ev, err := s.decodeEnvelopeWithLimit(r, limit)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		role, err := s.ver.Verify(r.Context(), ev)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if role != "admin" {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		handler(w, r, ev)
	}
}

func (s *Server) decodeEnvelopeWithLimit(r *http.Request, limit int) (*protocol.Envelope, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("read body")
	}
	_ = r.Body.Close()
	// Same percent-decoding as decodeEnvelope: fetch() percent-encodes
	// non-ASCII callsigns, the raw header would fail lookup/verification.
	sender, uerr := url.PathUnescape(r.Header.Get("X-Sender"))
	if uerr != nil {
		sender = r.Header.Get("X-Sender")
	}
	ev := &protocol.Envelope{
		Sender:    sender,
		Signature: r.Header.Get("X-Signature"),
		Nonce:     r.Header.Get("X-Nonce"),
		Kind:      r.Header.Get("X-Kind"),
		Data:      body,
	}
	ts, err := parseTS(r.Header.Get("X-TS"))
	if err != nil {
		return nil, fmt.Errorf("bad timestamp")
	}
	ev.TS = ts
	if ev.Sender == "" || ev.Kind == "" || ev.Nonce == "" || ev.Signature == "" {
		return nil, fmt.Errorf("missing signed fields")
	}
	return ev, nil
}

// fallbackTile is a 1x1 transparent PNG served (200, no-store) when neither
// custom nor embedded tiles have the requested tile — keeps the map from
// showing broken-image holes and 404 storms at zooms without data.
var fallbackTile = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
	0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x18, 0x05, 0xA3,
	0x60, 0x14, 0x8C, 0x02, 0x00, 0x00, 0x0D, 0x00, 0x01, 0xE2, 0x63, 0x1E,
	0x12, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60,
	0x82,
}

func serveFallbackTile(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(fallbackTile)
}

// serveTiles serves custom tiles first (data/tiles/{source}/...),
// then the embedded offline set (legacy flat {z}/{x}/{y}.png for osm),
// then a transparent fallback PNG so missing zooms don't break the map.
//
// URL scheme: /tiles/{source}/{z}/{x}/{y}.png (source = osm|sat);
// legacy /tiles/{z}/{x}/{y}.png is treated as osm.
func (s *Server) serveTiles(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/tiles/")
	rel = filepath.Clean(rel)
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		serveFallbackTile(w)
		return
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	src := tileSourceOSM
	if len(parts) == 4 {
		if !validTileSource(parts[0]) {
			serveFallbackTile(w)
			return
		}
		src = parts[0]
		parts = parts[1:]
	}
	if len(parts) != 3 {
		serveFallbackTile(w)
		return
	}
	z, err1 := strconv.Atoi(parts[0])
	x, err2 := strconv.Atoi(parts[1])
	y, err3 := strconv.Atoi(strings.TrimSuffix(parts[2], ".png"))
	if err1 != nil || err2 != nil || err3 != nil || !validTileCoord(z, x, y) ||
		!strings.HasSuffix(strings.ToLower(parts[2]), ".png") {
		serveFallbackTile(w)
		return
	}
	// custom override
	custom := filepath.Join(tilesSourceDir(s.st.DataDir(), src),
		strconv.Itoa(z), strconv.Itoa(x), strconv.Itoa(y)+".png")
	if data, err := os.ReadFile(custom); err == nil {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
		return
	}
	if src == tileSourceOSM {
		// embedded fallback (legacy flat layout); transparent PNG when
		// the zoom isn't covered by the bundle instead of a bare 404.
		embedRel := strconv.Itoa(z) + "/" + strconv.Itoa(x) + "/" + strconv.Itoa(y) + ".png"
		if data, err := fs.ReadFile(web.Tiles(), embedRel); err == nil {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			_, _ = w.Write(data)
			return
		}
		serveFallbackTile(w)
		return
	}
	serveFallbackTile(w)
}
