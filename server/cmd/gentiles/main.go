// Command gentiles generates offline placeholder map tiles (zooms 0-5)
// into server/internal/web/tiles, which are embedded into the binary by
// internal/web. Without network access it gives the map a usable offline
// basemap; replace the output with real OSM tiles via scripts/fetch_tiles.sh.
package main

import (
	"flag"
	"fmt"
	"hash/fnv"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

const tileSize = 256

func main() {
	out := flag.String("out", "internal/web/tiles", "output directory (relative to CWD)")
	maxZoom := flag.Int("z", 5, "maximum zoom level")
	flag.Parse()

	for z := 0; z <= *maxZoom; z++ {
		n := 1 << z
		log.Printf("zoom %d: %d tiles", z, n*n)
		for x := 0; x < n; x++ {
			for y := 0; y < n; y++ {
				path := filepath.Join(*out, fmt.Sprintf("%d/%d/%d.png", z, x, y))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					log.Fatal(err)
				}
				if err := writeTile(path, z, x, y); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
	log.Printf("done")
}

func writeTile(path string, z, x, y int) error {
	img := image.NewNRGBA(image.Rect(0, 0, tileSize, tileSize))
	base := baseColor(z, x, y)
	border := lighten(base, 18)
	line := lighten(base, 30)

	for py := 0; py < tileSize; py++ {
		for px := 0; px < tileSize; px++ {
			c := base
			if px == 0 || py == 0 || px == tileSize-1 || py == tileSize-1 {
				c = border
			} else if px == py || px == tileSize-py-1 { // subtle diagonal graticule
				c = line
			}
			img.SetNRGBA(px, py, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// baseColor picks a flat ocean/land-ish tone from latitude + tile hash.
func baseColor(z, x, y int) color.NRGBA {
	top, _ := tileLatLon(x, y, z)
	lat := math.Abs(top)
	var r, g, b uint8
	switch {
	case lat > 66: // arctic
		r, g, b = 214, 220, 230
	case lat > 50: // temperate
		r, g, b = 132, 168, 138
	case lat > 23: // tropics
		r, g, b = 96, 156, 96
	default: // equatorial
		r, g, b = 60, 116, 70
	}

	h := fnv.New32a()
	fmt.Fprintf(h, "%d/%d/%d", z, x, y)
	v := h.Sum32()
	dr := int8(v%12) - 6
	return color.NRGBA{clamp(int(r) + int(dr)), clamp(int(g) + int(dr)), clamp(int(b) + int(dr)), 255}
}

// tileLatLon returns the top-left corner (lat, lng) of tile (x,y) at zoom z.
func tileLatLon(x, y, z int) (lat, lng float64) {
	n := math.Pow(2, float64(z))
	lng = float64(x)/n*360.0 - 180.0
	latRad := math.Atan(math.Sinh(math.Pi*(1-2*float64(y)/n))) * 180.0 / math.Pi
	return latRad, lng
}

func lighten(c color.NRGBA, d uint8) color.NRGBA {
	return color.NRGBA{clamp(int(c.R) + int(d)), clamp(int(c.G) + int(d)), clamp(int(c.B) + int(d)), c.A}
}

func clamp(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
