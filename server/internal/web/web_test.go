package web

import (
	"io/fs"
	"testing"
)

func TestDistServesIndex(t *testing.T) {
	dist := Dist()
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		t.Fatalf("dist must contain index.html: %v", err)
	}
}

func TestTilesExposeZoomLevels(t *testing.T) {
	tiles := Tiles()
	entries, err := fs.ReadDir(tiles, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("tiles must contain at least one zoom level directory")
	}
}
