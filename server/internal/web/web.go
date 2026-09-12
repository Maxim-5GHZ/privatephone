// Package web bundles the compiled frontend and the offline map tiles into the
// single server binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

//go:embed all:tiles
var tilesFS embed.FS

// Dist exposes the compiled UI (Vite build output).
func Dist() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// Tiles exposes the offline map tiles under {z}/{x}/{y}.png.
func Tiles() fs.FS {
	sub, err := fs.Sub(tilesFS, "tiles")
	if err != nil {
		panic(err)
	}
	return sub
}
