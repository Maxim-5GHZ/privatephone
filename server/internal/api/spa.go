package api

import (
	"io/fs"
	"net/http"
	"strings"
)

// spa serves static assets and falls back to index.html for client-side routes.
func (s *Server) spa(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		// Unknown /api/* routes must answer 404 rather than silently serving
		// the SPA shell — REST clients never get HTML back.
		if strings.HasPrefix(path, "api/") {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(dist, path); err != nil {
			http.ServeFileFS(w, r, dist, "index.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
