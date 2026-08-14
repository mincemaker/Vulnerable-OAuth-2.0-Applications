// Package web embeds the static assets served by the HTTP server (CSS),
// so the compiled binary is self-contained and does not need web/static/
// copied alongside it at runtime.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var staticFS embed.FS

// Static is the static/ directory rooted at itself (so URL paths map
// directly onto it without a "static/" prefix), embedded at compile time.
var Static = mustSub(staticFS, "static")

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err) // only possible if the embed directive itself is broken
	}
	return sub
}
