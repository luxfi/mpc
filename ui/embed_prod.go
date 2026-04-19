//go:build embedui

// Package ui embeds the MPC admin dashboard when built with `-tags embedui`.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// DistDirFS returns the embedded dist/ tree rooted at "dist".
func DistDirFS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
