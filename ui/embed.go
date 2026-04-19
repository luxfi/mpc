//go:build !embedui

// Package ui provides a placeholder dashboard filesystem when the
// server is built without the `embedui` tag. Default build ships no UI.
// Production builds that want the bundled dashboard must
// `pnpm --dir ui build` then build with `-tags embedui`.
package ui

import (
	"io/fs"
	"testing/fstest"
)

var emptyFS = fstest.MapFS{
	"index.html": &fstest.MapFile{Data: []byte(
		`<!doctype html><title>MPC</title><p>UI not embedded. Build with -tags embedui.</p>`,
	)},
}

// DistDirFS returns an empty placeholder dashboard tree.
func DistDirFS() fs.FS { return emptyFS }
