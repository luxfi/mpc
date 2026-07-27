package infra

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// The other Hanzo stores a single binary links alongside SQLiteMeta — mpcd
	// links all three. Each must reach SQLite through github.com/hanzoai/sqlite,
	// the ONE package that registers the "sqlite" driver name. If any of them
	// (including this one) regresses to importing modernc.org/sqlite directly,
	// the second sql.Register panics while this test binary is still running
	// init and the whole package fails to start. That init-time explosion is
	// the teeth of this test; the assertions below are the readable part.
	_ "github.com/hanzoai/base/core"
	_ "github.com/hanzoai/orm/db"
)

// TestSQLiteDriverRegisteredOnce pins the invariant that broke hanzoai/mpc:
// linking SQLiteMeta next to base/core and orm/db must yield exactly one
// registration of the "sqlite" driver name.
func TestSQLiteDriverRegisteredOnce(t *testing.T) {
	drivers := sql.Drivers()
	assert.True(t, slices.Contains(drivers, "sqlite"),
		"no %q driver registered; hanzoai/sqlite must register it: %v", "sqlite", drivers)

	// sql.Register panics on a duplicate name, so reaching this line already
	// proves single registration. Assert it anyway so the intent is legible.
	var n int
	for _, d := range drivers {
		if d == "sqlite" {
			n++
		}
	}
	assert.Equal(t, 1, n, "driver %q registered %d times", "sqlite", n)
}

// TestSQLiteMeta_PragmasApplied proves the connection DSN is expressed in the
// ACTIVE backend's syntax. The previous hand-rolled `?_journal_mode=WAL&...`
// string was mattn-only: the pure-Go backend silently dropped it, leaving
// journal_mode=delete and busy_timeout=0 — immediate SQLITE_BUSY under
// concurrent writers. sqlite.PragmaDSN encodes them per backend.
func TestSQLiteMeta_PragmasApplied(t *testing.T) {
	s, err := NewSQLiteMeta(SQLiteMetaConfig{
		Path: filepath.Join(t.TempDir(), "meta.db"),
		WAL:  true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })

	pragma := func(name string) string {
		var v string
		require.NoError(t, s.db.NewQuery("PRAGMA "+name).Row(&v), "read pragma %s", name)
		return v
	}

	assert.Equal(t, "wal", pragma("journal_mode"))
	assert.Equal(t, "5000", pragma("busy_timeout"))
	assert.Equal(t, "1", pragma("foreign_keys"))
}
