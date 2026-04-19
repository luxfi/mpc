package db

import (
	"fmt"
	"strings"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Database holds the ORM entity store. SQLite backs local dev + tests;
// production deployments use postgres (hanzoai/sql). Both satisfy orm.DB so
// handlers are backend-agnostic. Serializable CAS is implemented in handlers
// via orm.RunInTransactionWith(IsolationSerializable); SQLite already
// serializes writes via its write-mutex, postgres honors the isolation.
type Database struct {
	ORM orm.DB
}

// New creates a Database. dsn selects the backend:
//
//	""                    → sqlite ./mpc.db
//	"sqlite://path"       → sqlite at path
//	"path.db"             → sqlite at path (legacy)
//	"postgres://…"        → postgres via pgx
//	"postgresql://…"      → postgres via pgx (alias)
//
// The second positional argument is kept for call-site compatibility and is
// ignored (it used to configure a KV sidecar that no longer exists).
func New(dsn, _ string) (*Database, error) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		sqlDB, err := ormdb.NewSQLDB(&ormdb.SQLConfig{DSN: dsn})
		if err != nil {
			return nil, fmt.Errorf("postgres: %w", err)
		}
		return &Database{ORM: orm.AdaptDB(sqlDB)}, nil
	}

	path := "mpc.db"
	switch {
	case dsn == "":
		// default
	case strings.HasPrefix(dsn, "sqlite://"):
		path = strings.TrimPrefix(dsn, "sqlite://")
	case strings.HasSuffix(dsn, ".db"):
		path = dsn
	default:
		return nil, fmt.Errorf("unsupported DSN: %q (use sqlite:// or postgres:// or .db path)", dsn)
	}

	sqliteDB, err := ormdb.NewSQLiteDB(&ormdb.SQLiteDBConfig{Path: path})
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}

	return &Database{
		ORM: orm.AdaptDB(sqliteDB),
	}, nil
}

// Close releases all database resources.
func (d *Database) Close() {
	if d.ORM != nil {
		d.ORM.Close()
	}
}
