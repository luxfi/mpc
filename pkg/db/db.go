package db

import (
	"fmt"
	"strings"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Database holds the ORM entity store. SQLite is the only backend — the
// driver-level write mutex plus BEGIN IMMEDIATE gives us serializable
// writes across goroutines in a single process. For multi-process
// deployments the same file is accessed through the reserved-lock path,
// which is enough for the MPC dashboard's control-plane workload.
type Database struct {
	ORM orm.DB
}

// New creates a Database. dsn selects the SQLite location:
//
//	""                    → sqlite ./mpc.db
//	"sqlite://path"       → sqlite at path
//	"path.db"             → sqlite at path (legacy)
//
// The second positional argument is kept for call-site compatibility and is
// ignored (it used to configure a KV sidecar that no longer exists).
func New(dsn, _ string) (*Database, error) {
	path := "mpc.db"
	switch {
	case dsn == "":
		// default
	case strings.HasPrefix(dsn, "sqlite://"):
		path = strings.TrimPrefix(dsn, "sqlite://")
	case strings.HasSuffix(dsn, ".db"):
		path = dsn
	default:
		return nil, fmt.Errorf("unsupported DSN: %q (use sqlite:// or a .db path)", dsn)
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
