package db

import (
	"fmt"
	"strings"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Database holds the ORM entity store backed by SQLite.
type Database struct {
	ORM orm.DB
}

// New creates a Database backed by SQLite.
// dsn accepts "" (defaults to mpc.db), "sqlite://path", or a ".db" file path.
// kvURL is ignored (retained for call-site compat, will be removed).
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
		return nil, fmt.Errorf("unsupported DSN: %q (use sqlite:// or .db path)", dsn)
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
