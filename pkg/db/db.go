package db

import (
	"fmt"
	"strings"

	kv "github.com/hanzoai/kv-go/v9"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Database holds the ORM entity store and optional KV cache.
type Database struct {
	ORM orm.DB
	KV  kv.UniversalClient
}

// New creates a Database. Detects backend from DSN:
//   - "" or "sqlite://..." or file path → SQLite (default, zero-config)
//   - "postgres://..." → PostgreSQL
//
// kvURL is optional — pass "" to skip KV cache.
func New(dsn, kvURL string) (*Database, error) {
	var ormInstance orm.DB

	switch {
	case dsn == "" || strings.HasPrefix(dsn, "sqlite://") || strings.HasSuffix(dsn, ".db"):
		// SQLite — default, zero external deps.
		path := "mpc.db"
		if strings.HasPrefix(dsn, "sqlite://") {
			path = strings.TrimPrefix(dsn, "sqlite://")
		} else if strings.HasSuffix(dsn, ".db") {
			path = dsn
		}
		sqliteDB, err := ormdb.NewSQLiteDB(&ormdb.SQLiteDBConfig{Path: path})
		if err != nil {
			return nil, fmt.Errorf("sqlite: %w", err)
		}
		ormInstance = orm.AdaptDB(sqliteDB)

	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		sqlDB, err := ormdb.NewSQLDB(&ormdb.SQLConfig{
			DSN:      dsn,
			MaxConns: 20,
			MinConns: 2,
		})
		if err != nil {
			return nil, fmt.Errorf("postgres: %w", err)
		}
		ormInstance = orm.AdaptDB(sqlDB)

	default:
		return nil, fmt.Errorf("unsupported DSN: %q (use sqlite://, postgres://, or .db path)", dsn)
	}

	var kvClient kv.UniversalClient
	if kvURL != "" {
		kvClient = kv.NewUniversalClient(&kv.UniversalOptions{
			Addrs: []string{kvURL},
		})
	}

	return &Database{
		ORM: ormInstance,
		KV:  kvClient,
	}, nil
}

// Close releases all database resources.
func (d *Database) Close() {
	if d.ORM != nil {
		d.ORM.Close()
	}
	if d.KV != nil {
		d.KV.Close()
	}
}
