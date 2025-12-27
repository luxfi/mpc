package db

import (
	"github.com/jackc/pgx/v5/pgxpool"
	kv "github.com/hanzoai/kv-go/v9"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
)

// Database holds the ORM entity store and the KV cache/session client.
type Database struct {
	ORM  orm.DB
	KV   kv.UniversalClient
	pool *pgxpool.Pool // underlying pool for raw SQL fallback
}

// New creates a Database wired to PostgreSQL (via ORM) and Valkey/Redis (via KV).
func New(postgresURL, kvURL string) (*Database, error) {
	sqlDB, err := ormdb.NewSQLDB(&ormdb.SQLConfig{
		DSN:      postgresURL,
		MaxConns: 20,
		MinConns: 2,
	})
	if err != nil {
		return nil, err
	}

	ormInstance := orm.AdaptDB(sqlDB)

	var kvClient kv.UniversalClient
	if kvURL != "" {
		kvClient = kv.NewUniversalClient(&kv.UniversalOptions{
			Addrs: []string{kvURL},
		})
	}

	return &Database{
		ORM:  ormInstance,
		KV:   kvClient,
		pool: sqlDB.Pool(),
	}, nil
}

// Pool returns the underlying pgxpool.Pool for raw SQL operations.
// Use this only for queries that have no ORM equivalent.
func (d *Database) Pool() *pgxpool.Pool {
	return d.pool
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
