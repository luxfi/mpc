module github.com/luxfi/mpc/e2e

go 1.25.5

require (
	github.com/dgraph-io/badger/v4 v4.8.0
	github.com/google/uuid v1.6.0
	github.com/luxfi/mpc v0.0.0-00010101000000-000000000000
	github.com/nats-io/nats.go v1.44.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
)

replace github.com/luxfi/mpc => ../

replace github.com/agl/ed25519 => github.com/luxfi/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
