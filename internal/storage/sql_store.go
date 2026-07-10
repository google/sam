// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/sam/api"
	"gopkg.in/yaml.v2"

	// Register PG and SQLite drivers
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// SQLStore implements Store interface using database/sql.
type SQLStore struct {
	db         *sql.DB
	driverName string
}

// NewSQLStore creates a new SQLStore, connects to the database, and initializes tables.
func NewSQLStore(driverName, dataSourceName string) (*SQLStore, error) {
	actualDriver := driverName
	if driverName == "postgres" || driverName == "postgresql" {
		actualDriver = "pgx"
	}
	if driverName == "sqlite" && !strings.Contains(dataSourceName, "?") {
		// SQLite driver options are configured via DSN query parameters so they apply
		// to all connections in the connection pool. We default to WAL mode for write
		// concurrency and busy_timeout to prevent SQLITE_BUSY locking errors.
		// Callers (e.g. integration tests that copy DB files) can override this by
		// passing a DSN containing custom query parameter parameters (e.g. "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)").
		dataSourceName = dataSourceName + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open(actualDriver, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLStore{
		db:         db,
		driverName: driverName,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

func (s *SQLStore) isPostgres() bool {
	return strings.Contains(s.driverName, "postgres") || strings.Contains(s.driverName, "pgx")
}

func (s *SQLStore) initSchema() error {
	var keyringSchema, nodesSchema, routersSchema, policiesSchema string

	if s.isPostgres() {
		keyringSchema = `
			CREATE TABLE IF NOT EXISTS keyring (
				id SERIAL PRIMARY KEY,
				private_key BYTEA NOT NULL,
				public_key BYTEA NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`
		nodesSchema = `
			CREATE TABLE IF NOT EXISTS nodes (
				peer_id VARCHAR(255) PRIMARY KEY,
				biscuit_token BYTEA NOT NULL,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`
		routersSchema = `
			CREATE TABLE IF NOT EXISTS routers (
				peer_id VARCHAR(255) PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`
		policiesSchema = `
			CREATE TABLE IF NOT EXISTS policies (
				id VARCHAR(255) PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`
	} else {
		keyringSchema = `
			CREATE TABLE IF NOT EXISTS keyring (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				private_key BLOB NOT NULL,
				public_key BLOB NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`
		nodesSchema = `
			CREATE TABLE IF NOT EXISTS nodes (
				peer_id TEXT PRIMARY KEY,
				biscuit_token BLOB NOT NULL,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`
		routersSchema = `
			CREATE TABLE IF NOT EXISTS routers (
				peer_id TEXT PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`
		policiesSchema = `
			CREATE TABLE IF NOT EXISTS policies (
				id TEXT PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`
	}

	schemas := []string{keyringSchema, nodesSchema, routersSchema, policiesSchema}
	for _, schema := range schemas {
		if _, err := s.db.Exec(schema); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) rebind(query string) string {
	if !s.isPostgres() {
		return query
	}
	var result strings.Builder
	paramIndex := 1
	for _, char := range query {
		if char == '?' {
			fmt.Fprintf(&result, "$%d", paramIndex)
			paramIndex++
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// GetCurrentKey implements Store.
func (s *SQLStore) GetCurrentKey(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	query := s.rebind(`SELECT private_key, public_key FROM keyring WHERE expiration IS NULL ORDER BY id DESC LIMIT 1`)
	var privBytes, pubBytes []byte
	err := s.db.QueryRowContext(ctx, query).Scan(&privBytes, &pubBytes)
	if err == sql.ErrNoRows {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return ed25519.PrivateKey(privBytes), ed25519.PublicKey(pubBytes), nil
}

// GetAllValidKeys implements Store.
func (s *SQLStore) GetAllValidKeys(ctx context.Context) ([]KeyPair, error) {
	query := s.rebind(`SELECT private_key, public_key, expiration FROM keyring WHERE expiration IS NULL OR expiration > ?`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []KeyPair
	for rows.Next() {
		var priv, pub []byte
		var exp sql.NullInt64
		if err := rows.Scan(&priv, &pub, &exp); err != nil {
			return nil, err
		}
		var expiration time.Time
		if exp.Valid {
			expiration = time.Unix(exp.Int64, 0)
		}
		keys = append(keys, KeyPair{
			Private:    ed25519.PrivateKey(priv),
			Public:     ed25519.PublicKey(pub),
			Expiration: expiration,
		})
	}
	return keys, rows.Err()
}

// RotateKeys implements Store.
func (s *SQLStore) RotateKeys(ctx context.Context, newPriv ed25519.PrivateKey, newPub ed25519.PublicKey, gracePeriod time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	expireTime := now.Add(gracePeriod)

	// Set expiration on the current active key
	updateQuery := s.rebind(`UPDATE keyring SET expiration = ? WHERE expiration IS NULL`)
	if _, err := tx.ExecContext(ctx, updateQuery, expireTime.Unix()); err != nil {
		return err
	}

	// Insert the new key
	insertQuery := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insertQuery, []byte(newPriv), []byte(newPub), now.Unix()); err != nil {
		return err
	}

	// Clean up expired keys
	deleteQuery := s.rebind(`DELETE FROM keyring WHERE expiration <= ?`)
	if _, err := tx.ExecContext(ctx, deleteQuery, now.Unix()); err != nil {
		return err
	}

	return tx.Commit()
}

// SaveInitialKey implements Store.
func (s *SQLStore) SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	query := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, query, []byte(priv), []byte(pub), time.Now().Unix())
	return err
}

// EnrollNode implements Store.
func (s *SQLStore) EnrollNode(ctx context.Context, peerID string, biscuit []byte, expiresAt time.Time) error {
	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, biscuit_token, enrolled_at, expires_at, banned) 
			VALUES (?, ?, ?, ?, FALSE)
			ON CONFLICT (peer_id) 
			DO UPDATE SET biscuit_token = EXCLUDED.biscuit_token, enrolled_at = EXCLUDED.enrolled_at, expires_at = EXCLUDED.expires_at`)
	} else {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, biscuit_token, enrolled_at, expires_at, banned) 
			VALUES (?, ?, ?, ?, 0)
			ON CONFLICT (peer_id) 
			DO UPDATE SET biscuit_token = excluded.biscuit_token, enrolled_at = excluded.enrolled_at, expires_at = excluded.expires_at`)
	}

	_, err := s.db.ExecContext(ctx, query, peerID, biscuit, time.Now().Unix(), expiresAt.Unix())
	return err
}

// GetNode implements Store.
func (s *SQLStore) GetNode(ctx context.Context, peerID string) (*EnrolledNode, error) {
	query := s.rebind(`SELECT peer_id, biscuit_token, enrolled_at, expires_at, banned FROM nodes WHERE peer_id = ?`)
	var node EnrolledNode
	var enrolledAtUnix, expiresAtUnix int64
	err := s.db.QueryRowContext(ctx, query, peerID).Scan(&node.PeerID, &node.Biscuit, &enrolledAtUnix, &expiresAtUnix, &node.Banned)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	node.EnrolledAt = time.Unix(enrolledAtUnix, 0)
	node.ExpiresAt = time.Unix(expiresAtUnix, 0)
	return &node, nil
}

// SetNodeBanned implements Store.
func (s *SQLStore) SetNodeBanned(ctx context.Context, peerID string, banned bool) error {
	query := s.rebind(`UPDATE nodes SET banned = ? WHERE peer_id = ?`)
	_, err := s.db.ExecContext(ctx, query, banned, peerID)
	return err
}

// IsNodeBanned implements Store.
func (s *SQLStore) IsNodeBanned(ctx context.Context, peerID string) (bool, error) {
	query := s.rebind(`SELECT banned FROM nodes WHERE peer_id = ?`)
	var banned bool
	err := s.db.QueryRowContext(ctx, query, peerID).Scan(&banned)
	if err == sql.ErrNoRows {
		return false, nil // Not found nodes are not banned by default
	}
	if err != nil {
		return false, err
	}
	return banned, nil
}

// UpsertRouterLease implements Store.
func (s *SQLStore) UpsertRouterLease(ctx context.Context, lease *RouterLease) error {
	addrsBytes, err := json.Marshal(lease.Addresses)
	if err != nil {
		return err
	}

	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO routers (peer_id, multiaddresses, last_lease_renewal, expires_at) 
			VALUES (?, ?, ?, ?)
			ON CONFLICT (peer_id) 
			DO UPDATE SET multiaddresses = EXCLUDED.multiaddresses, last_lease_renewal = EXCLUDED.last_lease_renewal, expires_at = EXCLUDED.expires_at`)
	} else {
		query = s.rebind(`
			INSERT INTO routers (peer_id, multiaddresses, last_lease_renewal, expires_at) 
			VALUES (?, ?, ?, ?)
			ON CONFLICT (peer_id) 
			DO UPDATE SET multiaddresses = excluded.multiaddresses, last_lease_renewal = excluded.last_lease_renewal, expires_at = excluded.expires_at`)
	}

	_, err = s.db.ExecContext(ctx, query, lease.PeerID, string(addrsBytes), lease.LastRenewal.Unix(), lease.ExpiresAt.Unix())
	return err
}

// GetActiveRouters implements Store.
func (s *SQLStore) GetActiveRouters(ctx context.Context) ([]RouterLease, error) {
	query := s.rebind(`SELECT peer_id, multiaddresses, last_lease_renewal, expires_at FROM routers WHERE expires_at > ?`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var leases []RouterLease
	for rows.Next() {
		var l RouterLease
		var addrsStr string
		var lastRenewalUnix, expiresAtUnix int64
		if err := rows.Scan(&l.PeerID, &addrsStr, &lastRenewalUnix, &expiresAtUnix); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(addrsStr), &l.Addresses); err != nil {
			return nil, err
		}
		l.LastRenewal = time.Unix(lastRenewalUnix, 0)
		l.ExpiresAt = time.Unix(expiresAtUnix, 0)
		leases = append(leases, l)
	}
	return leases, rows.Err()
}

// SavePolicy implements Store.
func (s *SQLStore) SavePolicy(ctx context.Context, policy *api.PolicyConfig) error {
	data, err := yaml.Marshal(policy)
	if err != nil {
		return err
	}

	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO policies (id, content, updated_at) 
			VALUES ('mesh-policy', ?, ?)
			ON CONFLICT (id) 
			DO UPDATE SET content = EXCLUDED.content, updated_at = EXCLUDED.updated_at`)
	} else {
		query = s.rebind(`
			INSERT INTO policies (id, content, updated_at) 
			VALUES ('mesh-policy', ?, ?)
			ON CONFLICT (id) 
			DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at`)
	}

	_, err = s.db.ExecContext(ctx, query, string(data), time.Now().Unix())
	return err
}

// GetPolicy implements Store.
func (s *SQLStore) GetPolicy(ctx context.Context) (*api.PolicyConfig, error) {
	query := s.rebind(`SELECT content FROM policies WHERE id = 'mesh-policy'`)
	var data string
	err := s.db.QueryRowContext(ctx, query).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var policy api.PolicyConfig
	if err := yaml.Unmarshal([]byte(data), &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// Close implements Store.
func (s *SQLStore) Close() error {
	return s.db.Close()
}
