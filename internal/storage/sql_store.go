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
	log "github.com/ipfs/go-log/v2"
	"gopkg.in/yaml.v2"

	// Register PG and SQLite drivers
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var logger = log.Logger("sam-storage")

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

type migration struct {
	version  int
	sqlite   []string
	postgres []string
}

var migrations = []migration{
	{
		version: 1,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS keyring (
				id SERIAL PRIMARY KEY,
				private_key BYTEA NOT NULL,
				public_key BYTEA NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS nodes (
				peer_id VARCHAR(255) PRIMARY KEY,
				public_key BYTEA NOT NULL,
				biscuit_token BYTEA NOT NULL,
				role VARCHAR(64) NOT NULL,
				enrollment_type VARCHAR(64) NOT NULL,
				claims_json TEXT,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS routers (
				peer_id VARCHAR(255) PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS policies (
				id VARCHAR(255) PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
				id VARCHAR(64) PRIMARY KEY,
				token_hash VARCHAR(64) UNIQUE NOT NULL,
				role VARCHAR(64) NOT NULL,
				max_usages INT NOT NULL,
				usages_count INT NOT NULL,
				description TEXT,
				created_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS enrollment_requests (
				id VARCHAR(64) PRIMARY KEY,
				peer_id VARCHAR(255) UNIQUE NOT NULL,
				public_key BYTEA NOT NULL,
				token_id VARCHAR(64) REFERENCES bootstrap_tokens(id),
				status INT NOT NULL,
				biscuit_token BYTEA,
				created_at BIGINT NOT NULL,
				resolved_at BIGINT,
				resolved_by VARCHAR(255)
			)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS keyring (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				private_key BLOB NOT NULL,
				public_key BLOB NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS nodes (
				peer_id TEXT PRIMARY KEY,
				public_key BLOB NOT NULL,
				biscuit_token BLOB NOT NULL,
				role TEXT NOT NULL,
				enrollment_type TEXT NOT NULL,
				claims_json TEXT,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS routers (
				peer_id TEXT PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS policies (
				id TEXT PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
				id TEXT PRIMARY KEY,
				token_hash TEXT UNIQUE NOT NULL,
				role TEXT NOT NULL,
				max_usages INTEGER NOT NULL,
				usages_count INTEGER NOT NULL,
				description TEXT,
				created_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS enrollment_requests (
				id TEXT PRIMARY KEY,
				peer_id TEXT UNIQUE NOT NULL,
				public_key BLOB NOT NULL,
				token_id TEXT REFERENCES bootstrap_tokens(id),
				status INTEGER NOT NULL,
				biscuit_token BLOB,
				created_at BIGINT NOT NULL,
				resolved_at BIGINT,
				resolved_by TEXT
			)`,
		},
	},
	{
		version: 2,
		postgres: []string{
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS connected_peers TEXT`,
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS dht_size INT`,
		},
		sqlite: []string{
			`ALTER TABLE routers ADD COLUMN connected_peers TEXT`,
			`ALTER TABLE routers ADD COLUMN dht_size INTEGER`,
		},
	},
}

func (s *SQLStore) initSchema() error {
	// Create schema_migrations table
	createMigrationsTable := `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`
	if _, err := s.db.Exec(createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	var currentVersion int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to check current schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		err := func() error {
			tx, err := s.db.Begin()
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()

			queries := m.sqlite
			if s.isPostgres() {
				queries = m.postgres
			}

			for _, query := range queries {
				if _, err := tx.Exec(query); err != nil {
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "duplicate column") || strings.Contains(errStr, "already exists") {
						continue
					}
					return fmt.Errorf("migration version %d failed: query %q failed: %w", m.version, query, err)
				}
			}

			insertQuery := s.rebind("INSERT INTO schema_migrations (version) VALUES (?)")
			if _, err := tx.Exec(insertQuery, m.version); err != nil {
				return fmt.Errorf("failed to update schema_migrations version: %w", err)
			}

			if err := tx.Commit(); err != nil {
				return err
			}
			logger.Infof("Applied schema migration version %d successfully", m.version)
			return nil
		}()
		if err != nil {
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
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
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
			expiration = time.UnixMilli(exp.Int64)
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
	if _, err := tx.ExecContext(ctx, updateQuery, expireTime.UnixMilli()); err != nil {
		return err
	}

	// Insert the new key
	insertQuery := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insertQuery, []byte(newPriv), []byte(newPub), now.UnixMilli()); err != nil {
		return err
	}

	// Clean up expired keys
	deleteQuery := s.rebind(`DELETE FROM keyring WHERE expiration <= ?`)
	if _, err := tx.ExecContext(ctx, deleteQuery, now.UnixMilli()); err != nil {
		return err
	}

	return tx.Commit()
}

// SaveInitialKey implements Store.
func (s *SQLStore) SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	query := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, query, []byte(priv), []byte(pub), time.Now().UnixMilli())
	return err
}

// EnrollNode implements Store.
func (s *SQLStore) EnrollNode(ctx context.Context, node *EnrolledNode) error {
	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, enrolled_at, expires_at, banned) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE)
			ON CONFLICT (peer_id) 
			DO UPDATE SET public_key = EXCLUDED.public_key, biscuit_token = EXCLUDED.biscuit_token, role = EXCLUDED.role, enrollment_type = EXCLUDED.enrollment_type, claims_json = EXCLUDED.claims_json, enrolled_at = EXCLUDED.enrolled_at, expires_at = EXCLUDED.expires_at`)
	} else {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, enrolled_at, expires_at, banned) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
			ON CONFLICT (peer_id) 
			DO UPDATE SET public_key = excluded.public_key, biscuit_token = excluded.biscuit_token, role = excluded.role, enrollment_type = excluded.enrollment_type, claims_json = excluded.claims_json, enrolled_at = excluded.enrolled_at, expires_at = excluded.expires_at`)
	}

	_, err := s.db.ExecContext(ctx, query,
		node.PeerID,
		node.PublicKey,
		node.Biscuit,
		node.Role,
		node.EnrollmentType,
		node.ClaimsJSON,
		node.EnrolledAt.UnixMilli(),
		node.ExpiresAt.UnixMilli(),
	)
	return err
}

// GetNode implements Store.
func (s *SQLStore) GetNode(ctx context.Context, peerID string) (*EnrolledNode, error) {
	query := s.rebind(`SELECT peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, enrolled_at, expires_at, banned FROM nodes WHERE peer_id = ?`)
	var node EnrolledNode
	var enrolledAtUnix, expiresAtUnix int64
	err := s.db.QueryRowContext(ctx, query, peerID).Scan(
		&node.PeerID,
		&node.PublicKey,
		&node.Biscuit,
		&node.Role,
		&node.EnrollmentType,
		&node.ClaimsJSON,
		&enrolledAtUnix,
		&expiresAtUnix,
		&node.Banned,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	node.EnrolledAt = time.UnixMilli(enrolledAtUnix)
	node.ExpiresAt = time.UnixMilli(expiresAtUnix)
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
	peersBytes, err := json.Marshal(lease.ConnectedPeers)
	if err != nil {
		return err
	}

	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO routers (peer_id, multiaddresses, last_lease_renewal, expires_at, connected_peers, dht_size) 
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (peer_id) 
			DO UPDATE SET multiaddresses = EXCLUDED.multiaddresses, last_lease_renewal = EXCLUDED.last_lease_renewal, expires_at = EXCLUDED.expires_at, connected_peers = EXCLUDED.connected_peers, dht_size = EXCLUDED.dht_size`)
	} else {
		query = s.rebind(`
			INSERT INTO routers (peer_id, multiaddresses, last_lease_renewal, expires_at, connected_peers, dht_size) 
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (peer_id) 
			DO UPDATE SET multiaddresses = excluded.multiaddresses, last_lease_renewal = excluded.last_lease_renewal, expires_at = excluded.expires_at, connected_peers = excluded.connected_peers, dht_size = excluded.dht_size`)
	}

	_, err = s.db.ExecContext(ctx, query, lease.PeerID, string(addrsBytes), lease.LastRenewal.UnixMilli(), lease.ExpiresAt.UnixMilli(), string(peersBytes), lease.DHTSize)
	return err
}

// GetActiveRouters implements Store.
func (s *SQLStore) GetActiveRouters(ctx context.Context) ([]RouterLease, error) {
	query := s.rebind(`SELECT peer_id, multiaddresses, last_lease_renewal, expires_at, connected_peers, dht_size FROM routers WHERE expires_at > ?`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var leases []RouterLease
	for rows.Next() {
		var l RouterLease
		var addrsStr string
		var peersStr sql.NullString
		var dhtSize sql.NullInt64
		var lastRenewalUnix, expiresAtUnix int64
		if err := rows.Scan(&l.PeerID, &addrsStr, &lastRenewalUnix, &expiresAtUnix, &peersStr, &dhtSize); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(addrsStr), &l.Addresses); err != nil {
			return nil, err
		}
		if peersStr.Valid && peersStr.String != "" {
			if err := json.Unmarshal([]byte(peersStr.String), &l.ConnectedPeers); err != nil {
				return nil, err
			}
		}
		if dhtSize.Valid {
			l.DHTSize = int(dhtSize.Int64)
		}
		l.LastRenewal = time.UnixMilli(lastRenewalUnix)
		l.ExpiresAt = time.UnixMilli(expiresAtUnix)
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

	_, err = s.db.ExecContext(ctx, query, string(data), time.Now().UnixMilli())
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

// SaveBootstrapToken persists a new bootstrap token.
func (s *SQLStore) SaveBootstrapToken(ctx context.Context, token *BootstrapToken) error {
	query := `INSERT INTO bootstrap_tokens (id, token_hash, role, max_usages, usages_count, description, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, s.rebind(query),
		token.ID,
		token.TokenHash,
		token.Role,
		token.MaxUsages,
		token.UsagesCount,
		token.Description,
		token.CreatedAt.Unix(),
		token.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to save bootstrap token: %w", err)
	}
	return nil
}

// GetBootstrapToken retrieves a bootstrap token by its ID.
func (s *SQLStore) GetBootstrapToken(ctx context.Context, id string) (*BootstrapToken, error) {
	query := `SELECT id, token_hash, role, max_usages, usages_count, description, created_at, expires_at 
		FROM bootstrap_tokens WHERE id = ?`
	var created, expires int64
	var t BootstrapToken
	err := s.db.QueryRowContext(ctx, s.rebind(query), id).Scan(
		&t.ID,
		&t.TokenHash,
		&t.Role,
		&t.MaxUsages,
		&t.UsagesCount,
		&t.Description,
		&created,
		&expires,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan bootstrap token: %w", err)
	}
	t.CreatedAt = time.Unix(created, 0)
	t.ExpiresAt = time.Unix(expires, 0)
	return &t, nil
}

// IncrementBootstrapTokenUsage increments usage count.
func (s *SQLStore) IncrementBootstrapTokenUsage(ctx context.Context, id string) error {
	query := `UPDATE bootstrap_tokens SET usages_count = usages_count + 1 WHERE id = ?`
	_, err := s.db.ExecContext(ctx, s.rebind(query), id)
	if err != nil {
		return fmt.Errorf("failed to increment usage: %w", err)
	}
	return nil
}

// CreateEnrollmentRequest saves a new pending request.
func (s *SQLStore) CreateEnrollmentRequest(ctx context.Context, req *EnrollmentRequest) error {
	query := `INSERT INTO enrollment_requests (id, peer_id, public_key, token_id, status, biscuit_token, created_at, resolved_at, resolved_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var resAt sql.NullInt64
	if req.ResolvedAt != nil {
		resAt = sql.NullInt64{Int64: req.ResolvedAt.Unix(), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, s.rebind(query),
		req.ID,
		req.PeerID,
		req.PublicKey,
		req.TokenID,
		int(req.Status),
		req.BiscuitToken,
		req.CreatedAt.Unix(),
		resAt,
		req.ResolvedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create enrollment request: %w", err)
	}
	return nil
}

// GetEnrollmentRequest retrieves request by PeerID.
func (s *SQLStore) GetEnrollmentRequest(ctx context.Context, peerID string) (*EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests WHERE peer_id = ?`
	return s.scanEnrollmentRequest(s.db.QueryRowContext(ctx, s.rebind(query), peerID))
}

// GetEnrollmentRequestByID retrieves request by UUID.
func (s *SQLStore) GetEnrollmentRequestByID(ctx context.Context, id string) (*EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests WHERE id = ?`
	return s.scanEnrollmentRequest(s.db.QueryRowContext(ctx, s.rebind(query), id))
}

type scannable interface {
	Scan(dest ...any) error
}

func (s *SQLStore) scanEnrollmentRequest(row scannable) (*EnrollmentRequest, error) {
	var created int64
	var resAt sql.NullInt64
	var statusVal int
	var req EnrollmentRequest

	err := row.Scan(
		&req.ID,
		&req.PeerID,
		&req.PublicKey,
		&req.TokenID,
		&statusVal,
		&req.BiscuitToken,
		&created,
		&resAt,
		&req.ResolvedBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan enrollment request: %w", err)
	}

	req.CreatedAt = time.Unix(created, 0)
	req.Status = api.EnrollmentStatus(statusVal)
	if resAt.Valid {
		t := time.Unix(resAt.Int64, 0)
		req.ResolvedAt = &t
	}
	return &req, nil
}

// ListEnrollmentRequests retrieves all requests.
func (s *SQLStore) ListEnrollmentRequests(ctx context.Context) ([]EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, s.rebind(query))
	if err != nil {
		return nil, fmt.Errorf("failed to query enrollment requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var reqs []EnrollmentRequest
	for rows.Next() {
		req, err := s.scanEnrollmentRequest(rows)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, *req)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return reqs, nil
}

// UpdateEnrollmentRequest updates status, timestamp and biscuit token.
func (s *SQLStore) UpdateEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error {
	query := `UPDATE enrollment_requests SET status = ?, biscuit_token = ?, resolved_at = ?, resolved_by = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, s.rebind(query),
		int(status),
		biscuit,
		time.Now().Unix(),
		resolvedBy,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to update enrollment request: %w", err)
	}
	return nil
}

// ListNodes retrieves all enrolled nodes.
func (s *SQLStore) ListNodes(ctx context.Context) ([]EnrolledNode, error) {
	query := s.rebind(`SELECT peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, enrolled_at, expires_at, banned FROM nodes ORDER BY enrolled_at DESC`)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var nodes []EnrolledNode
	for rows.Next() {
		var node EnrolledNode
		var claimsJSON sql.NullString
		var enrolledAtUnix, expiresAtUnix int64
		err := rows.Scan(
			&node.PeerID,
			&node.PublicKey,
			&node.Biscuit,
			&node.Role,
			&node.EnrollmentType,
			&claimsJSON,
			&enrolledAtUnix,
			&expiresAtUnix,
			&node.Banned,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan enrolled node: %w", err)
		}
		if claimsJSON.Valid {
			node.ClaimsJSON = claimsJSON.String
		}
		node.EnrolledAt = time.UnixMilli(enrolledAtUnix)
		node.ExpiresAt = time.UnixMilli(expiresAtUnix)
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// ListBootstrapTokens retrieves all bootstrap tokens.
func (s *SQLStore) ListBootstrapTokens(ctx context.Context) ([]BootstrapToken, error) {
	query := s.rebind(`SELECT id, token_hash, role, max_usages, usages_count, description, created_at, expires_at FROM bootstrap_tokens ORDER BY created_at DESC`)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query bootstrap tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []BootstrapToken
	for rows.Next() {
		var t BootstrapToken
		var desc sql.NullString
		var created, expires int64
		err := rows.Scan(
			&t.ID,
			&t.TokenHash,
			&t.Role,
			&t.MaxUsages,
			&t.UsagesCount,
			&desc,
			&created,
			&expires,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bootstrap token: %w", err)
		}
		if desc.Valid {
			t.Description = desc.String
		}
		t.CreatedAt = time.Unix(created, 0)
		t.ExpiresAt = time.Unix(expires, 0)
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// Close implements Store.
func (s *SQLStore) Close() error {
	return s.db.Close()
}
