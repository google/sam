package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const defaultFederation = "default"

// Manager owns a pool of per-federation bbolt stores under a shared base directory.
// Each federation gets a physically isolated file: <baseDir>/<name>.db.
// The master identity store (state.db) is intentionally kept separate and is
// NOT managed here.
type Manager struct {
	mu      sync.Mutex
	stores  map[string]*BoltStore
	baseDir string
}

// FederationsDir returns the default directory for federation databases:
// ~/.config/sam/federations/
func FederationsDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	return filepath.Join(cfgDir, "sam", "federations"), nil
}

// NewManager creates a Manager rooted at the default federations directory.
func NewManager() (*Manager, error) {
	dir, err := FederationsDir()
	if err != nil {
		return nil, err
	}
	return NewManagerAt(dir)
}

// NewManagerAt creates a Manager rooted at the given directory.
// The directory is created lazily when the first federation is opened.
func NewManagerAt(dir string) (*Manager, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("manager base directory must not be empty")
	}
	return &Manager{
		stores:  make(map[string]*BoltStore),
		baseDir: dir,
	}, nil
}

// Store returns (opening lazily if needed) the Store for the given federation.
// Name must be non-empty and contain only safe filesystem characters (letters,
// digits, hyphens, underscores, dots). Use the constant DefaultFederation for
// the standard "default" federation.
func (m *Manager) Store(fedID string) (Store, error) {
	fedID = strings.TrimSpace(fedID)
	if fedID == "" {
		fedID = defaultFederation
	}
	if err := validateFedID(fedID); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.stores[fedID]; ok {
		return s, nil
	}

	path := filepath.Join(m.baseDir, fedID+".db")
	s, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening federation %q: %w", fedID, err)
	}
	m.stores[fedID] = s
	return s, nil
}

// DefaultStore is shorthand for Store(defaultFederation).
func (m *Manager) DefaultStore() (Store, error) {
	return m.Store(defaultFederation)
}

// DropFederation closes the store for the given federation and deletes its
// physical file from disk. Calling this while other goroutines are actively
// using the returned Store is unsafe.
func (m *Manager) DropFederation(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("federation name must not be empty")
	}
	if err := validateFedID(name); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.stores[name]; ok {
		if err := s.Close(); err != nil {
			return fmt.Errorf("closing federation %q: %w", name, err)
		}
		delete(m.stores, name)
	}

	path := filepath.Join(m.baseDir, name+".db")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting federation db %q: %w", name, err)
	}
	return nil
}

// ListFederations returns the names of all federation databases that exist on
// disk under the manager's base directory (including those not yet opened).
func (m *Manager) ListFederations() ([]string, error) {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing federations dir %q: %w", m.baseDir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".db") {
			names = append(names, strings.TrimSuffix(e.Name(), ".db"))
		}
	}
	return names, nil
}

// Close closes all open federation stores.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for name, s := range m.stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("closing federation %q: %w", name, err)
		}
		delete(m.stores, name)
	}
	return firstErr
}

// BaseDir returns the directory where federation databases are stored.
func (m *Manager) BaseDir() string { return m.baseDir }

// validateFedID rejects names that could be used for path traversal.
func validateFedID(name string) error {
	if strings.ContainsAny(name, `/\:*?"<>|`) || strings.Contains(name, "..") {
		return fmt.Errorf("federation name %q contains invalid characters", name)
	}
	return nil
}

// FederatedGet is a convenience wrapper that opens the federation store and
// performs a single Get. Useful for one-off lookups; prefer Store() when
// making multiple calls to avoid repeated open overhead.
func (m *Manager) FederatedGet(ctx context.Context, fedID, bucket, key string) ([]byte, error) {
	s, err := m.Store(fedID)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, bucket, key)
}

// FederatedPut is a convenience wrapper; see FederatedGet.
func (m *Manager) FederatedPut(ctx context.Context, fedID, bucket, key string, value []byte) error {
	s, err := m.Store(fedID)
	if err != nil {
		return err
	}
	return s.Put(ctx, bucket, key, value)
}

// FederatedDelete is a convenience wrapper; see FederatedGet.
func (m *Manager) FederatedDelete(ctx context.Context, fedID, bucket, key string) error {
	s, err := m.Store(fedID)
	if err != nil {
		return err
	}
	return s.Delete(ctx, bucket, key)
}
