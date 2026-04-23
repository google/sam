package main

import (
	"fmt"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

const (
	bucketIdentity = "identity"
	keyBiscuit     = "identity_biscuit"
	keyPrivKey     = "node_private_key"
)

type Store struct {
	db *bbolt.DB
}

func GetDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "sam-mesh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func NewStore(dir string) (*Store, error) {
	dbPath := filepath.Join(dir, "agent.db")
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, _ = tx.CreateBucketIfNotExists([]byte(bucketIdentity))
		return nil
	})

	return &Store{db: db}, err
}

func (s *Store) SaveIdentity(biscuit string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte(keyBiscuit), []byte(biscuit))
	})
}

func (s *Store) LoadIdentity() (string, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte(keyBiscuit))
		return nil
	})
	if len(val) == 0 {
		return "", fmt.Errorf("no identity found")
	}
	return string(val), nil
}

func (s *Store) SaveKey(key []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		return b.Put([]byte(keyPrivKey), key)
	})
}

func (s *Store) LoadKey() ([]byte, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		val = b.Get([]byte(keyPrivKey))
		return nil
	})
	return val, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
