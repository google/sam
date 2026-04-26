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

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: gen_db <db_path>")
	}
	dbPath := os.Args[1]

	err := os.MkdirAll(filepath.Dir(dbPath), 0700)
	if err != nil {
		log.Fatal(err)
	}

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("identity"))
		if err != nil {
			return err
		}
		// The following constants are mock values used for testing.
		// 'mock-biscuit-token' is a dummy token string.
		// The hub public key is a dummy 32-byte hex string (all zeros).
		if err := b.Put([]byte("identity_biscuit"), []byte("mock-biscuit-token")); err != nil {
			return err
		}
		if err := b.Put([]byte("hub_public_key"), []byte("0000000000000000000000000000000000000000000000000000000000000000")); err != nil {
			return err
		}
		addrsData, _ := json.Marshal([]string{"/ip4/127.0.0.1/tcp/4002/p2p/QmYyQSo1sn1GjUuQwca9AdvV8Zeyvmxrww8dDnewPrfJs9"})
		if err := b.Put([]byte("hub_addresses"), addrsData); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
