package db

import (
	"encoding/json"
	"fmt"
	"time"
)

// Codec keeps serialization pluggable while defaulting to JSON.
type Codec interface {
	Marshal(version int, v any) ([]byte, error)
	Unmarshal(data []byte, currentVersion int, v any, transform MigrationFunc) error
}

type JSONCodec struct{}

type versionedEnvelope struct {
	Metadata Metadata        `json:"metadata"`
	Payload  json.RawMessage `json:"payload"`
}

// MigrationFunc can mutate payload map in-memory when older versions are read.
// It receives the raw payload map and source version.
type MigrationFunc func(payload map[string]any, fromVersion int) map[string]any

func (JSONCodec) Marshal(version int, v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	env := versionedEnvelope{
		Metadata: Metadata{Version: version, Updated: time.Now().UTC()},
		Payload:  payload,
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

func (JSONCodec) Unmarshal(data []byte, currentVersion int, v any, transform MigrationFunc) error {
	var original versionedEnvelope
	if err := json.Unmarshal(data, &original); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}
	fromVersion := original.Metadata.Version

	migrated := migrate(data, currentVersion)
	var env versionedEnvelope
	if err := json.Unmarshal(migrated, &env); err != nil {
		return fmt.Errorf("unmarshal migrated envelope: %w", err)
	}
	payload := env.Payload
	if transform != nil && fromVersion < currentVersion {
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			return fmt.Errorf("unmarshal legacy payload map: %w", err)
		}
		m = transform(m, fromVersion)
		updatedPayload, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("marshal migrated payload map: %w", err)
		}
		payload = updatedPayload
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	return nil
}

// migrate upgrades envelope metadata lazily at read-time.
func migrate(data []byte, currentVersion int) []byte {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return data
	}
	meta, ok := raw["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
		raw["metadata"] = meta
	}
	version := 0
	if v, ok := meta["version"]; ok {
		switch typed := v.(type) {
		case float64:
			version = int(typed)
		case int:
			version = typed
		}
	}
	if version < currentVersion {
		meta["version"] = currentVersion
		meta["updated_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return data
	}
	return out
}
