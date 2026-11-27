// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package secretid

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// KeySize is the length in bytes of a space key.
const KeySize = 32

var (
	// ErrNoKey is returned when no key is given.
	ErrNoKey = errors.New("secretid: no key")
	// ErrClosed is returned when a key is used after Close.
	ErrClosed = errors.New("secretid: key is closed")
	// ErrKeySize is returned by NewKey for a key that is not KeySize bytes.
	ErrKeySize = errors.New("secretid: key must be 32 bytes")
	// ErrNoKeyID is returned by NewKey for an empty key id.
	ErrNoKeyID = errors.New("secretid: key id is empty")
	// errNotSerializable is returned by every serializer on Key.
	errNotSerializable = errors.New("secretid: a key cannot be serialized")
)

// Key is a space's identity key. It lives in memory only: its bytes are not
// exported, it has no String method, every formatting verb prints only its key
// id, and the JSON, text and binary serializers refuse it. Close zeroes the
// bytes; a closed key computes nothing.
//
// A Key is safe for concurrent use.
type Key struct {
	mu     sync.RWMutex
	id     string
	b      []byte
	closed bool
}

// NewKey builds a key from the key id and the key bytes the platform returns.
// The bytes are copied; the caller should zero its own copy once NewKey
// returns. keyID names the key version and accompanies every id computed with
// the key, so ids computed under different key versions can be told apart.
func NewKey(keyID string, key []byte) (*Key, error) {
	if keyID == "" {
		return nil, ErrNoKeyID
	}
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	b := make([]byte, KeySize)
	copy(b, key)
	return &Key{id: keyID, b: b}, nil
}

// KeyID returns the id of the key version. It is not secret.
func (k *Key) KeyID() string {
	if k == nil {
		return ""
	}
	return k.id
}

// Close zeroes the key bytes. Every later use of the key fails with ErrClosed.
// Close is idempotent.
func (k *Key) Close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.b {
		k.b[i] = 0
	}
	k.closed = true
}

// redacted is what every formatter prints for a key.
func (k *Key) redacted() string {
	if k == nil {
		return "secretid.Key(nil)"
	}
	return "secretid.Key(" + k.id + ")"
}

// Format implements fmt.Formatter so that %v, %+v, %#v, %s, %x and every
// other verb print the key id only, never the key bytes.
func (k *Key) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(k.redacted()))
}

// LogValue implements slog.LogValuer so that a key passed to a structured
// logger logs as its key id only.
func (k *Key) LogValue() slog.Value {
	return slog.StringValue(k.redacted())
}

// MarshalJSON refuses to serialize the key.
func (k *Key) MarshalJSON() ([]byte, error) { return nil, errNotSerializable }

// MarshalText refuses to serialize the key.
func (k *Key) MarshalText() ([]byte, error) { return nil, errNotSerializable }

// MarshalBinary refuses to serialize the key.
func (k *Key) MarshalBinary() ([]byte, error) { return nil, errNotSerializable }

// GobEncode refuses to serialize the key.
func (k *Key) GobEncode() ([]byte, error) { return nil, errNotSerializable }
