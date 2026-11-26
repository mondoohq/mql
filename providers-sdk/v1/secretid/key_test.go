// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package secretid

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All cases are synthetic: the key is a fixed byte pattern.

func TestNewKey(t *testing.T) {
	b := make([]byte, KeySize)
	_, err := NewKey("", b)
	assert.ErrorIs(t, err, ErrNoKeyID)

	_, err = NewKey("k1", b[:16])
	assert.ErrorIs(t, err, ErrKeySize)

	_, err = NewKey("k1", append(b, 0))
	assert.ErrorIs(t, err, ErrKeySize)

	k, err := NewKey("k1", b)
	require.NoError(t, err)
	assert.Equal(t, "k1", k.KeyID())
	assert.Equal(t, "", (*Key)(nil).KeyID())
}

// TestNewKeyCopies checks that zeroing the caller's buffer, which callers are
// told to do, does not change the key.
func TestNewKeyCopies(t *testing.T) {
	b := make([]byte, KeySize)
	for i := range b {
		b[i] = byte(i)
	}
	k, err := NewKey("k1", b)
	require.NoError(t, err)
	before, err := ID(k, "x")
	require.NoError(t, err)

	for i := range b {
		b[i] = 0
	}
	after, err := ID(k, "x")
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestKeyClose(t *testing.T) {
	k := testKey(t, "k1", 0)
	k.Close()
	k.Close() // idempotent

	assert.Equal(t, make([]byte, KeySize), k.b, "Close must zero the key bytes")
	_, err := ID(k, "x")
	assert.ErrorIs(t, err, ErrClosed)
	_, err = IDs([]*Key{k}, "x")
	assert.ErrorIs(t, err, ErrClosed)
	_, err = OccurrenceID(k, "r", "p", 1, "x")
	assert.ErrorIs(t, err, ErrClosed)
	_, err = LineHash(k, "x")
	assert.ErrorIs(t, err, ErrClosed)

	(*Key)(nil).Close() // no panic
}

// TestKeyNeverPrinted checks that no formatting verb, logger or serializer
// reveals the key bytes, in raw or hex form.
func TestKeyNeverPrinted(t *testing.T) {
	k := testKey(t, "key-v7", 0x41) // bytes "ABCDEF…", printable on purpose
	raw := string(k.b)
	hexed := hex.EncodeToString(k.b)

	check := func(t *testing.T, out string) {
		t.Helper()
		assert.NotContains(t, out, raw[:8])
		assert.NotContains(t, out, hexed[:16])
		assert.NotContains(t, out, "65 66 67") // %v of a byte slice
		assert.NotContains(t, out, "[65")
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		t.Run(verb, func(t *testing.T) {
			out := fmt.Sprintf(verb, k)
			check(t, out)
			assert.Contains(t, out, "key-v7")
		})
	}
	t.Run("embedded in a struct", func(t *testing.T) {
		out := fmt.Sprintf("%+v", struct{ K *Key }{k})
		check(t, out)
	})

	t.Run("slog", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("scan", "key", k)
		check(t, buf.String())
		assert.Contains(t, buf.String(), "key-v7")
	})

	t.Run("json", func(t *testing.T) {
		out, err := json.Marshal(struct{ K *Key }{k})
		assert.Error(t, err)
		check(t, string(out))
	})

	t.Run("gob", func(t *testing.T) {
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(k)
		assert.Error(t, err)
		check(t, buf.String())
	})

	t.Run("text and binary", func(t *testing.T) {
		_, err := k.MarshalText()
		assert.Error(t, err)
		_, err = k.MarshalBinary()
		assert.Error(t, err)
	})

	assert.Equal(t, "secretid.Key(nil)", fmt.Sprint((*Key)(nil)))
}

// TestKeyConcurrentClose runs ids and Close concurrently; with -race it
// checks the lock. Every result is either a valid id or ErrClosed.
func TestKeyConcurrentClose(t *testing.T) {
	k := testKey(t, "k1", 0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				id, err := ID(k, "x")
				if err != nil {
					assert.ErrorIs(t, err, ErrClosed)
					continue
				}
				assert.True(t, strings.HasPrefix(id, "v1:"))
			}
		})
	}
	wg.Go(k.Close)
	wg.Wait()
}
