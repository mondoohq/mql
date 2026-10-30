// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package javascript

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHashes(t *testing.T) {
	// A single sha512 SRI decodes to a SHA-512 hash with a lower-case hex value.
	got := NewHashes("sha512-wLH6RzYPQAryrsJakc9I3k0aFWE/cJyWoUD8dQy186jxwtLgeQdVc0+NegNyab7MIPi7Hsv9A3hx6lM1rPH94A==")
	require.Len(t, got, 1)
	assert.Equal(t, "SHA-512", got[0].Alg)
	assert.Equal(t, "c0b1fa47360f400af2aec25a91cf48de4d1a15613f709c96a140fc750cb5f3a8f1c2d2e0790755734f8d7a037269becc20f8bb1ecbfd037871ea5335acf1fde0", got[0].Value)

	// Multiple space-separated entries yield one hash each, unknown algs skipped.
	multi := NewHashes("sha1-qBk8lPTdW3wLpjSFMv40C0OT13c= whirlpool-notanalg")
	require.Len(t, multi, 1)
	assert.Equal(t, "SHA-1", multi[0].Alg)

	// Empty, malformed (no dash), and undecodable base64 all yield nothing.
	assert.Nil(t, NewHashes(""))
	assert.Nil(t, NewHashes("   "))
	assert.Nil(t, NewHashes("sha512"))
	assert.Nil(t, NewHashes("sha512-!!!not base64!!!"))
}
