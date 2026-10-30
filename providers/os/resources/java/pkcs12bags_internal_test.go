// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from RFC 2268 section 5, run backwards: decrypting the published
// ciphertext must give the published plaintext.
func TestRC2DecryptRFC2268Vectors(t *testing.T) {
	tests := []struct {
		key        string
		t1         int
		plaintext  string
		ciphertext string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
	}
	for _, tt := range tests {
		key, err := hex.DecodeString(tt.key)
		require.NoError(t, err)
		ct, err := hex.DecodeString(tt.ciphertext)
		require.NoError(t, err)

		got := make([]byte, 8)
		c, err := newRC2(key, tt.t1)
		require.NoError(t, err)
		c.Decrypt(got, ct)
		assert.Equal(t, tt.plaintext, hex.EncodeToString(got), "key %s t1 %d", tt.key, tt.t1)
	}
}

// RFC 7292 publishes no vectors for its key derivation. These are the widely
// shared known answers for the input "smeg" (as the BMPString below), salt
// 0A58CF64530D823F and one iteration, the same ones the Bouncy Castle and
// OpenSSL-derived PKCS#12 test suites check against.
func TestPKCS12KDFKnownAnswer(t *testing.T) {
	salt, _ := hex.DecodeString("0a58cf64530d823f")
	in, _ := hex.DecodeString("0073006d006500670000")
	key := pkcs12KDF(sha1.New, salt, in, 1, 1, 24)
	assert.Equal(t, "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3", hex.EncodeToString(key))
	iv := pkcs12KDF(sha1.New, salt, in, 1, 2, 8)
	assert.Equal(t, "79993dfe048d3b76", hex.EncodeToString(iv))
}

// PKCS#12 keys its PBE schemes with the UTF-16BE encoding plus a two-byte
// terminator, including for characters outside the BMP.
func TestBMPPasswordEncoding(t *testing.T) {
	assert.Equal(t, "0000", hex.EncodeToString(bmpPassword("")))
	assert.Equal(t, "0061006200e920ac0000", hex.EncodeToString(bmpPassword("abé€")))
	assert.Equal(t, "d83cdf3f0000", hex.EncodeToString(bmpPassword("\U0001F33F")))
}

func TestNewRC2RejectsUnusableKeys(t *testing.T) {
	_, err := newRC2(nil, 40)
	assert.Error(t, err)
	_, err = newRC2(make([]byte, 129), 64)
	assert.Error(t, err)
}

func TestCBCDecryptRejectsBadPadding(t *testing.T) {
	block, err := newRC2([]byte{1, 2, 3, 4, 5}, 40)
	require.NoError(t, err)
	_, err = cbcDecrypt(block, make([]byte, 8), make([]byte, 16))
	assert.ErrorIs(t, err, errPKCS12Decrypt)
	_, err = cbcDecrypt(block, make([]byte, 8), make([]byte, 7))
	assert.ErrorIs(t, err, errPKCS12Decrypt, "not a whole number of blocks")
}
