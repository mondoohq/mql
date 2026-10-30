// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnssec

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rfc4034Key is the 1024-bit RSASHA1 example key from RFC 4034 appendix B,
// reused by RFC 4509 for the SHA-256 DS example. Both DS digests below are
// published values, so they pin the digest computation against the standard
// rather than against this implementation's own output.
const rfc4034Key = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/" +
	"2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvx" +
	"egXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc" +
	"nOf+EPbtG9DMBmADjFDc2w/rljwvFw=="

func TestFlagBits(t *testing.T) {
	cases := []struct {
		name          string
		flags         int
		keySigningKey bool
		zoneKey       bool
		revoked       bool
	}{
		{name: "zone signing key", flags: 256, keySigningKey: false, zoneKey: true},
		{name: "key signing key", flags: 257, keySigningKey: true, zoneKey: true},
		// The reason these are bit tests and not equality tests: a revoked KSK
		// reads 385, and `flags == 257` would classify it as a zone signing key.
		{name: "revoked key signing key", flags: 385, keySigningKey: true, zoneKey: true, revoked: true},
		{name: "revoked zone signing key", flags: 384, keySigningKey: false, zoneKey: true, revoked: true},
		{name: "no flags at all", flags: 0},
		// A key without the zone bit cannot validate zone data, whatever else
		// it claims about itself.
		{name: "secure entry point without the zone bit", flags: 1, keySigningKey: true, zoneKey: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.keySigningKey, IsKeySigningKey(tc.flags), "IsKeySigningKey")
			assert.Equal(t, tc.zoneKey, IsZoneKey(tc.flags), "IsZoneKey")
			assert.Equal(t, tc.revoked, IsRevoked(tc.flags), "IsRevoked")
		})
	}
}

func TestAlgorithmName(t *testing.T) {
	assert.Equal(t, "RSASHA256", AlgorithmName(8))
	assert.Equal(t, "ECDSAP256SHA256", AlgorithmName(13))
	assert.Equal(t, "ED25519", AlgorithmName(15))
	assert.Equal(t, "RSASHA1", AlgorithmName(5))
	// Unassigned numbers report empty rather than a made-up mnemonic, so a
	// caller can tell "we do not know this algorithm" from "algorithm 8".
	assert.Equal(t, "", AlgorithmName(9))
	assert.Equal(t, "", AlgorithmName(0))
}

func TestDigestTypeName(t *testing.T) {
	assert.Equal(t, "SHA-1", DigestTypeName(1))
	assert.Equal(t, "SHA-256", DigestTypeName(2))
	assert.Equal(t, "SHA-384", DigestTypeName(4))
	assert.Equal(t, "", DigestTypeName(99))
}

func TestPublicKeyBits(t *testing.T) {
	cases := []struct {
		name      string
		algorithm int
		key       string
		want      int
	}{
		{
			name:      "RSASHA1 1024-bit (RFC 4034 appendix B)",
			algorithm: 5,
			key:       rfc4034Key,
			want:      1024,
		},
		{
			name:      "ECDSAP256SHA256 (RFC 6605 section 6.1)",
			algorithm: 13,
			key:       "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
			want:      256,
		},
		{
			name:      "ECDSAP384SHA384 (RFC 6605 section 6.2)",
			algorithm: 14,
			key:       "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40",
			want:      384,
		},
		{
			name:      "ED25519 (RFC 8080 section 6.1)",
			algorithm: 15,
			key:       "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
			want:      256,
		},
		{
			// Whitespace is how a key arrives out of a multi-line zone file.
			name:      "folded base64 is accepted",
			algorithm: 15,
			key:       "l02Woi0iS8Aa25FQkUd9\n RMzZHJpBoRQwAQEX1SxZJA4=",
			want:      256,
		},
		{
			name:      "unassigned algorithm reports unknown",
			algorithm: 9,
			key:       rfc4034Key,
			want:      0,
		},
		{
			name:      "undecodable key reports unknown",
			algorithm: 8,
			key:       "not base64 at all!!",
			want:      0,
		},
		{
			name:      "empty key reports unknown",
			algorithm: 8,
			key:       "",
			want:      0,
		},
		{
			// A truncated RSA key must report unknown rather than a confident
			// wrong size: the exponent header claims more bytes than are here.
			name:      "RSA key truncated inside its exponent reports unknown",
			algorithm: 8,
			key:       "CAEC",
			want:      0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, PublicKeyBits(tc.algorithm, tc.key))
		})
	}
}

// TestDSDigest pins the digest against the values published in RFC 4034 and
// RFC 4509 for the same key. Getting this wrong in the safe-looking direction
// (a digest that never matches) reports every correctly delegated zone as
// having a broken chain of trust.
func TestDSDigest(t *testing.T) {
	t.Run("SHA-1, RFC 4034 section 5.4", func(t *testing.T) {
		got, err := DSDigest("dskey.example.com.", 256, 3, 5, rfc4034Key, 1)
		require.NoError(t, err)
		assert.Equal(t, "2bb183af5f22588179a53b0a98631fad1a292118", got)
	})

	t.Run("SHA-256, RFC 4509 section 2.3", func(t *testing.T) {
		got, err := DSDigest("dskey.example.com.", 256, 3, 5, rfc4034Key, 2)
		require.NoError(t, err)
		assert.Equal(t, "d4b7d520e7bb5f0f67674a0cceb1e3e0614b93c4f9e99b8383f6a1e4469da50a", got)
	})

	t.Run("owner name case does not change the digest", func(t *testing.T) {
		lower, err := DSDigest("dskey.example.com.", 256, 3, 5, rfc4034Key, 2)
		require.NoError(t, err)
		upper, err := DSDigest("DsKey.Example.COM", 256, 3, 5, rfc4034Key, 2)
		require.NoError(t, err)
		assert.Equal(t, lower, upper)
	})

	t.Run("SHA-384 produces a 96-character digest", func(t *testing.T) {
		got, err := DSDigest("dskey.example.com.", 256, 3, 5, rfc4034Key, 4)
		require.NoError(t, err)
		assert.Len(t, got, 96)
	})

	t.Run("unsupported digest type errors rather than returning a wrong digest", func(t *testing.T) {
		_, err := DSDigest("dskey.example.com.", 256, 3, 5, rfc4034Key, 3)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported DS digest type 3")
	})

	t.Run("undecodable public key errors", func(t *testing.T) {
		_, err := DSDigest("dskey.example.com.", 256, 3, 5, "not base64!!", 2)
		require.Error(t, err)
	})

	t.Run("empty public key errors", func(t *testing.T) {
		_, err := DSDigest("dskey.example.com.", 256, 3, 5, "", 2)
		require.Error(t, err)
	})
}

func TestCanonicalName(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		got, err := CanonicalName(".")
		require.NoError(t, err)
		assert.Equal(t, []byte{0}, got)
	})

	t.Run("empty string is the root", func(t *testing.T) {
		got, err := CanonicalName("")
		require.NoError(t, err)
		assert.Equal(t, []byte{0}, got)
	})

	t.Run("labels are length-prefixed and lowercased", func(t *testing.T) {
		got, err := CanonicalName("Example.COM.")
		require.NoError(t, err)
		assert.Equal(t, []byte("\x07example\x03com\x00"), got)
	})

	t.Run("trailing dot is optional", func(t *testing.T) {
		with, err := CanonicalName("example.com.")
		require.NoError(t, err)
		without, err := CanonicalName("example.com")
		require.NoError(t, err)
		assert.Equal(t, with, without)
	})

	t.Run("empty label errors", func(t *testing.T) {
		_, err := CanonicalName("example..com")
		require.Error(t, err)
	})

	t.Run("over-long label errors", func(t *testing.T) {
		_, err := CanonicalName(strings.Repeat("a", 64) + ".com")
		require.Error(t, err)
	})
}

func TestNSEC3(t *testing.T) {
	t.Run("opt-out bit", func(t *testing.T) {
		assert.False(t, NSEC3OptOut(0))
		assert.True(t, NSEC3OptOut(1))
	})

	t.Run("hash algorithm name", func(t *testing.T) {
		assert.Equal(t, "SHA-1", NSEC3HashAlgorithmName(1))
		assert.Equal(t, "", NSEC3HashAlgorithmName(2))
	})

	t.Run("salt length", func(t *testing.T) {
		// `-` is how a zone with no salt is written. Reading it as a
		// one-character salt would report salted when the zone is not.
		assert.Equal(t, 0, NSEC3SaltLength("-"))
		assert.Equal(t, 0, NSEC3SaltLength(""))
		assert.Equal(t, 0, NSEC3SaltLength("   "))
		assert.Equal(t, 4, NSEC3SaltLength("AABBCCDD"))
		assert.Equal(t, 8, NSEC3SaltLength("0123456789abcdef"))
		assert.Equal(t, 0, NSEC3SaltLength("zzzz"))
	})
}

func TestSignatureWindow(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	t.Run("inside the window", func(t *testing.T) {
		w := SignatureWindow{
			Inception:  now.Add(-24 * time.Hour),
			Expiration: now.Add(14 * 24 * time.Hour),
		}
		assert.True(t, w.Valid(now))
		assert.False(t, w.Expired(now))
		assert.False(t, w.NotYetValid(now))
		assert.Equal(t, 14*24*time.Hour, w.RemainingValidity(now))
	})

	t.Run("expired", func(t *testing.T) {
		w := SignatureWindow{
			Inception:  now.Add(-30 * 24 * time.Hour),
			Expiration: now.Add(-time.Hour),
		}
		assert.False(t, w.Valid(now))
		assert.True(t, w.Expired(now))
		assert.Equal(t, -time.Hour, w.RemainingValidity(now))
	})

	t.Run("not yet valid is as broken as expired", func(t *testing.T) {
		w := SignatureWindow{
			Inception:  now.Add(time.Hour),
			Expiration: now.Add(14 * 24 * time.Hour),
		}
		assert.False(t, w.Valid(now))
		assert.True(t, w.NotYetValid(now))
		assert.False(t, w.Expired(now))
	})

	t.Run("zero times report no window rather than the year 1", func(t *testing.T) {
		var w SignatureWindow
		assert.True(t, w.Valid(now))
		assert.False(t, w.Expired(now))
		assert.False(t, w.NotYetValid(now))
		assert.Equal(t, time.Duration(0), w.RemainingValidity(now))
	})
}
