// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/bind9"
)

// Both fixtures below are the literal output of `dnssec-keygen -a
// ECDSAP256SHA256 -n ZONE example.com`, one with -f KSK. Using what the tool
// actually writes is the point: a fixture written to match the parser would
// only prove the parser agrees with itself.
const zskFile = `; This is a zone-signing key, keyid 53434, for example.com.
; Created: 20260816141610 (Sun Aug 16 14:16:10 2026)
; Publish: 20260816141610 (Sun Aug 16 14:16:10 2026)
; Activate: 20260816141610 (Sun Aug 16 14:16:10 2026)
example.com. IN DNSKEY 256 3 13 dyb3XJ7oixFxVwYfk5hKpXI2VjcyuMFDQFYuplyWQNYdNOziW39LSmfb jQ==
`

const kskFile = `; This is a key-signing key, keyid 59706, for example.com.
; Created: 20260816141610 (Sun Aug 16 14:16:10 2026)
example.com. IN DNSKEY 257 3 13 fkl9VBx6NMinDp05GoAFyXN+VYcu2KdtMnfdwK0TLFCHv2Hz/02cTuVR iQ==
`

func TestParseDNSSECKeyFile(t *testing.T) {
	t.Run("zone signing key", func(t *testing.T) {
		k := bind9.ParseDNSSECKeyFile("Kexample.com.+013+53434.key", zskFile)
		require.NotNil(t, k)
		assert.Equal(t, "example.com", k.Zone, "the trailing dot is trimmed so this compares against bind9.zone.name")
		assert.Equal(t, 13, k.Algorithm)
		assert.Equal(t, 53434, k.KeyTag)
		assert.False(t, k.KeySigningKey)
		assert.Equal(t, time.Date(2026, 8, 16, 14, 16, 10, 0, time.UTC), k.Created)
	})

	t.Run("key signing key", func(t *testing.T) {
		k := bind9.ParseDNSSECKeyFile("Kexample.com.+013+59706.key", kskFile)
		require.NotNil(t, k)
		assert.Equal(t, 59706, k.KeyTag)
		assert.True(t, k.KeySigningKey, "flags 257 has the secure entry point bit set")
	})

	// The flags are read bitwise rather than compared to 257, so a revoked key
	// signing key — flags 385 — is still reported as one. Comparing exactly
	// would silently reclassify it as a zone signing key, and a check asserting
	// "no private KSK on this host" would then skip it.
	t.Run("a revoked key signing key is still a key signing key", func(t *testing.T) {
		revoked := `example.com. IN DNSKEY 385 3 13 fkl9VBx6NMinDp05GoAFyXN+VYcu2Kdt`
		k := bind9.ParseDNSSECKeyFile("Kexample.com.+013+59706.key", revoked)
		require.NotNil(t, k)
		assert.True(t, k.KeySigningKey)
	})

	t.Run("a record with no class still parses", func(t *testing.T) {
		noClass := `example.com. 3600 DNSKEY 257 3 13 fkl9VBx6NMinDp05GoAFyXN`
		k := bind9.ParseDNSSECKeyFile("Kexample.com.+013+59706.key", noClass)
		require.NotNil(t, k)
		assert.True(t, k.KeySigningKey)
	})

	t.Run("no Created line leaves the time zero", func(t *testing.T) {
		k := bind9.ParseDNSSECKeyFile("Kexample.com.+013+53434.key",
			"example.com. IN DNSKEY 256 3 13 dyb3XJ7oix")
		require.NotNil(t, k)
		assert.True(t, k.Created.IsZero(), "absent is not the epoch")
	})

	t.Run("a zone with dots and dashes", func(t *testing.T) {
		k := bind9.ParseDNSSECKeyFile("Ksub.corp-eu.example.com.+008+01234.key", zskFile)
		require.NotNil(t, k)
		assert.Equal(t, "sub.corp-eu.example.com", k.Zone)
		assert.Equal(t, 8, k.Algorithm)
		assert.Equal(t, 1234, k.KeyTag)
	})

	t.Run("names that are not key files", func(t *testing.T) {
		for _, name := range []string{
			"Kexample.com.+013+53434.private", // the private half, matched separately
			"db.example.com",
			"named.conf",
			"Kexample.com.+13+53434.key", // algorithm is three digits
			"managed-keys.bind",
		} {
			assert.Nil(t, bind9.ParseDNSSECKeyFile(name, zskFile), "name %q", name)
		}
	})
}

func TestIsDNSSECKeyFile(t *testing.T) {
	assert.True(t, bind9.IsDNSSECKeyFile("Kexample.com.+013+53434.key"))
	assert.False(t, bind9.IsDNSSECKeyFile("Kexample.com.+013+53434.private"))
	assert.False(t, bind9.IsDNSSECKeyFile("random.key"))
}

func TestPrivateKeyPath(t *testing.T) {
	assert.Equal(t,
		"/var/cache/bind/Kexample.com.+013+53434.private",
		bind9.PrivateKeyPath("/var/cache/bind/Kexample.com.+013+53434.key"))
}
