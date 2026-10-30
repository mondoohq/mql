// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/dnssec"
)

// The params dict these read is what convert.JsonToDict produced from a
// dnsshake.DnsRecord, so the keys are the json tags and every number arrives as
// float64. Building the fixtures by hand here pins that contract: reading "TTL"
// instead of "ttl", or asserting int64, is how a field silently goes missing.

// rfc4034DnskeyRdata is the RFC 4034 appendix B example key, in the rdata form
// the record sweep stores.
const rfc4034DnskeyRdata = "256 3 5 " +
	"AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ" +
	"DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc" +
	"nOf+EPbtG9DMBmADjFDc2w/rljwvFw=="

func paramsWith(recordType, name string, rdata ...string) map[string]any {
	values := make([]any, 0, len(rdata))
	for _, v := range rdata {
		values = append(values, v)
	}
	return map[string]any{
		recordType: map[string]any{
			"name":  name,
			"class": "IN",
			"type":  recordType,
			"ttl":   float64(86400),
			"rData": values,
			"rCode": dns.RcodeToString[dns.RcodeSuccess],
		},
	}
}

func TestDnskeyRecordsFromParams(t *testing.T) {
	t.Run("parses the published keys and their flag bits", func(t *testing.T) {
		params := paramsWith("DNSKEY", "dskey.example.com.",
			rfc4034DnskeyRdata,
			"257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
		)

		keys := dnskeyRecordsFromParams(params)
		require.Len(t, keys, 2)

		assert.Equal(t, uint16(256), keys[0].Flags)
		assert.False(t, dnssec.IsKeySigningKey(int(keys[0].Flags)))
		assert.True(t, dnssec.IsZoneKey(int(keys[0].Flags)))
		assert.Equal(t, 1024, dnssec.PublicKeyBits(int(keys[0].Algorithm), keys[0].PublicKey))

		assert.Equal(t, uint16(257), keys[1].Flags)
		assert.True(t, dnssec.IsKeySigningKey(int(keys[1].Flags)))
		assert.Equal(t, 256, dnssec.PublicKeyBits(int(keys[1].Algorithm), keys[1].PublicKey))
	})

	t.Run("a revoked key signing key is still a key signing key", func(t *testing.T) {
		// Flags 385 is 257 with the revoke bit added. An equality test against
		// 257 would report this zone as having no key signing key at all.
		params := paramsWith("DNSKEY", "example.com.",
			"385 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")

		keys := dnskeyRecordsFromParams(params)
		require.Len(t, keys, 1)
		assert.True(t, dnssec.IsKeySigningKey(int(keys[0].Flags)))
		assert.True(t, dnssec.IsRevoked(int(keys[0].Flags)))
	})

	t.Run("one unparseable record costs that key, not the whole set", func(t *testing.T) {
		params := paramsWith("DNSKEY", "dskey.example.com.",
			"this is not a dnskey",
			rfc4034DnskeyRdata,
		)

		keys := dnskeyRecordsFromParams(params)
		assert.Len(t, keys, 1, "the readable key must survive its malformed neighbour")
	})

	t.Run("an unsuccessful lookup reports nothing", func(t *testing.T) {
		params := paramsWith("DNSKEY", "example.com.", rfc4034DnskeyRdata)
		params["DNSKEY"].(map[string]any)["rCode"] = "SERVFAIL"
		assert.Empty(t, dnskeyRecordsFromParams(params))
	})

	t.Run("absent params report nothing rather than erroring", func(t *testing.T) {
		assert.Empty(t, dnskeyRecordsFromParams(nil))
		assert.Empty(t, dnskeyRecordsFromParams(map[string]any{}))
	})

	t.Run("a record of another type is not mistaken for a key", func(t *testing.T) {
		assert.Empty(t, dnskeyRecordsFromParams(paramsWith("DNSKEY", "example.com.")))
	})
}

func TestDsRecordsFromParams(t *testing.T) {
	t.Run("parses the parent's delegation", func(t *testing.T) {
		params := paramsWith("DS", "dskey.example.com.",
			"60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118")

		records := dsRecordsFromParams(params)
		require.Len(t, records, 1)
		assert.Equal(t, uint8(5), records[0].Algorithm)
		assert.Equal(t, uint8(1), records[0].DigestType)
		assert.Equal(t, "SHA-1", dnssec.DigestTypeName(int(records[0].DigestType)))
	})

	t.Run("no delegation is an empty list, which is what an insecure delegation looks like", func(t *testing.T) {
		assert.Empty(t, dsRecordsFromParams(nil))
	})
}

func TestDelegationMatchesKey(t *testing.T) {
	keys := dnskeyRecordsFromParams(paramsWith("DNSKEY", "dskey.example.com.", rfc4034DnskeyRdata))
	require.Len(t, keys, 1)

	t.Run("matches the key it delegates to", func(t *testing.T) {
		records := dsRecordsFromParams(paramsWith("DS", "dskey.example.com.",
			"60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"))
		require.Len(t, records, 1)
		assert.True(t, delegationMatchesKey(records[0], keys))
	})

	t.Run("does not match a key the zone no longer publishes", func(t *testing.T) {
		records := dsRecordsFromParams(paramsWith("DS", "dskey.example.com.",
			"60485 5 1 0000000000000000000000000000000000000000"))
		require.Len(t, records, 1)
		assert.False(t, delegationMatchesKey(records[0], keys))
	})

	t.Run("no keys at all does not match", func(t *testing.T) {
		records := dsRecordsFromParams(paramsWith("DS", "dskey.example.com.",
			"60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"))
		require.Len(t, records, 1)
		assert.False(t, delegationMatchesKey(records[0], nil))
	})
}

func TestNsec3ParamFromParams(t *testing.T) {
	t.Run("reads the parameters an NSEC3 zone publishes", func(t *testing.T) {
		params := paramsWith("NSEC3PARAM", "example.com.", "1 0 10 AABBCCDD")

		p := nsec3ParamFromParams(params)
		require.NotNil(t, p)
		assert.Equal(t, uint8(1), p.Hash)
		assert.Equal(t, uint16(10), p.Iterations)
		assert.Equal(t, 4, dnssec.NSEC3SaltLength(p.Salt))
		assert.False(t, dnssec.NSEC3OptOut(int(p.Flags)))
	})

	t.Run("an unsalted zone reports no salt rather than a one-byte salt", func(t *testing.T) {
		// RFC 9276 asks for no salt, and a zone that follows it writes `-`.
		// Reading that as one character would report every compliant zone as
		// salted.
		params := paramsWith("NSEC3PARAM", "example.com.", "1 0 0 -")

		p := nsec3ParamFromParams(params)
		require.NotNil(t, p)
		assert.Equal(t, uint16(0), p.Iterations)
		assert.Equal(t, 0, dnssec.NSEC3SaltLength(p.Salt))
	})

	t.Run("opt-out is read from the flags", func(t *testing.T) {
		params := paramsWith("NSEC3PARAM", "example.com.", "1 1 0 -")

		p := nsec3ParamFromParams(params)
		require.NotNil(t, p)
		assert.True(t, dnssec.NSEC3OptOut(int(p.Flags)))
	})

	t.Run("a zone without NSEC3 reports nil, which is how NSEC is inferred", func(t *testing.T) {
		assert.Nil(t, nsec3ParamFromParams(nil))
		assert.Nil(t, nsec3ParamFromParams(paramsWith("DNSKEY", "example.com.", rfc4034DnskeyRdata)))
	})
}

// TestRecordsFromParamsReadsTheJsonTagTtl guards the same contract dictTTL
// does, one level up: the fixture uses the json tag and a float64, because
// that is what the dict actually carries.
func TestRecordsFromParamsReadsTheJsonTagTtl(t *testing.T) {
	params := paramsWith("DNSKEY", "dskey.example.com.", rfc4034DnskeyRdata)

	records := recordsFromParams(params, "DNSKEY")
	require.Len(t, records, 1)
	assert.Equal(t, uint32(86400), records[0].Header().Ttl)

	t.Run("a missing ttl still parses the record", func(t *testing.T) {
		delete(params["DNSKEY"].(map[string]any), "ttl")
		records := recordsFromParams(params, "DNSKEY")
		assert.Len(t, records, 1)
	})
}
