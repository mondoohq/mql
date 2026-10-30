// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/dnssec"
)

// These tests never touch the network. Everything they exercise is decoding
// and comparison over records built here, which is where a DNSSEC bug is
// silent: it compiles, it lints, and it reports a confident wrong verdict on a
// zone rather than an error.

// rfc4034Dnskey and rfc4034DS are the matching key and delegation from
// RFC 4034 appendix B, tied together by the digest in RFC 4034 section 5.4.
const (
	rfc4034Dnskey = "dskey.example.com. 86400 IN DNSKEY 256 3 5 " +
		"AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ" +
		"DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc" +
		"nOf+EPbtG9DMBmADjFDc2w/rljwvFw=="

	rfc4034DS = "dskey.example.com. 86400 IN DS 60485 5 1 " +
		"2BB183AF5F22588179A53B0A98631FAD1A292118"
)

// rootKSK2017 is the root zone key signing key with tag 20326, as the root
// zone publishes it. It is public data: a trust anchor is only useful because
// everyone has the same copy.
const rootKSK2017 = ". 172800 IN DNSKEY 257 3 8 " +
	"AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixH" +
	"lFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WG" +
	"e2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eN" +
	"buv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6" +
	"+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="

func mustDNSKEY(t *testing.T, s string) *dns.DNSKEY {
	t.Helper()
	rr, err := dns.NewRR(s)
	require.NoError(t, err)
	key, ok := rr.(*dns.DNSKEY)
	require.True(t, ok, "expected a DNSKEY record")
	return key
}

func mustDS(t *testing.T, s string) *dns.DS {
	t.Helper()
	rr, err := dns.NewRR(s)
	require.NoError(t, err)
	ds, ok := rr.(*dns.DS)
	require.True(t, ok, "expected a DS record")
	return ds
}

// TestSharedDigestMatchesMiekg is the guard against the shared decoder
// drifting away from the wire library.
//
// The DS digest is computed by utils/dnssec so that the same implementation
// serves a key read off disk and a key read off the wire. That only stays
// honest while it agrees with the library that parsed the record, so this
// compares the two across every digest type and key algorithm in use. A
// mismatch here means every correctly delegated zone would be reported as
// having a broken chain of trust, which is the failure direction that matters.
func TestSharedDigestMatchesMiekg(t *testing.T) {
	keys := []string{
		rfc4034Dnskey,
		rootKSK2017,
		"example.net. 3600 IN DNSKEY 257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
		"example.com. 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
	}

	for _, keyStr := range keys {
		key := mustDNSKEY(t, keyStr)
		for _, digestType := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
			t.Run(key.Hdr.Name+"/"+dns.AlgorithmToString[key.Algorithm]+"/"+dns.HashToString[digestType], func(t *testing.T) {
				expected := key.ToDS(digestType)
				require.NotNil(t, expected)

				got, err := dnssec.DSDigest(
					key.Hdr.Name,
					int(key.Flags), int(key.Protocol), int(key.Algorithm),
					key.PublicKey,
					int(digestType),
				)
				require.NoError(t, err)
				assert.True(t, strings.EqualFold(expected.Digest, got),
					"shared digest %q does not match miekg %q", got, expected.Digest)
			})
		}
	}
}

func TestAnyDelegationMatchesKey(t *testing.T) {
	key := mustDNSKEY(t, rfc4034Dnskey)
	ds := mustDS(t, rfc4034DS)

	t.Run("the RFC 4034 DS matches its key", func(t *testing.T) {
		assert.True(t, anyDelegationMatchesKey([]*dns.DS{ds}, []*dns.DNSKEY{key}))
	})

	t.Run("a DS left behind by a rolled key matches nothing", func(t *testing.T) {
		// The shape that breaks validation while the zone still looks signed:
		// the parent publishes a delegation for a key that is no longer there.
		stale := mustDS(t, "dskey.example.com. 86400 IN DS 60485 5 1 "+
			"0000000000000000000000000000000000000000")
		assert.False(t, anyDelegationMatchesKey([]*dns.DS{stale}, []*dns.DNSKEY{key}))
	})

	t.Run("one matching DS among several is enough to link the zone", func(t *testing.T) {
		stale := mustDS(t, "dskey.example.com. 86400 IN DS 60485 5 1 "+
			"0000000000000000000000000000000000000000")
		assert.True(t, anyDelegationMatchesKey([]*dns.DS{stale, ds}, []*dns.DNSKEY{key}))
	})

	t.Run("no DS records means no link", func(t *testing.T) {
		assert.False(t, anyDelegationMatchesKey(nil, []*dns.DNSKEY{key}))
	})

	t.Run("no keys means no link", func(t *testing.T) {
		assert.False(t, anyDelegationMatchesKey([]*dns.DS{ds}, nil))
	})

	t.Run("an unsupported digest type does not match rather than panicking", func(t *testing.T) {
		gost := mustDS(t, "dskey.example.com. 86400 IN DS 60485 5 3 "+
			"2BB183AF5F22588179A53B0A98631FAD1A2921182BB183AF5F22588179A53B0A")
		assert.False(t, anyDelegationMatchesKey([]*dns.DS{gost}, []*dns.DNSKEY{key}))
	})
}

func TestMatchesRootAnchor(t *testing.T) {
	rootKey := mustDNSKEY(t, rootKSK2017)

	t.Run("the published root key signing key matches an IANA anchor", func(t *testing.T) {
		assert.True(t, matchesRootAnchor([]*dns.DNSKEY{rootKey}))
	})

	t.Run("a zone signing key is never an anchor", func(t *testing.T) {
		// Only a key with the Secure Entry Point bit can be an anchor. Without
		// the filter, a substituted zone signing key would be checked against
		// the anchors and, more importantly, the check would be meaningless.
		zsk := mustDNSKEY(t, strings.Replace(rootKSK2017, "DNSKEY 257 3 8", "DNSKEY 256 3 8", 1))
		assert.False(t, matchesRootAnchor([]*dns.DNSKEY{zsk}))
	})

	t.Run("an unrelated key does not match", func(t *testing.T) {
		other := mustDNSKEY(t, "example.com. 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")
		assert.False(t, matchesRootAnchor([]*dns.DNSKEY{other}))
	})

	t.Run("no keys", func(t *testing.T) {
		assert.False(t, matchesRootAnchor(nil))
	})
}

func TestParentZone(t *testing.T) {
	cases := []struct{ zone, want string }{
		{"example.com.", "com."},
		{"example.com", "com."},
		{"a.b.example.com.", "b.example.com."},
		{"com.", "."},
		{"com", "."},
		{".", "."},
	}

	for _, tc := range cases {
		t.Run(tc.zone, func(t *testing.T) {
			assert.Equal(t, tc.want, parentZone(tc.zone))
		})
	}
}

func TestRrsetCoveredBy(t *testing.T) {
	a1, err := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	require.NoError(t, err)
	a2, err := dns.NewRR("www.example.com. 300 IN A 192.0.2.2")
	require.NoError(t, err)
	otherName, err := dns.NewRR("other.example.com. 300 IN A 192.0.2.3")
	require.NoError(t, err)
	otherType, err := dns.NewRR("www.example.com. 300 IN TXT \"hello\"")
	require.NoError(t, err)

	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "www.example.com.", Class: dns.ClassINET},
		TypeCovered: dns.TypeA,
	}

	t.Run("collects every record of the covered type at the name", func(t *testing.T) {
		got := rrsetCoveredBy(sig, []dns.RR{a1, otherType, a2, otherName})
		assert.Equal(t, []dns.RR{a1, a2}, got)
	})

	t.Run("name comparison is case insensitive, as DNS names are", func(t *testing.T) {
		upper := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "WWW.Example.COM.", Class: dns.ClassINET},
			TypeCovered: dns.TypeA,
		}
		assert.Len(t, rrsetCoveredBy(upper, []dns.RR{a1, a2}), 2)
	})

	t.Run("nothing covered returns empty, not nil-shaped surprises", func(t *testing.T) {
		assert.Empty(t, rrsetCoveredBy(sig, []dns.RR{otherName, otherType}))
	})
}

func TestVerifySignaturesSkipsIrrelevantRrsigs(t *testing.T) {
	a1, err := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	require.NoError(t, err)

	// An RRSIG covering NSEC, bundled alongside an A answer by a validating
	// resolver. Nothing in the answer is of the covered type.
	nsecSig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "www.example.com.", Class: dns.ClassINET},
		TypeCovered: dns.TypeNSEC,
		SignerName:  "example.com.",
	}

	d := &DnsClient{}

	t.Run("an answer carrying only uncovered signatures does not verify", func(t *testing.T) {
		// Every signature is skipped, so nothing was actually checked. This
		// must not pass: skipping is only safe while at least one signature
		// still has to verify.
		verified, unreadable := d.verifySignatures("", []*dns.RRSIG{nsecSig}, []dns.RR{a1})
		assert.False(t, verified)
		// Nothing was fetched, so this is a genuine "did not verify" rather
		// than a key set the resolver would not hand over.
		assert.Empty(t, unreadable)
	})

	t.Run("no signatures at all does not verify", func(t *testing.T) {
		verified, unreadable := d.verifySignatures("", nil, []dns.RR{a1})
		assert.False(t, verified)
		assert.Empty(t, unreadable)
	})
}

func TestVerifyDnskeySetRejectsUnsignedSets(t *testing.T) {
	key := mustDNSKEY(t, rfc4034Dnskey)

	t.Run("a DNSKEY set with no signature over it is not self-signed", func(t *testing.T) {
		assert.False(t, verifyDnskeySet(nil, []*dns.DNSKEY{key}))
	})

	t.Run("a signature covering something else does not count", func(t *testing.T) {
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "dskey.example.com.", Class: dns.ClassINET},
			TypeCovered: dns.TypeA,
		}
		assert.False(t, verifyDnskeySet([]*dns.RRSIG{sig}, []*dns.DNSKEY{key}))
	})

	t.Run("a DNSKEY signature that does not verify does not count", func(t *testing.T) {
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "dskey.example.com.", Class: dns.ClassINET},
			TypeCovered: dns.TypeDNSKEY,
			Algorithm:   5,
			Signature:   "bm90IGEgc2lnbmF0dXJl",
		}
		assert.False(t, verifyDnskeySet([]*dns.RRSIG{sig}, []*dns.DNSKEY{key}))
	})
}

func TestNewDnssecSignature(t *testing.T) {
	rr, err := dns.NewRR("www.example.com. 300 IN RRSIG A 8 3 300 " +
		"20260901000000 20260818000000 12345 example.com. " +
		"bm90IGEgcmVhbCBzaWduYXR1cmU=")
	require.NoError(t, err)
	sig, ok := rr.(*dns.RRSIG)
	require.True(t, ok)

	got := newDnssecSignature(sig)

	assert.Equal(t, "www.example.com.", got.Name)
	assert.Equal(t, "A", got.TypeCovered)
	assert.Equal(t, 8, got.Algorithm)
	assert.Equal(t, "RSASHA256", got.AlgorithmName)
	assert.Equal(t, 3, got.Labels)
	assert.Equal(t, int64(300), got.OriginalTTL)
	assert.Equal(t, "example.com.", got.SignerName)
	assert.Equal(t, time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), got.Inception)
	assert.Equal(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), got.Expiration)

	t.Run("the key tag and the signature bytes are not carried", func(t *testing.T) {
		// Both change on every re-signing, so a check built on either flaps on
		// a schedule the operator did not choose. The fingerprint is a hash
		// used only to keep two signatures apart within one response.
		assert.NotContains(t, got.Fingerprint, sig.Signature)
		assert.Len(t, got.Fingerprint, 16)
	})

	t.Run("the window comes back usable", func(t *testing.T) {
		inside := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
		assert.True(t, got.Window().Valid(inside))
		assert.False(t, got.Window().Expired(inside))

		after := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		assert.True(t, got.Window().Expired(after))
	})
}

func TestFingerprintSignatureIsStableAndDistinguishing(t *testing.T) {
	a := fingerprintSignature("one")
	b := fingerprintSignature("two")
	assert.Equal(t, a, fingerprintSignature("one"))
	assert.NotEqual(t, a, b)
}

func TestResponseHasDnssecOk(t *testing.T) {
	t.Run("set when the response echoes the DNSSEC OK bit", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.SetEdns0(4096, true)
		assert.True(t, responseHasDnssecOk(msg))
	})

	t.Run("clear when EDNS0 is present without the bit", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.SetEdns0(4096, false)
		assert.False(t, responseHasDnssecOk(msg))
	})

	t.Run("clear when EDNS0 was stripped entirely", func(t *testing.T) {
		// A middlebox that removes EDNS0 makes every other DNSSEC observation
		// on the response meaningless rather than negative, which is why this
		// is reported separately instead of folded into the other flags.
		assert.False(t, responseHasDnssecOk(&dns.Msg{}))
	})
}

func TestValidateDnssecRejectsUnknownRecordTypes(t *testing.T) {
	client, err := New("example.com")
	require.NoError(t, err)

	t.Run("unknown type", func(t *testing.T) {
		_, err := client.ValidateDnssec("NOTATYPE")
		require.Error(t, err)
	})

	t.Run("no type at all", func(t *testing.T) {
		_, err := client.ValidateDnssec()
		require.Error(t, err)
	})
}

// TestValidateDnssecWithoutAResolverIsInspectable pins the failure contract:
// nothing about a resolution that cannot happen may abort the scan. The result
// comes back describing what went wrong.
func TestValidateDnssecWithoutAResolverIsInspectable(t *testing.T) {
	client, err := New("example.com")
	require.NoError(t, err)
	client.config.Servers = nil

	res, err := client.ValidateDnssec("A")
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.False(t, res.ChainOfTrustValidated)
	assert.False(t, res.AuthenticatedData)
	assert.Empty(t, res.Signatures)
	assert.NotEmpty(t, res.Error, "a resolution that could not happen must say so")
}

// TestSigningZone pins where the chain walk starts when an answer carries
// signatures from more than one zone, which is what a CNAME into another
// zone produces. Taking whichever the resolver happened to list first would
// make the reported chain depend on response ordering.
func TestSigningZone(t *testing.T) {
	queried := "www.example.com."

	sigForName := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "www.example.com."},
		SignerName: "example.com.",
	}
	sigForTarget := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "cdn.provider.net."},
		SignerName: "provider.net.",
	}

	t.Run("the signature over the queried name wins, whatever the order", func(t *testing.T) {
		assert.Equal(t, "example.com.", signingZone(queried, []*dns.RRSIG{sigForTarget, sigForName}))
		assert.Equal(t, "example.com.", signingZone(queried, []*dns.RRSIG{sigForName, sigForTarget}))
	})

	t.Run("name matching is case insensitive", func(t *testing.T) {
		assert.Equal(t, "example.com.", signingZone("WWW.Example.COM.", []*dns.RRSIG{sigForTarget, sigForName}))
	})

	t.Run("falls back to the first signature when none covers the queried name", func(t *testing.T) {
		assert.Equal(t, "provider.net.", signingZone(queried, []*dns.RRSIG{sigForTarget}))
	})
}
