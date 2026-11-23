// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
)

// TestComputeAddressIsExternal drives the derived internet-facing predicate.
// Synthetic: no target showed this; it covers both states and the absent case.
func TestComputeAddressIsExternal(t *testing.T) {
	cases := []struct {
		addressType string
		want        bool
	}{
		{"EXTERNAL", true},
		{"INTERNAL", false},
		{"", false},
	}
	for _, c := range cases {
		addr := &mqlGcpProjectComputeServiceAddress{
			AddressType: plugin.TValue[string]{Data: c.addressType, State: plugin.StateIsSet},
		}
		got, err := addr.isExternal()
		assert.NoError(t, err)
		assert.Equal(t, c.want, got, "addressType=%q", c.addressType)
	}
}

func TestCustomerEncryptionKeyToDict(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, customerEncryptionKeyToDict(nil))
	})

	t.Run("populated key maps every field", func(t *testing.T) {
		got := customerEncryptionKeyToDict(&compute.CustomerEncryptionKey{
			KmsKeyName:           "projects/p/locations/us/keyRings/r/cryptoKeys/k",
			KmsKeyServiceAccount: "sa@p.iam.gserviceaccount.com",
			RawKey:               "raw",
			RsaEncryptedKey:      "rsa",
			Sha256:               "deadbeef",
		})
		assert.Equal(t, map[string]any{
			"kmsKeyName":           "projects/p/locations/us/keyRings/r/cryptoKeys/k",
			"kmsKeyServiceAccount": "sa@p.iam.gserviceaccount.com",
			"rawKey":               "raw",
			"rsaEncryptedKey":      "rsa",
			"sha256":               "deadbeef",
		}, got)
	})

	t.Run("empty key still returns a map", func(t *testing.T) {
		// A non-nil key with all-empty fields should still produce a dict
		// (with empty-string values), so callers can distinguish "no key
		// configured" (nil) from "key configured but raw value not returned"
		// (populated dict with empty strings — common for KMS responses).
		got := customerEncryptionKeyToDict(&compute.CustomerEncryptionKey{})
		assert.NotNil(t, got)
		assert.Equal(t, "", got["kmsKeyName"])
		assert.Equal(t, "", got["sha256"])
	})
}

func TestVpnTunnelCipherSuiteArgs(t *testing.T) {
	cipherFields := []string{
		"phase1EncryptionAlgorithms", "phase1IntegrityAlgorithms", "phase1PrfAlgorithms", "phase1DhGroups",
		"phase2EncryptionAlgorithms", "phase2IntegrityAlgorithms", "phase2PfsGroups",
	}

	// Synthetic: a tunnel with every role configured; values are taken from the
	// Cloud VPN supported IKE ciphers table, no live tunnel showed this.
	t.Run("full suite maps each role to its own field", func(t *testing.T) {
		got := vpnTunnelCipherSuiteArgs(&compute.VpnTunnelCipherSuite{
			Phase1: &compute.VpnTunnelPhase1Algorithms{
				Encryption: []string{"AES-CBC-256", "3DES-CBC"},
				Integrity:  []string{"HMAC-SHA2-256-128"},
				Prf:        []string{"PRF-HMAC-SHA2-256"},
				Dh:         []string{"Group-14", "Group-2"},
			},
			Phase2: &compute.VpnTunnelPhase2Algorithms{
				Encryption: []string{"AES-GCM-16-256"},
				Integrity:  []string{"HMAC-SHA1-96"},
				Pfs:        []string{"Group-20"},
			},
		})
		assert.Equal(t, []any{"AES-CBC-256", "3DES-CBC"}, got["phase1EncryptionAlgorithms"].Value)
		assert.Equal(t, []any{"HMAC-SHA2-256-128"}, got["phase1IntegrityAlgorithms"].Value)
		assert.Equal(t, []any{"PRF-HMAC-SHA2-256"}, got["phase1PrfAlgorithms"].Value)
		assert.Equal(t, []any{"Group-14", "Group-2"}, got["phase1DhGroups"].Value)
		assert.Equal(t, []any{"AES-GCM-16-256"}, got["phase2EncryptionAlgorithms"].Value)
		assert.Equal(t, []any{"HMAC-SHA1-96"}, got["phase2IntegrityAlgorithms"].Value)
		assert.Equal(t, []any{"Group-20"}, got["phase2PfsGroups"].Value)
		assert.Equal(t, types.Array(types.String), got["phase1DhGroups"].Type)
	})

	// Synthetic: only phase 2 configured; no live tunnel showed this.
	t.Run("phase2 only leaves phase1 roles null", func(t *testing.T) {
		got := vpnTunnelCipherSuiteArgs(&compute.VpnTunnelCipherSuite{
			Phase2: &compute.VpnTunnelPhase2Algorithms{
				Encryption: []string{"AES-CBC-128"},
				Pfs:        []string{"Group-14"},
			},
		})
		assert.Nil(t, got["phase1EncryptionAlgorithms"].Value)
		assert.Nil(t, got["phase1IntegrityAlgorithms"].Value)
		assert.Nil(t, got["phase1PrfAlgorithms"].Value)
		assert.Nil(t, got["phase1DhGroups"].Value)
		assert.Equal(t, []any{"AES-CBC-128"}, got["phase2EncryptionAlgorithms"].Value)
		assert.Nil(t, got["phase2IntegrityAlgorithms"].Value, "an empty role inside a configured phase is null, not an empty list")
		assert.Equal(t, []any{"Group-14"}, got["phase2PfsGroups"].Value)
	})

	// Synthetic: a tunnel with no cipherSuite, which the API omits when nothing
	// is configured.
	t.Run("nil cipher suite yields null for every role", func(t *testing.T) {
		got := vpnTunnelCipherSuiteArgs(nil)
		assert.Len(t, got, len(cipherFields))
		for _, f := range cipherFields {
			if assert.Contains(t, got, f) {
				assert.Nil(t, got[f].Value, f)
			}
		}
	})

	// Synthetic: cipherSuite present with empty phases.
	t.Run("empty phases yield null for every role", func(t *testing.T) {
		got := vpnTunnelCipherSuiteArgs(&compute.VpnTunnelCipherSuite{
			Phase1: &compute.VpnTunnelPhase1Algorithms{},
			Phase2: &compute.VpnTunnelPhase2Algorithms{Encryption: []string{}},
		})
		for _, f := range cipherFields {
			assert.Nil(t, got[f].Value, f)
		}
	})
}

func TestFirewallSourceRangesContainPublic(t *testing.T) {
	cases := []struct {
		name   string
		ranges []any
		want   bool
	}{
		{"ipv4 any", []any{"0.0.0.0/0"}, true},
		{"ipv6 any", []any{"::/0"}, true},
		{"ipv4 halves", []any{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{"one ipv4 half", []any{"128.0.0.0/1"}, true},
		{"ipv4 /7", []any{"8.0.0.0/7"}, true},
		{"ipv6 /3 global unicast", []any{"2000::/3"}, true},
		{"surrounding whitespace", []any{" 0.0.0.0/0 "}, true},
		{"rfc1918 /8", []any{"10.0.0.0/8"}, false},
		{"ipv6 unique local", []any{"fc00::/7"}, false},
		{"ipv4 multicast and reserved", []any{"224.0.0.0/3"}, false},
		{"ipv4 reserved", []any{"240.0.0.0/4"}, false},
		{"ipv6 /11 inside global unicast", []any{"2000::/11"}, true},
		{"ipv6 /12 not broad enough", []any{"2000::/12"}, false},
		{"single host", []any{"203.0.113.7/32"}, false},
		{"bare address", []any{"203.0.113.7"}, false},
		{"empty", []any{}, false},
		{"non-string", []any{42}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firewallSourceRangesContainPublic(tc.ranges))
		})
	}
}

// v4Slash8s returns first.0.0.0/8 through last.0.0.0/8, stepping by step.
func v4Slash8s(first, last, step int) []any {
	out := []any{}
	for i := first; i <= last; i += step {
		out = append(out, fmt.Sprintf("%d.0.0.0/8", i))
	}
	return out
}

// v4Slash9s returns the two /9s of every /8 from first through last.
func v4Slash9s(first, last int) []any {
	out := []any{}
	for i := first; i <= last; i++ {
		out = append(out, fmt.Sprintf("%d.0.0.0/9", i), fmt.Sprintf("%d.128.0.0/9", i))
	}
	return out
}

// v6OddSlash12s returns every other /12 inside 2000::/3, 256 in all.
func v6OddSlash12s() []any {
	out := []any{}
	for i := 1; i < 512; i += 2 {
		out = append(out, fmt.Sprintf("%x::/12", 0x2000+i<<4))
	}
	return out
}

func TestInternetSourceFamilies(t *testing.T) {
	cases := []struct {
		name   string
		ranges []any
		wantV4 bool
		wantV6 bool
	}{
		{"256 /8s cover all of ipv4", v4Slash8s(0, 255, 1), true, false},
		{"448 /9s cover 0.0.0.0 through 223.255.255.255", v4Slash9s(0, 223), true, false},
		{"128 /9s span 0.0.0.0/2", v4Slash9s(0, 63), true, false},
		{"odd /8s cover half the routable space with no aligned /7", v4Slash8s(1, 223, 2), true, false},
		{"odd /8s one short of half", v4Slash8s(1, 221, 2), false, false},
		{"two /8s straddling a /7 boundary", []any{"1.0.0.0/8", "2.0.0.0/8"}, false, false},
		{"two /8s forming an aligned /7", []any{"2.0.0.0/8", "3.0.0.0/8"}, true, false},
		{"/8s inside multicast and reserved", v4Slash8s(224, 255, 1), false, false},
		{"private ranges", []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, false, false},
		{"mixed families both open", append(v4Slash8s(0, 255, 1), "2000::/4", "3000::/4"), true, true},
		{"ipv6 /12s forming an aligned /11", []any{"2000::/12", "2010::/12"}, false, true},
		{"ipv6 /12s with a gap", []any{"2000::/12", "2020::/12"}, false, false},
		{"ipv6 every other /12 covers half of 2000::/3", v6OddSlash12s(), false, true},
		{"ipv6 hosts are ignored", []any{"2001:db8::1/128", "2001:db8::2/128"}, false, false},
		{"ipv4 open, ipv6 gap", append(v4Slash9s(0, 223), "2000::/12", "2020::/12"), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := internetSourceFamilies(tc.ranges)
			assert.Equal(t, tc.wantV4, v4, "ipv4")
			assert.Equal(t, tc.wantV6, v6, "ipv6")
			assert.Equal(t, tc.wantV4 || tc.wantV6, firewallSourceRangesContainPublic(tc.ranges))
		})
	}
}

func TestMergeSpans(t *testing.T) {
	got := mergeSpans([]addrSpan{{10, 20}, {0, 4}, {21, 30}, {5, 5}, {40, 50}, {45, 46}})
	assert.Equal(t, []addrSpan{{0, 5}, {10, 30}, {40, 50}}, got)
	full := mergeSpans([]addrSpan{{0, ^uint64(0)}, {7, 9}})
	assert.Equal(t, []addrSpan{{0, ^uint64(0)}}, full)
}

func TestAllowedRulePermitsPortWithHalvesSourceRanges(t *testing.T) {
	// allowsSshFromInternet combines the source-range test with the port test.
	ranges := []any{"0.0.0.0/1", "128.0.0.0/1"}
	rule := map[string]any{"IPProtocol": "tcp", "ports": []any{"22", "3389"}}
	assert.True(t, firewallSourceRangesContainPublic(ranges))
	assert.True(t, allowedRulePermitsPort(rule, 22))
	assert.True(t, allowedRulePermitsPort(rule, 3389))
}
