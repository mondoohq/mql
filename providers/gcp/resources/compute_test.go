// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
)

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
