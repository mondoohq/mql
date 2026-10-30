// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"github.com/stretchr/testify/assert"
)

func TestDecryptionProfileFields(t *testing.T) {
	// The forward-proxy-only controls that must be null for inbound profiles.
	forwardProxyOnly := []string{
		"isExpiredCertificateBlocked",
		"isUntrustedIssuerBlocked",
		"isRevocationStatusTimeoutBlocked",
		"isUnknownRevocationStatusBlocked",
		"areCertificateExtensionsRestricted",
		"isAutoIncludeAltName",
	}

	t.Run("forward-proxy profile populates all blocking controls", func(t *testing.T) {
		summary := networkfirewall.DecryptionProfileSummary{Name: new("fp")}
		dp := networkfirewall.SslForwardProxyProfile{
			IsUnsupportedVersionBlocked:        new(true),
			IsUnsupportedCipherBlocked:         new(true),
			IsOutOfCapacityBlocked:             new(false),
			IsExpiredCertificateBlocked:        new(true),
			IsUntrustedIssuerBlocked:           new(true),
			IsRevocationStatusTimeoutBlocked:   new(false),
			IsUnknownRevocationStatusBlocked:   new(true),
			AreCertificateExtensionsRestricted: new(false),
			IsAutoIncludeAltName:               new(true),
		}

		fields := decryptionProfileFields(dp, summary)
		assert.Equal(t, "fp", fields["name"].Value)
		assert.Equal(t, "SSL_FORWARD_PROXY", fields["type"].Value)
		assert.Equal(t, true, fields["isUnsupportedVersionBlocked"].Value)
		assert.Equal(t, false, fields["isOutOfCapacityBlocked"].Value)
		assert.Equal(t, true, fields["isExpiredCertificateBlocked"].Value)
		assert.Equal(t, false, fields["areCertificateExtensionsRestricted"].Value)
		// none of the forward-proxy controls are null
		for _, k := range forwardProxyOnly {
			assert.NotNil(t, fields[k].Value, k)
		}
	})

	t.Run("inbound-inspection profile leaves certificate controls null", func(t *testing.T) {
		summary := networkfirewall.DecryptionProfileSummary{Name: new("inbound")}
		dp := networkfirewall.SslInboundInspectionProfile{
			IsUnsupportedVersionBlocked: new(true),
			IsUnsupportedCipherBlocked:  new(false),
			IsOutOfCapacityBlocked:      new(true),
		}

		fields := decryptionProfileFields(dp, summary)
		assert.Equal(t, "SSL_INBOUND_INSPECTION", fields["type"].Value)
		assert.Equal(t, true, fields["isUnsupportedVersionBlocked"].Value)
		assert.Equal(t, false, fields["isUnsupportedCipherBlocked"].Value)
		// the forward-proxy-only controls are not applicable → null
		for _, k := range forwardProxyOnly {
			assert.Nil(t, fields[k].Value, k)
		}
	})
}
