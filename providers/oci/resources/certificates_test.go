// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/stretchr/testify/assert"
)

func TestCaKindFromConfigType(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "root CA generated internally maps to ROOT",
			cfg:  string(certificatesmanagement.CertificateAuthorityConfigTypeRootCaGeneratedInternally),
			want: "ROOT",
		},
		{
			name: "root CA managed externally maps to ROOT",
			cfg:  string(certificatesmanagement.CertificateAuthorityConfigTypeRootCaManagedExternally),
			want: "ROOT",
		},
		{
			name: "subordinate CA issued by internal maps to SUBORDINATE",
			cfg:  string(certificatesmanagement.CertificateAuthorityConfigTypeSubordinateCaIssuedByInternalCa),
			want: "SUBORDINATE",
		},
		{
			name: "subordinate CA managed internally by external maps to SUBORDINATE",
			cfg:  string(certificatesmanagement.CertificateAuthorityConfigTypeSubordinateCaManagedInternallyIssuedByExternalCa),
			want: "SUBORDINATE",
		},
		{
			name: "empty string maps to empty string",
			cfg:  "",
			want: "",
		},
		{
			name: "unknown enum value maps to empty string",
			cfg:  "SOMETHING_NEW_FROM_OCI",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, caKindFromConfigType(tc.cfg))
		})
	}
}

// unknownCertRule is a stand-in for a future CertificateRule variant the
// flattener doesn't know about. Satisfies the empty CertificateRule interface.
type unknownCertRule struct{}

func TestExtractCertificateRenewal(t *testing.T) {
	t.Run("empty rule set", func(t *testing.T) {
		enabled, interval := extractCertificateRenewal(nil)
		assert.False(t, enabled)
		assert.Equal(t, "", interval)
	})

	t.Run("renewal rule present", func(t *testing.T) {
		rules := []certificatesmanagement.CertificateRule{
			certificatesmanagement.CertificateRenewalRule{
				RenewalInterval:      new("P90D"),
				AdvanceRenewalPeriod: new("P7D"),
			},
		}
		enabled, interval := extractCertificateRenewal(rules)
		assert.True(t, enabled)
		assert.Equal(t, "P90D", interval)
	})

	t.Run("renewal rule with nil interval returns enabled+empty", func(t *testing.T) {
		rules := []certificatesmanagement.CertificateRule{
			certificatesmanagement.CertificateRenewalRule{},
		}
		enabled, interval := extractCertificateRenewal(rules)
		assert.True(t, enabled)
		assert.Equal(t, "", interval)
	})

	t.Run("unknown rule type is ignored", func(t *testing.T) {
		rules := []certificatesmanagement.CertificateRule{unknownCertRule{}}
		enabled, interval := extractCertificateRenewal(rules)
		assert.False(t, enabled)
		assert.Equal(t, "", interval)
	})

	t.Run("first renewal rule wins when multiple present", func(t *testing.T) {
		rules := []certificatesmanagement.CertificateRule{
			unknownCertRule{},
			certificatesmanagement.CertificateRenewalRule{
				RenewalInterval: new("P30D"),
			},
			certificatesmanagement.CertificateRenewalRule{
				RenewalInterval: new("P60D"),
			},
		}
		enabled, interval := extractCertificateRenewal(rules)
		assert.True(t, enabled)
		assert.Equal(t, "P30D", interval)
	})
}

func TestSanSliceToAny(t *testing.T) {
	t.Run("nil slice returns empty", func(t *testing.T) {
		assert.Equal(t, []any{}, sanSliceToAny(nil))
	})

	t.Run("empty slice returns empty", func(t *testing.T) {
		assert.Equal(t, []any{}, sanSliceToAny([]certificatesmanagement.CertificateSubjectAlternativeName{}))
	})

	t.Run("mixed DNS and IP SANs are formatted as type:value", func(t *testing.T) {
		sans := []certificatesmanagement.CertificateSubjectAlternativeName{
			{
				Type:  certificatesmanagement.CertificateSubjectAlternativeNameTypeDns,
				Value: new("api.example.com"),
			},
			{
				Type:  certificatesmanagement.CertificateSubjectAlternativeNameTypeIp,
				Value: new("10.0.0.1"),
			},
		}
		out := sanSliceToAny(sans)
		assert.Equal(t, []any{"DNS:api.example.com", "IP:10.0.0.1"}, out)
	})

	t.Run("nil value pointer yields type:empty", func(t *testing.T) {
		sans := []certificatesmanagement.CertificateSubjectAlternativeName{
			{
				Type: certificatesmanagement.CertificateSubjectAlternativeNameTypeDns,
			},
		}
		out := sanSliceToAny(sans)
		assert.Equal(t, []any{"DNS:"}, out)
	})
}
