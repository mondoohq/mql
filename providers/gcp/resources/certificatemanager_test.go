// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/stretchr/testify/assert"
)

func TestCertificateUsedBy(t *testing.T) {
	// Synthetic: no certificate on a live target; names follow the format the
	// API documents for the field.
	entry := "//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m/certificateMapEntries/e"
	proxy := "//compute.googleapis.com/projects/p/locations/global/targetHttpsProxies/web"
	got := certificateUsedBy([]*certificatemanagerpb.Certificate_UsedBy{
		{Name: entry},
		nil,
		{Name: ""},
		{Name: proxy},
	})
	assert.Equal(t, []any{entry, proxy}, got)

	// Synthetic: an unused certificate reads as an empty list, not null.
	unused := certificateUsedBy(nil)
	assert.NotNil(t, unused)
	assert.Empty(t, unused)
}

func TestFlattenSpiffeTrustStores(t *testing.T) {
	// Synthetic: no trust config on a live target.
	got := flattenSpiffeTrustStores(map[string]*certificatemanagerpb.TrustConfig_TrustStore{
		"example.org": {
			TrustAnchors: []*certificatemanagerpb.TrustConfig_TrustAnchor{
				{Kind: &certificatemanagerpb.TrustConfig_TrustAnchor_PemCertificate{PemCertificate: "ROOT"}},
			},
			IntermediateCas: []*certificatemanagerpb.TrustConfig_IntermediateCA{
				{Kind: &certificatemanagerpb.TrustConfig_IntermediateCA_PemCertificate{PemCertificate: "INT"}},
			},
		},
		"empty.example": nil,
	})
	assert.Equal(t, map[string]any{
		"example.org": map[string]any{
			"trustAnchors":    []any{map[string]any{"pemCertificate": "ROOT"}},
			"intermediateCas": []any{map[string]any{"pemCertificate": "INT"}},
		},
		"empty.example": map[string]any{
			"trustAnchors":    []any{},
			"intermediateCas": []any{},
		},
	}, got)

	// Synthetic: no SPIFFE trust domain configured.
	assert.Empty(t, flattenSpiffeTrustStores(nil))
}

func TestFlattenAllowlistedCertificates(t *testing.T) {
	// Synthetic: no trust config on a live target.
	got := flattenAllowlistedCertificates([]*certificatemanagerpb.TrustConfig_AllowlistedCertificate{
		{PemCertificate: "LEAF"},
		nil,
	})
	assert.Equal(t, []any{map[string]any{"pemCertificate": "LEAF"}}, got)

	// Synthetic: nothing allowlisted reads as an empty list, not null.
	none := flattenAllowlistedCertificates(nil)
	assert.NotNil(t, none)
	assert.Empty(t, none)
}
