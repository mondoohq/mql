// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/azure/resources"
)

const (
	testSubID      = "00000000-0000-0000-0000-000000000000"
	testTenantID   = "11111111-1111-1111-1111-111111111111"
	testPlatformID = "//platformid.api.mondoo.app/runtime/azure/subscriptions/" + testSubID
)

// detect used to be a bare `return nil`, so the root asset -- the one the caller
// connected as, before any discovery -- reached the client with no platform, no
// name, and no platform id. Every Azure scan carried one blank entry, and
// `--discover none` produced nothing but the blank entry.
func TestApplyAzureSubscriptionIdentity(t *testing.T) {
	asset := &inventory.Asset{}
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")

	require.NotNil(t, asset.Platform, "a blank platform is the defect")
	assert.Equal(t, "azure", asset.Platform.Name)
	assert.Equal(t, []string{"azure", testTenantID, testSubID, "account"},
		asset.Platform.TechnologyUrlSegments)

	assert.Equal(t, []string{testPlatformID}, asset.PlatformIds)
	assert.Equal(t, testPlatformID, asset.Id)
	assert.Equal(t, "Azure subscription Production", asset.Name)
	assert.Equal(t, testSubID, asset.Labels[resources.SubscriptionLabel])
}

// The whole point is that the same subscription reads the same whether it arrived
// as the root asset or as one discovery found, so the shape has to match
// subToAsset's: the same platform id, the same name prefix, the same label. The
// client recognizes the discovered duplicate by this platform id and skips it,
// which is what removes the second entry from the scan.
func TestApplyAzureSubscriptionIdentityMatchesDiscoveryShape(t *testing.T) {
	asset := &inventory.Asset{}
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")

	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/"+testSubID, asset.Id,
		"the platform id format discovery uses")
	assert.Equal(t, asset.Id, asset.PlatformIds[0], "id and platform id agree")
	assert.Equal(t, "azure.mondoo.com/subscription", resources.SubscriptionLabel,
		"the label key discovery sets")
}

func TestApplyAzureSubscriptionIdentityFallbacks(t *testing.T) {
	t.Run("no display name falls back to the id", func(t *testing.T) {
		// Reached when the subscription lookup fails, or when ARM omits
		// displayName -- which it does for deleted, disabled, and cross-tenant
		// subscriptions. A scan must not fail over a display name.
		asset := &inventory.Asset{}
		applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "")
		assert.Equal(t, "Azure subscription "+testSubID, asset.Name)
	})

	t.Run("no tenant id is reported as unknown", func(t *testing.T) {
		// Reached only when the caller passed no --tenant-id AND the ARM
		// record could not be read; detect otherwise takes the tenant from
		// the record, the same field subToAsset reads for a discovered
		// subscription.
		asset := &inventory.Asset{}
		applyAzureSubscriptionIdentity(asset, testSubID, "", testPlatformID, "Production")
		assert.Equal(t, []string{"azure", "unknown", testSubID, "account"},
			asset.Platform.TechnologyUrlSegments)
	})
}

// An asset that already carries an id or a label keeps them: those came from
// whoever built the asset, and this only fills in what is missing.
func TestApplyAzureSubscriptionIdentityDoesNotOverwriteExistingIdentity(t *testing.T) {
	asset := &inventory.Asset{
		Id:     "//some/other/id",
		Labels: map[string]string{resources.SubscriptionLabel: "someone-elses-sub", "env": "prod"},
	}
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")

	assert.Equal(t, "//some/other/id", asset.Id, "an id already set is left alone")
	assert.Equal(t, "someone-elses-sub", asset.Labels[resources.SubscriptionLabel])
	assert.Equal(t, "prod", asset.Labels["env"], "unrelated labels survive")
}

// Platform ids that arrived with the asset are the key an integration may
// resolve it by, so they survive; the connection's own id is appended so the
// client can still recognize the discovered duplicate of this subscription.
func TestApplyAzureSubscriptionIdentityKeepsExistingPlatformIds(t *testing.T) {
	asset := &inventory.Asset{PlatformIds: []string{"//integration/key/for/this/asset"}}
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")

	assert.Equal(t, []string{"//integration/key/for/this/asset", testPlatformID}, asset.PlatformIds)

	// And appending is idempotent: a second detect pass adds nothing.
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")
	assert.Equal(t, []string{"//integration/key/for/this/asset", testPlatformID}, asset.PlatformIds)
}

// A name the caller supplied via --asset-name survives detect. Naming the root
// asset here runs after cnspec has already applied --asset-name, so an
// unconditional write makes that flag a no-op for every Azure scan.
func TestApplyAzureSubscriptionIdentityKeepsARequestedName(t *testing.T) {
	asset := &inventory.Asset{Name: "prod-billing-account"}
	applyAzureSubscriptionIdentity(asset, testSubID, testTenantID, testPlatformID, "Production")

	assert.Equal(t, "prod-billing-account", asset.Name, "a name already set is left alone")

	// The rest of the identity is still stamped on.
	assert.Equal(t, []string{testPlatformID}, asset.PlatformIds)
	assert.Equal(t, testSubID, asset.Labels[resources.SubscriptionLabel])
}

// detect returns without touching the asset when there is no single subscription
// to be: the caller named several, or none, and discovery enumerates them.
func TestDetectLeavesAMultiSubscriptionConnectionAlone(t *testing.T) {
	s := &Service{}
	asset := &inventory.Asset{}

	// A nil connection is not an *AzureConnection, which is the same branch a
	// snapshot connection takes -- those are detected by the os provider.
	require.NoError(t, s.detect(asset, nil))
	assert.Nil(t, asset.Platform)
	assert.Empty(t, asset.Name)
	assert.Empty(t, asset.PlatformIds)
}
