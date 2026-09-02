// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestHandDownRequestedName covers --asset-name on the fan-out providers. Their
// detect step sets a platform but no platform ID, so the node the caller connected
// to is never scanned and renaming it changes nothing. The request has to reach the
// asset that is actually scanned, but only when there is exactly one of them.
func TestHandDownRequestedName(t *testing.T) {
	t.Run("hands the name to the only child of an unscannable node", func(t *testing.T) {
		// `cnspec scan aws --asset-name prod-account`: the aws root carries no
		// platform IDs and the account below it is what gets scanned
		child := &TrackedAsset{Asset: &inventory.Asset{
			Name:        "alias-123456789012",
			PlatformIds: []string{"//platformid.api.mondoo.app/runtime/aws/accounts/123456789012"},
		}}
		root := &TrackedAsset{Asset: &inventory.Asset{}, Children: []*TrackedAsset{child}}

		handDownRequestedName(root, "prod-account")

		assert.Equal(t, "prod-account", child.Asset.Name)
		assert.Equal(t, "prod-account", requestedName(child.Asset), "the child has to survive its own connect")
	})

	t.Run("leaves a fan-out alone", func(t *testing.T) {
		// several scannable assets and no way to tell which one the caller meant --
		// naming one of a fleet after the scan is worse than not naming it at all
		children := []*TrackedAsset{
			{Asset: &inventory.Asset{Name: "i-aaa", PlatformIds: []string{"aaa"}}},
			{Asset: &inventory.Asset{Name: "i-bbb", PlatformIds: []string{"bbb"}}},
		}
		root := &TrackedAsset{Asset: &inventory.Asset{}, Children: children}

		handDownRequestedName(root, "prod-account")

		assert.Equal(t, "i-aaa", children[0].Asset.Name)
		assert.Equal(t, "i-bbb", children[1].Asset.Name)
	})

	t.Run("keeps the name on a node that is itself scannable", func(t *testing.T) {
		// a scannable root already wears the requested name, so passing it down
		// would put the same name on two assets in one scan
		child := &TrackedAsset{Asset: &inventory.Asset{Name: "container-1", PlatformIds: []string{"c1"}}}
		root := &TrackedAsset{
			Asset:    &inventory.Asset{Name: "my-host", PlatformIds: []string{"host"}},
			Children: []*TrackedAsset{child},
		}

		handDownRequestedName(root, "my-host")

		assert.Equal(t, "container-1", child.Asset.Name)
	})

	t.Run("does nothing without a request", func(t *testing.T) {
		child := &TrackedAsset{Asset: &inventory.Asset{Name: "alias-123456789012"}}
		root := &TrackedAsset{Asset: &inventory.Asset{}, Children: []*TrackedAsset{child}}

		handDownRequestedName(root, "")

		assert.Equal(t, "alias-123456789012", child.Asset.Name)
		assert.False(t, child.Asset.NameOverride)
	})

	t.Run("tolerates a childless node and a nil node", func(t *testing.T) {
		assert.NotPanics(t, func() {
			handDownRequestedName(&TrackedAsset{Asset: &inventory.Asset{}}, "prod-account")
			handDownRequestedName(nil, "prod-account")
		})
	})
}
