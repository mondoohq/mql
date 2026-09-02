// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestRequestedName covers the distinction the whole fix rests on: a name sitting on
// an inventory asset is not evidence that anyone asked for it. Around seventeen
// providers set Asset.Name in their own ParseCLI and then improve it in detect, so
// treating any present name as a request hands the placeholder the win.
func TestRequestedName(t *testing.T) {
	t.Run("a marked name is a request", func(t *testing.T) {
		asset := &inventory.Asset{Name: "my-prod-state", NameOverride: true}

		assert.Equal(t, "my-prod-state", requestedName(asset))
	})

	t.Run("an unmarked name is a provider default", func(t *testing.T) {
		// `mql shell docker b4b8a93f9d85` -- the os provider's ParseCLI names the
		// asset after the raw container id, and detect replaces it with the
		// container's real name. Reading this as a request renames every scanned
		// container back to its id.
		asset := &inventory.Asset{Name: "b4b8a93f9d85"}

		assert.Empty(t, requestedName(asset))
	})

	t.Run("tolerates a nil asset", func(t *testing.T) {
		assert.Empty(t, requestedName(nil))
	})
}

// TestRestoreRequestedName covers the name precedence between the caller and the
// provider. Connecting replaces the asset with the provider's connection asset, and
// providers name that asset in their detect step -- several of them unconditionally.
// A name the caller asked for has to survive that.
func TestRestoreRequestedName(t *testing.T) {
	t.Run("restores a name the provider overwrote", func(t *testing.T) {
		// what `cnspec scan terraform plan tf.json --asset-name ...` looks like
		// after the terraform provider's detect step has run
		asset := &inventory.Asset{Name: "Terraform Plan tf"}

		restoreRequestedName(asset, "tf-plan-team-sandbox")

		assert.Equal(t, "tf-plan-team-sandbox", asset.Name)
	})

	t.Run("keeps the marker so the name survives a second connect", func(t *testing.T) {
		asset := &inventory.Asset{Name: "Terraform Plan tf"}

		restoreRequestedName(asset, "tf-plan-team-sandbox")

		assert.Equal(t, "tf-plan-team-sandbox", requestedName(asset))
	})

	t.Run("keeps the detected name when none was requested", func(t *testing.T) {
		// the docker regression in its end-to-end shape: ParseCLI left the container
		// id behind, detect resolved the real name, and nothing was ever requested
		asset := &inventory.Asset{Name: "server-postgres-1"}

		restoreRequestedName(asset, requestedName(&inventory.Asset{Name: "b4b8a93f9d85"}))

		assert.Equal(t, "server-postgres-1", asset.Name)
		assert.False(t, asset.NameOverride)
	})

	t.Run("names a provider left empty", func(t *testing.T) {
		asset := &inventory.Asset{}

		restoreRequestedName(asset, "tf-plan-team-sandbox")

		assert.Equal(t, "tf-plan-team-sandbox", asset.Name)
	})

	t.Run("is a no-op when the provider agrees with the request", func(t *testing.T) {
		asset := &inventory.Asset{Name: "tf-plan-team-sandbox"}

		restoreRequestedName(asset, "tf-plan-team-sandbox")

		assert.Equal(t, "tf-plan-team-sandbox", asset.Name)
	})

	t.Run("tolerates a nil asset", func(t *testing.T) {
		assert.NotPanics(t, func() {
			restoreRequestedName(nil, "tf-plan-team-sandbox")
		})
	})
}
