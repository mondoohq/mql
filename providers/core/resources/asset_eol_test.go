// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEolLabels(t *testing.T) {
	t.Run("platform metadata reaches the lookup", func(t *testing.T) {
		// Measured: SLES 15 SP4 (EC2 suse-sles-15-sp4-sapcal-v20260703) with
		// an SLES-LTSS extension in /etc/products.d, 2026-10-31. The LTSS
		// extension is only in the platform metadata.
		got := eolLabels(
			map[string]any{"distro-id": "sles", "variant-id": "sles-sapcal"},
			map[string]any{
				"distro-id":        "sles",
				"suse/baseproduct": "sles",
				"suse/modules":     "Linux Enterprise Server LTSS 15 SP4,Basesystem,Public Cloud",
			},
		)
		assert.Equal(t, map[string]string{
			"distro-id":        "sles",
			"variant-id":       "sles-sapcal",
			"suse/baseproduct": "sles",
			"suse/modules":     "Linux Enterprise Server LTSS 15 SP4,Basesystem,Public Cloud",
		}, got)
	})

	t.Run("metadata wins on a shared key", func(t *testing.T) {
		// Synthetic: the vulnerability database merges metadata last; no
		// target showed differing values.
		got := eolLabels(map[string]any{"ubuntu/pro": "disabled"}, map[string]any{"ubuntu/pro": "enabled"})
		assert.Equal(t, "enabled", got["ubuntu/pro"])
	})

	t.Run("no labels and no metadata", func(t *testing.T) {
		// Synthetic: an asset without labels, such as a cloud account.
		assert.Nil(t, eolLabels(nil, nil))
	})
}
