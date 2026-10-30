// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	vimtypes "github.com/vmware/govmomi/vim25/types"

	"github.com/stretchr/testify/assert"
)

func idInfo(key, value string) vimtypes.HostSystemIdentificationInfo {
	return vimtypes.HostSystemIdentificationInfo{
		IdentifierType:  &vimtypes.ElementDescription{Key: key},
		IdentifierValue: value,
	}
}

func TestClassifyIdentifyingInfo(t *testing.T) {
	t.Run("promotes known keys and bags the rest", func(t *testing.T) {
		asset, service, installDate, oem := classifyIdentifyingInfo([]vimtypes.HostSystemIdentificationInfo{
			idInfo("AssetTag", "ASSET-123"),
			idInfo("ServiceTag", "SVC-456"),
			idInfo("HostInstallDate", "2023-05-01T10:00:00Z"),
			idInfo("EnclosureSerialNumberTag", "ENC-789"),
		})
		assert.Equal(t, "ASSET-123", asset)
		assert.Equal(t, "SVC-456", service)
		assert.False(t, installDate.IsZero())
		assert.Equal(t, 2023, installDate.Year())
		assert.Equal(t, map[string]any{"EnclosureSerialNumberTag": "ENC-789"}, oem)
	})

	t.Run("missing install date leaves it zero without error", func(t *testing.T) {
		_, _, installDate, oem := classifyIdentifyingInfo([]vimtypes.HostSystemIdentificationInfo{
			idInfo("AssetTag", "A"),
		})
		assert.True(t, installDate.IsZero())
		assert.Empty(t, oem)
	})

	t.Run("non-RFC3339 install date is ignored, not fatal", func(t *testing.T) {
		_, _, installDate, _ := classifyIdentifyingInfo([]vimtypes.HostSystemIdentificationInfo{
			idInfo("HostInstallDate", "2023-05-01"), // not RFC3339
		})
		assert.True(t, installDate.IsZero())
	})

	t.Run("empty key is not bagged", func(t *testing.T) {
		_, _, _, oem := classifyIdentifyingInfo([]vimtypes.HostSystemIdentificationInfo{
			idInfo("", "orphan"),
		})
		assert.Empty(t, oem)
	})
}
