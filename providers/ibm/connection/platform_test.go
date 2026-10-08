// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestSubAssetFromOptions(t *testing.T) {
	c := &IbmConnection{Conf: &inventory.Config{Options: map[string]string{OptionPowerWorkspace: "crn:ws"}}}
	s, crn, ok := c.SubAsset()
	require.True(t, ok)
	assert.Equal(t, OptionPowerWorkspace, s.Option)
	assert.Equal(t, "crn:ws", crn)

	c = &IbmConnection{Conf: &inventory.Config{Options: map[string]string{}}}
	_, _, ok = c.SubAsset()
	assert.False(t, ok)
}

func TestSubAssetIdentifier(t *testing.T) {
	c := &IbmConnection{accountID: "acc"}
	assert.Equal(t, PlatformIdIbmAccount+"acc/power-workspace/crn:ws", c.SubAssetIdentifier(SubAssets[2], "crn:ws"))
}

func TestEveryPlatformIsCataloged(t *testing.T) {
	for _, s := range SubAssets {
		assert.NotNil(t, PlatformByName(s.Platform), s.Platform)
	}
	assert.NotNil(t, PlatformByName("ibm-account"))
}
