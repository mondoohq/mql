// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/ids"
)

func TestDefaultIdDetectors(t *testing.T) {
	cloudHost := []string{ids.IdDetector_CloudDetect, ids.IdDetector_Hostname}
	withBios := []string{ids.IdDetector_CloudDetect, ids.IdDetector_Hostname, ids.IdDetector_BiosUUID}

	assert.Equal(t, cloudHost, DefaultIdDetectors(shared.Type_Local, &plugin.ConnectReq{}, false))
	assert.Equal(t, withBios, DefaultIdDetectors(shared.Type_Local, &plugin.ConnectReq{}, true), "bios-uuid on VMs")
	assert.Equal(t, cloudHost, DefaultIdDetectors(shared.Type_SSH, nil, false))
	assert.Equal(t, withBios, DefaultIdDetectors(shared.Type_SSH, nil, true), "bios-uuid on VMs")
	assert.Equal(t, []string{ids.IdDetector_Hostname}, DefaultIdDetectors(shared.Type_Tar, nil, true))
	assert.Nil(t, DefaultIdDetectors(shared.Type_Winrm, nil, false))
}

func TestIdentifyPlatformDefaultKeyword(t *testing.T) {
	identify := func(t *testing.T, detectors []string) (*PlatformFingerprint, error) {
		t.Helper()
		asset := &inventory.Asset{}
		conn := local.NewConnection(1, &inventory.Config{Type: "local"}, asset)
		fp, _, err := IdentifyPlatform(conn, &plugin.ConnectReq{}, nil, detectors)
		return fp, err
	}

	implicit, err := identify(t, nil)
	require.NoError(t, err)
	require.NotEmpty(t, implicit.ActiveIdDetectors)

	t.Run("default expands like the empty list", func(t *testing.T) {
		fp, err := identify(t, []string{ids.IdDetector_Default})
		require.NoError(t, err)
		assert.Equal(t, implicit.ActiveIdDetectors, fp.ActiveIdDetectors)
		assert.Equal(t, implicit.PlatformIDs, fp.PlatformIDs)
	})

	t.Run("default plus a detector", func(t *testing.T) {
		fp, err := identify(t, []string{ids.IdDetector_Default, ids.IdDetector_CrowdStrikeAID})
		require.NoError(t, err)
		assert.Equal(t, append(append([]string{}, implicit.ActiveIdDetectors...), ids.IdDetector_CrowdStrikeAID), fp.ActiveIdDetectors)
		assert.Subset(t, fp.PlatformIDs, implicit.PlatformIDs)
	})

	t.Run("a single detector is used alone", func(t *testing.T) {
		fp, err := identify(t, []string{ids.IdDetector_Hostname})
		require.NoError(t, err)
		assert.Equal(t, []string{ids.IdDetector_Hostname}, fp.ActiveIdDetectors)
	})

	t.Run("an unknown detector alone fails as before", func(t *testing.T) {
		_, err := identify(t, []string{"no-such-detector"})
		assert.Error(t, err)
	})

	t.Run("an unknown detector next to default is skipped", func(t *testing.T) {
		fp, err := identify(t, []string{ids.IdDetector_Default, "no-such-detector"})
		require.NoError(t, err)
		assert.Equal(t, implicit.PlatformIDs, fp.PlatformIDs)
	})
}
