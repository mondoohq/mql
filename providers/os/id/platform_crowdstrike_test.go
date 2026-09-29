// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector/crowdstrike"
	"go.mondoo.com/mql/providers/os/id/ids"
)

func TestGatherPlatformInfoCrowdStrikeAID(t *testing.T) {
	const (
		aid = "4d7f5b8b9e0b4c2a8d1e2f3a4b5c6d7e"
		cid = "0123456789abcdef0123456789abcdef"
	)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	linux := func(labels map[string]string) *inventory.Platform {
		return &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}, Labels: labels}
	}

	t.Run("no sensor yields no id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, linux(nil), ids.IdDetector_CrowdStrikeAID)
		require.NoError(t, err)
		assert.Empty(t, info.IDs)
	})

	t.Run("detected sensor yields a cid-scoped id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, linux(map[string]string{
			crowdstrike.LabelAID: aid,
			crowdstrike.LabelCID: cid,
		}), ids.IdDetector_CrowdStrikeAID)
		require.NoError(t, err)
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/crowdstrike/cids/" + cid + "/aids/" + aid}, info.IDs)
	})

	t.Run("sensor without a cid yields no id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, linux(map[string]string{crowdstrike.LabelAID: aid}), ids.IdDetector_CrowdStrikeAID)
		require.NoError(t, err)
		assert.Empty(t, info.IDs, "an AID is only unique within a customer")
	})

	t.Run("sensor that is not registered yet yields no id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, linux(map[string]string{crowdstrike.LabelCID: cid}), ids.IdDetector_CrowdStrikeAID)
		require.NoError(t, err)
		assert.Empty(t, info.IDs)
	})

	t.Run("reads the sensor when detection recorded no labels", func(t *testing.T) {
		falconctl := "/opt/CrowdStrike/falconctl"
		sensor, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
			Files: map[string]*mock.MockFileData{falconctl: {Path: falconctl, StatData: mock.FileInfo{Mode: 0o750}}},
			Commands: map[string]*mock.Command{
				falconctl + " -g --aid --cid": {Stdout: `cid="` + cid + `", aid="` + aid + `".` + "\n"},
			},
		}))
		require.NoError(t, err)
		info, err := gatherPlatformInfo(sensor, linux(nil), ids.IdDetector_CrowdStrikeAID)
		require.NoError(t, err)
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/crowdstrike/cids/" + cid + "/aids/" + aid}, info.IDs)
	})
}
