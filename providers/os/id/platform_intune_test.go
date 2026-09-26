// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	win "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/id/ids"
)

func TestGatherPlatformInfoIntuneDevice(t *testing.T) {
	const (
		tenant = "11223344-5566-7788-99aa-bbccddeeff00"
		device = "0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9"
	)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	windows := func(labels map[string]string) *inventory.Platform {
		return &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}, Labels: labels}
	}

	t.Run("detected identity yields a tenant-scoped id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, windows(map[string]string{
			win.LabelIntuneDeviceID: device,
			win.LabelEntraTenantID:  tenant,
		}), ids.IdDetector_IntuneDevice)
		require.NoError(t, err)
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/intune/tenants/" + tenant + "/devices/" + device}, info.IDs)
	})

	t.Run("a device id without a tenant yields no id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, &inventory.Platform{Name: "ubuntu", Family: []string{"linux", "os"}, Labels: map[string]string{
			win.LabelIntuneDeviceID: device,
		}}, ids.IdDetector_IntuneDevice)
		require.NoError(t, err)
		assert.Empty(t, info.IDs)
	})

	t.Run("a non-windows platform without labels yields no id", func(t *testing.T) {
		info, err := gatherPlatformInfo(conn, &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, ids.IdDetector_IntuneDevice)
		require.NoError(t, err)
		assert.Empty(t, info.IDs)
	})
}
