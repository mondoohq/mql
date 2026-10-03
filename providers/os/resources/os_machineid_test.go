// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func machineIDRuntime(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
		Name:   "amazonlinux",
		Family: []string{"linux", "unix", "os"},
	}}, mock.WithData(&mock.TomlData{Files: mockFiles}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// The amazonlinux, ALT and other container images ship neither
// /etc/machine-id nor /var/lib/dbus/machine-id, and os.machineid errored with
// "open /etc/machine-id: no such file or directory".
func TestMachineIDAbsent(t *testing.T) {
	rt := machineIDRuntime(t, nil)
	res, err := CreateResource(rt, "os.base", nil)
	require.NoError(t, err)
	v := res.(*mqlOsBase).GetMachineid()
	require.NoError(t, v.Error)
	assert.True(t, v.IsNull())

	osRes, err := CreateResource(rt, "os", nil)
	require.NoError(t, err)
	ov := osRes.(*mqlOs).GetMachineid()
	require.NoError(t, ov.Error)
	assert.True(t, ov.IsNull(), "the os.machineid alias is null too")
}

func TestMachineIDPresent(t *testing.T) {
	rt := machineIDRuntime(t, map[string]string{"/etc/machine-id": "3F2C9A1B7E4D4C0A9B8E6D5C4B3A2910\n"})
	res, err := CreateResource(rt, "os.base", nil)
	require.NoError(t, err)
	v := res.(*mqlOsBase).GetMachineid()
	require.NoError(t, v.Error)
	assert.Equal(t, "3f2c9a1b7e4d4c0a9b8e6d5c4b3a2910", v.Data)
}
