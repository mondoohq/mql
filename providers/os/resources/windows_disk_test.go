// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/utils/syncx"
)

func windowsDiskRuntime(t *testing.T, family string, stdout string, exit int) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(555101, &inventory.Asset{
		Platform: &inventory.Platform{Name: family, Family: []string{family}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			powershell.Encode(windows.PSGetDisks): {Stdout: stdout, Stderr: "Get-CimInstance : Invalid namespace", ExitStatus: exit},
		},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestWindowsDisksBuildsResources(t *testing.T) {
	// Two disks sharing a UniqueId, which cloned virtual disks do. Both must
	// survive as separate resources rather than the second reading as the first.
	stdout := `[
  {"Number":1,"FriendlyName":"Data","UniqueId":"SAME","Size":10737418240,"BusType":17,"PartitionStyle":0,"IsBoot":false,"OperationalStatus":[53264],"HealthStatus":0},
  {"Number":0,"FriendlyName":"Boot","SerialNumber":"  S1  ","UniqueId":"SAME","Size":64424509440,"BusType":15,"PartitionStyle":2,"IsBoot":true,"IsSystem":true,"IsOffline":false,"IsReadOnly":false,"OperationalStatus":[2],"HealthStatus":1}
]`
	runtime := windowsDiskRuntime(t, "windows", stdout, 0)

	list, err := (&mqlWindows{MqlRuntime: runtime}).disks()
	require.NoError(t, err)
	require.Len(t, list, 2)

	boot := list[0].(*mqlWindowsDisk)
	data := list[1].(*mqlWindowsDisk)
	assert.NotEqual(t, boot.__id, data.__id)

	assert.Equal(t, int64(0), boot.Number.Data)
	assert.Equal(t, "Boot", boot.FriendlyName.Data)
	assert.Equal(t, "S1", boot.SerialNumber.Data)
	assert.Equal(t, int64(64424509440), boot.Size.Data)
	assert.Equal(t, "File Backed Virtual", boot.BusType.Data)
	assert.Equal(t, "GPT", boot.PartitionStyle.Data)
	assert.True(t, boot.IsBoot.Data)
	assert.True(t, boot.IsSystem.Data)
	assert.Equal(t, []any{"OK"}, boot.OperationalStatus.Data)
	assert.Equal(t, "Warning", boot.HealthStatus.Data)

	assert.Equal(t, "Data", data.FriendlyName.Data)
	assert.Equal(t, "RAW", data.PartitionStyle.Data)
	assert.False(t, data.IsBoot.Data)
	assert.Equal(t, []any{"Online"}, data.OperationalStatus.Data)
	// Not reported, so null rather than false.
	assert.True(t, data.IsSystem.State&plugin.StateIsNull != 0)
	assert.True(t, data.SerialNumber.State&plugin.StateIsNull != 0)
}

func TestWindowsDiskResourceIDs(t *testing.T) {
	one, zero := int64(1), int64(0)
	uid := "SAME"
	assert.NotEqual(t,
		diskResourceID(0, windows.Disk{Number: &zero, UniqueId: &uid}),
		diskResourceID(1, windows.Disk{Number: &one, UniqueId: &uid}))
	// Without numbers, position keeps them apart.
	assert.NotEqual(t,
		diskResourceID(0, windows.Disk{UniqueId: &uid}),
		diskResourceID(1, windows.Disk{UniqueId: &uid}))
}

func TestWindowsDisksNonZeroExitIsError(t *testing.T) {
	runtime := windowsDiskRuntime(t, "windows", "[]", 1)
	_, err := (&mqlWindows{MqlRuntime: runtime}).disks()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid namespace")
}

func TestWindowsDisksErrorKinds(t *testing.T) {
	t.Run("no output is unclassified", func(t *testing.T) {
		_, err := (&mqlWindows{MqlRuntime: windowsDiskRuntime(t, "windows", "", 0)}).disks()
		require.ErrorIs(t, err, windows.ErrNoDiskOutput)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	})
	t.Run("unparseable output is malformed data", func(t *testing.T) {
		_, err := (&mqlWindows{MqlRuntime: windowsDiskRuntime(t, "windows", "not json", 0)}).disks()
		assert.ErrorIs(t, err, llx.ErrMalformedData)
	})
	t.Run("non-windows platform is not applicable", func(t *testing.T) {
		_, err := (&mqlWindows{MqlRuntime: windowsDiskRuntime(t, "linux", "[]", 0)}).disks()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
	t.Run("connection that cannot run commands is not applicable", func(t *testing.T) {
		runtime := windowsDiskRuntime(t, "windows", "[]", 0)
		runtime.Connection = noRunCommandConn{runtime.Connection.(*mock.Connection)}
		_, err := (&mqlWindows{MqlRuntime: runtime}).disks()
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
	})
}

// noRunCommandConn is a connection with file access only, the shape of a
// mounted disk image or a container filesystem.
type noRunCommandConn struct{ *mock.Connection }

func (noRunCommandConn) Capabilities() shared.Capabilities { return shared.Capability_File }
