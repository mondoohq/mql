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

// fedora:44 after `dnf5 install -y kernel-core`, run on Docker Desktop: the
// image's kernel package is newer than the host's linuxkit kernel, which says
// nothing about the container.
// rpmQueryKernel is the query reboot.RpmNewestKernel runs.
const rpmQueryKernel = "rpm -q --whatprovides kernel --queryformat '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}__%{VENDOR}__%{SUMMARY}__%{LICENSE}__%{INSTALLTIME}\n'"

func fedoraKernelCoreFiles(withDockerenv bool) *mock.TomlData {
	data := &mock.TomlData{
		Commands: map[string]*mock.Command{
			"LC_ALL=C needs-restarting -r": {Stdout: "", ExitStatus: 127},
			rpmQueryKernel: {
				Stdout: "kernel-core 0:7.2.8-200.fc44 aarch64__Fedora Project__The Linux kernel__GPL-2.0-only__1791014400\n",
			},
			"uname -r": {Stdout: "7.0.14-linuxkit\n"},
		},
		Files: map[string]*mock.MockFileData{},
	}
	if withDockerenv {
		data.Files["/.dockerenv"] = &mock.MockFileData{Path: "/.dockerenv"}
	}
	return data
}

func rebootPendingFor(t *testing.T, data *mock.TomlData) bool {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
		Name:    "fedora",
		Version: "44",
		Family:  []string{"redhat", "linux", "unix", "os"},
		Kind:    inventory.AssetKindBaremetal,
	}}, mock.WithData(data))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := CreateResource(rt, "os.base", nil)
	require.NoError(t, err)
	pending := res.(*mqlOsBase).GetRebootpending()
	require.NoError(t, pending.Error)
	return pending.Data
}

func TestRebootPendingInsideContainer(t *testing.T) {
	// the host-side comparison still holds outside a container
	assert.True(t, rebootPendingFor(t, fedoraKernelCoreFiles(false)))
	// a local scan inside a container never has a reboot pending
	assert.False(t, rebootPendingFor(t, fedoraKernelCoreFiles(true)))
}

// os.rebootpending is the deprecated alias of os.base.rebootpending, with its
// own implementation.
func TestOsRebootPendingInsideContainer(t *testing.T) {
	for _, withDockerenv := range []bool{false, true} {
		conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
			Name:   "fedora",
			Family: []string{"redhat", "linux", "unix", "os"},
		}}, mock.WithData(fedoraKernelCoreFiles(withDockerenv)))
		require.NoError(t, err)
		rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
		res, err := CreateResource(rt, "os", nil)
		require.NoError(t, err)
		pending := res.(*mqlOs).GetRebootpending()
		require.NoError(t, pending.Error)
		assert.Equal(t, !withDockerenv, pending.Data)
	}
}
