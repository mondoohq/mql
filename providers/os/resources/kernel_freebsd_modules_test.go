// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// On FreeBSD, kernel.module knows modules by the names `kldstat -v` lists,
// including those compiled into the kernel, and reads the loader's
// module_blacklist.
func TestKernelModulesFreeBSD(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/kernel_freebsd145.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath(fixturePath))
	require.NoError(t, err)
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "kernel", nil)
	require.NoError(t, err)
	modules := raw.(*mqlKernel).GetModules()
	require.NoError(t, modules.Error)
	var names []string
	for _, m := range modules.Data {
		names = append(names, m.(*mqlKernelModule).Name.Data)
	}
	assert.Equal(t, []string{
		"cubic", "pseudofs", "tmpfs", "msdosfs", "devfs", "g_part_gpt", "pci/xl",
		"pci/ena", "pci/intsmb", "intsmb/smbus", "ipfw", "zfsctrl", "zfs",
	}, names)

	module := func(name string) *mqlKernelModule {
		raw, err := NewResource(runtime, "kernel.module", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		require.NoError(t, err)
		return raw.(*mqlKernelModule)
	}

	type state struct {
		loaded, builtIn, onDisk, blacklisted, installBypass, disabled bool
	}
	get := func(m *mqlKernelModule) state {
		builtIn := m.GetBuiltIn()
		require.NoError(t, builtIn.Error)
		onDisk := m.GetOnDisk()
		require.NoError(t, onDisk.Error)
		blacklisted := m.GetBlacklisted()
		require.NoError(t, blacklisted.Error)
		installBypass := m.GetInstallBypass()
		require.NoError(t, installBypass.Error)
		disabled := m.GetDisabled()
		require.NoError(t, disabled.Error)
		return state{m.Loaded.Data, builtIn.Data, onDisk.Data, blacklisted.Data, installBypass.Data, disabled.Data}
	}

	// compiled into GENERIC: loaded, and the .ko on disk is never needed
	assert.Equal(t, state{loaded: true, builtIn: true, onDisk: true}, get(module("msdosfs")))
	// loaded from zfs.ko
	zfs := module("zfs")
	assert.Equal(t, state{loaded: true, onDisk: true}, get(zfs))
	assert.Equal(t, "5e9340", zfs.Size.Data)
	// not loaded, but kldload can load it
	assert.Equal(t, state{onDisk: true}, get(module("ext2fs")))
	// blacklisted in /boot/loader.conf: the loader does not load it at boot
	assert.Equal(t, state{onDisk: true, blacklisted: true, disabled: true}, get(module("sctp")))
	// blacklisted in /boot/loader.conf.d, not installed
	assert.Equal(t, state{blacklisted: true, disabled: true}, get(module("smbfs")))
	// the defaults' blacklist, extended with ${module_blacklist}
	assert.Equal(t, state{blacklisted: true, disabled: true}, get(module("nvidia-modeset")))
	assert.Equal(t, state{blacklisted: true, disabled: true}, get(module("drm")))
	// a driver attachment has no file of its own
	assert.Equal(t, state{loaded: true}, get(module("pci/ena")))
	// the name kernel.modules used for a loaded file still finds it
	assert.Equal(t, state{loaded: true, onDisk: true}, get(module("zfs.ko")))
	// a loaded file that registers no module is no module (`kldstat -m` does
	// not find it either)
	assert.False(t, module("smbus.ko").Loaded.Data)
}
