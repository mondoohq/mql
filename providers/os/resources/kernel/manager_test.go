// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "debian",
			Version: "8.0",
			Family:  []string{"debian", "linux"},
		},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.Modules()
	require.NoError(t, err)

	assert.Equal(t, 40, len(mounts))
}

func TestManagerCentos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "centos",
			Version: "6.10",
			Family:  []string{"linux", "redhat"},
		},
	}, mock.WithPath("./testdata/centos7.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "3.10.0-1160.105.1.el7.x86_64", info.Version)
	assert.Equal(t, map[string]string{"biosdevname": "0", "crashkernel": "auto", "elevator": "noop", "net.ifnames": "0", "no_timer_check": "", "quiet": "", "rd.lvm.lv": "centos_centos7/swap", "rhgb": "", "ro": ""}, info.Arguments)
	assert.Equal(t, "/vmlinuz-3.10.0-1160.105.1.el7.x86_64", info.Path)
	assert.Equal(t, "/dev/mapper/centos_centos7-root", info.Device)

	mods, err := mm.Modules()
	require.NoError(t, err)

	assert.Equal(t, 16, len(mods))
}

func TestManagerAmazonLinux1(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "amazonlinux",
			Version: "2018.03",
			Family:  []string{"linux"},
		},
	}, mock.WithPath("./testdata/amznlinux1.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "4.14.193-113.317.amzn1.x86_64", info.Version)
	assert.Equal(t, map[string]string{"console": "ttyS0", "nvme_core.io_timeout": "4294967295", "selinux": "0"}, info.Arguments)
	assert.Equal(t, "", info.Path)
	assert.Equal(t, "LABEL=/", info.Device)

	mods, err := mm.Modules()
	require.NoError(t, err)

	assert.Equal(t, 21, len(mods))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "macos",
			Family: []string{"unix", "darwin"},
		},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "19.4.0", info.Version)
	assert.Equal(t, map[string]string(nil), info.Arguments)
	assert.Equal(t, "", info.Path)
	assert.Equal(t, "", info.Device)

	mounts, err := mm.Modules()
	require.NoError(t, err)

	assert.Equal(t, 33, len(mounts))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/freebsd14.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)
	modules, err := mm.Modules()
	require.NoError(t, err)

	assert.Equal(t, 6, len(modules))

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "FreeBSD 14.3-RELEASE releng/14.3-n271432-8c9ce319fef7 GENERIC", info.Version)
}

func TestManagerOpenBSD(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "openbsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath("./testdata/openbsd77.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)
	modules, err := mm.Modules()
	require.NoError(t, err)
	assert.Equal(t, 0, len(modules))

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "GENERIC.MP#625", info.Version)
}

func TestManagerAIX(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "aix",
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/aix.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mock)
	require.NoError(t, err)
	modules, err := mm.Modules()
	require.NoError(t, err)
	require.Equal(t, []*KernelModule{
		{Name: "bpf", Size: "d000"},
		{Name: "autofs.ext", Size: "36000"},
		{Name: "ahafs.ext", Size: "1d000"},
	}, modules)

	info, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, "7300-03-00-2446", info.Version)
}

// Container-Optimized OS ships lsmod as /bin/lsmod and has an empty /sbin, so
// the hard-coded /sbin/lsmod exits 127 with no output. Nothing checked the exit
// status, so the empty parse was reported as "no modules loaded" and a policy
// asserting a module is absent passed without the list ever being read.
func TestManagerCOSFallsBackToProcModules(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "cos",
			Version: "121",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/cos.toml"))
	require.NoError(t, err)

	mm, err := ResolveManager(mockConn)
	require.NoError(t, err)

	modules, err := mm.Modules()
	require.NoError(t, err)
	require.Len(t, modules, 13, "modules must come from /proc/modules when lsmod is absent")

	assert.Equal(t, "nft_chain_nat", modules[0].Name)
	assert.Equal(t, "12288", modules[0].Size)
	assert.Equal(t, "3", modules[0].UsedBy)
	assert.Equal(t, "fuse", modules[12].Name)
}
