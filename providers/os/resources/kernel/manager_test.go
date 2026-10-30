// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
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

// procSysDump is procSysDumpCommand's output on a container that is not
// root: values, a value that spans lines, and a parameter it was denied.
const procSysDump = "V./kernel/randomize_va_space\x002\x00" +
	"V./net/ipv4/ip_forward\x000\x00" +
	"V./dev/cdrom/info\x00CD-ROM information, Id: cdrom.c 3.20 2003/12/17\n\ndrive name:\x00" +
	"V./fs/dentry-state\x00674835\t584714\t45\t0\t262633\t0\x00" +
	"D./kernel/usermodehelper/bset\x00\x00"

func TestParseProcSysDump(t *testing.T) {
	params, denied, err := parseProcSysDump(strings.NewReader(procSysDump))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"kernel.randomize_va_space": "2",
		"net.ipv4.ip_forward":       "0",
		"dev.cdrom.info":            "CD-ROM information, Id: cdrom.c 3.20 2003/12/17\n\ndrive name:",
		"fs.dentry-state":           "674835\t584714\t45\t0\t262633\t0",
	}, params)
	assert.Equal(t, []string{"kernel.usermodehelper.bset"}, denied)

	_, _, err = parseProcSysDump(strings.NewReader("sh: find: not found\n"))
	assert.Error(t, err)
	_, _, err = parseProcSysDump(strings.NewReader(procSysDump[:len(procSysDump)-5]))
	assert.Error(t, err, "cut short")
}

func newSysctlMock(t *testing.T, commands map[string]*mock.Command, files map[string]*mock.MockFileData) *mock.Connection {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "almalinux", Version: "9", Family: []string{"redhat", "linux"}},
	}, mock.WithData(&mock.TomlData{Commands: commands, Files: files}))
	require.NoError(t, err)
	return conn
}

// A minimal image has no sysctl. The parameters are read with one command
// instead of a read per file, ~1900 of them, which over the docker-container
// transport took a minute and a half.
func TestParametersWithoutSysctl(t *testing.T) {
	conn := newSysctlMock(t, map[string]*mock.Command{
		"/sbin/sysctl -a":  {ExitStatus: 127, Stderr: "sh: /sbin/sysctl: not found\n"},
		procSysDumpCommand: {Stdout: procSysDump},
	}, nil)
	params, denied, err := (&LinuxKernelManager{conn: conn}).ParametersWithDenied()
	require.NoError(t, err)
	assert.Equal(t, "2", params["kernel.randomize_va_space"])
	assert.Len(t, params, 4)
	assert.Equal(t, []string{"kernel.usermodehelper.bset"}, denied)
}

// Without a shell or find, the files are read one by one as before.
func TestParametersFallBackToTheWalk(t *testing.T) {
	conn := &procSysConn{
		Connection: newSysctlMock(t, map[string]*mock.Command{
			"/sbin/sysctl -a":  {ExitStatus: 127},
			procSysDumpCommand: {ExitStatus: 127},
		}, nil),
		fs: procSysFs(t),
	}
	params, _, err := (&LinuxKernelManager{conn: conn}).ParametersWithDenied()
	require.NoError(t, err)
	assert.Equal(t, "2", params["kernel.randomize_va_space"])
	assert.Len(t, params, 6)
}

// procSysConn is a mock connection whose file system holds a /proc/sys.
type procSysConn struct {
	*mock.Connection
	fs afero.Fs
}

func (c *procSysConn) FileSystem() afero.Fs { return c.fs }
