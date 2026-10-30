// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestKldstatVerboseParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd145.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("kldstat -v")
	require.NoError(t, err)

	entries := ParseKldstatVerbose(f.Stdout)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	assert.Equal(t, []string{"cubic", "msdosfs", "devfs", "pci/ena", "pci/intsmb", "intsmb/smbus", "ipfw"}, names)

	// compiled into the kernel: no size of its own
	assert.Equal(t, &KernelModule{Name: "msdosfs", File: "kernel", BuiltIn: true}, findModule(entries, "msdosfs"))
	assert.Equal(t, &KernelModule{Name: "ipfw", Size: "28450", UsedBy: "1", File: "ipfw.ko"}, findModule(entries, "ipfw"))
}

// kldstat without a module list (plain output) is read one entry per file.
func TestKldstatVerboseParser_NoModuleLists(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd14.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("kldstat")
	require.NoError(t, err)

	entries := ParseKldstatVerbose(f.Stdout)
	assert.Equal(t, 6, len(entries))
	assert.Equal(t, "zfs.ko", entries[2].Name)
}

func TestParseFreeBSDModulePath(t *testing.T) {
	assert.Equal(t, []string{"/boot/kernel", "/boot/modules", "/boot/dtb", "/boot/dtb/overlays"},
		ParseFreeBSDModulePath("/boot/kernel;/boot/modules;/boot/dtb;/boot/dtb/overlays"))
	assert.Equal(t, []string{"/boot/kernel", "/boot/modules"}, ParseFreeBSDModulePath(""))
	assert.Equal(t, []string{"/boot/kernel"}, ParseFreeBSDModulePath(" /boot/kernel ; ;"))
}

func TestFreeBSDModuleFile(t *testing.T) {
	cases := map[string]string{
		"msdosfs": "msdosfs.ko",
		"zfs.ko":  "zfs.ko",
		// a driver attachment has no file of its own
		"pci/ena": "",
		"":        "",
	}
	for name, want := range cases {
		assert.Equal(t, want, FreeBSDModuleFile(name), name)
	}
}
