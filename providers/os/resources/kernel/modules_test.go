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

func TestLsmodParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("/sbin/lsmod")
	require.NoError(t, err)

	entries := ParseLsmod(f.Stdout)
	assert.Equal(t, 40, len(entries))

	expected := &KernelModule{
		Name:   "cryptd",
		Size:   "24576",
		UsedBy: "3",
	}
	found := findModule(entries, "cryptd")
	assert.Equal(t, expected, found)
}

func TestLinuxProcModulesParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.FileSystem().Open("/proc/modules")
	require.NoError(t, err)
	defer f.Close()

	entries := ParseLinuxProcModules(f)
	assert.Equal(t, 40, len(entries))

	expected := &KernelModule{
		Name:   "cryptd",
		Size:   "24576",
		UsedBy: "3",
	}
	found := findModule(entries, "cryptd")
	assert.Equal(t, expected, found)
}

func TestKldstatParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd14.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("kldstat")
	require.NoError(t, err)

	entries := ParseKldstat(f.Stdout)
	assert.Equal(t, 6, len(entries))

	expected := &KernelModule{
		Name:   "smbus.ko",
		Size:   "2178",
		UsedBy: "1",
	}
	found := findModule(entries, "smbus.ko")
	assert.Equal(t, expected, found)
}

func TestKextstatParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("kextstat")
	require.NoError(t, err)

	entries := ParseKextstat(f.Stdout)
	assert.Equal(t, 33, len(entries))

	expected := &KernelModule{
		Name:   "com.apple.kpi.mach",
		Size:   "0x62e0",
		UsedBy: "144",
	}
	found := findModule(entries, "com.apple.kpi.mach")
	assert.Equal(t, expected, found)
}

func findModule(modules []*KernelModule, name string) *KernelModule {
	for i := range modules {
		if modules[i].Name == name {
			return modules[i]
		}
	}
	return nil
}
