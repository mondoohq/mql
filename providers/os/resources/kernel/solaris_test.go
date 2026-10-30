// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Captured from `modinfo` on Oracle Solaris 11.4.86 (OCI).
func TestParseSolarisModinfo(t *testing.T) {
	f, err := os.Open("./testdata/solaris114_modinfo.txt")
	require.NoError(t, err)
	defer f.Close()

	mods, err := ParseSolarisModinfo(f)
	require.NoError(t, err)

	// 204 rows, 177 distinct names: zfs, autofs and others list one row per
	// linkage.
	require.Len(t, mods, 177)

	byName := map[string]*KernelModule{}
	for _, m := range mods {
		_, dup := byName[m.Name]
		assert.False(t, dup, "module %s listed twice", m.Name)
		byName[m.Name] = m
	}

	require.Contains(t, byName, "unix")
	assert.Equal(t, "4163367", byName["unix"].Size) // 0x3f8727

	require.Contains(t, byName, "dtrace")
	assert.Equal(t, "154392", byName["dtrace"].Size) // 0x25b18

	require.Contains(t, byName, "zfs")
	assert.NotContains(t, byName, "(ZFS")
}

// The system properties at the top of `prtconf -v` on the same host.
func TestParseSolarisPrtconfProperties(t *testing.T) {
	f, err := os.Open("./testdata/solaris114_prtconf_v.txt")
	require.NoError(t, err)
	defer f.Close()

	props, err := ParseSolarisPrtconfProperties(f)
	require.NoError(t, err)

	assert.Equal(t, "/platform/i86pc/kernel/amd64/unix", props["whoami"])
	assert.Equal(t, "rpool/39", props["zfs-bootfs"])
	assert.Equal(t, "/pseudo/lofi@1:b", props["bootpath"])
	// an empty boot-args is type=unknown, not a string
	assert.NotContains(t, props, "boot-args")
	// int properties are not strings either
	assert.NotContains(t, props, "PAGESIZE")

	info := solarisKernelInfo("11.4.86.201.2", props)
	assert.Equal(t, "11.4.86.201.2", info.Version)
	assert.Equal(t, "/platform/i86pc/kernel/amd64/unix", info.Path)
	assert.Equal(t, "rpool/39", info.Device)
	assert.Empty(t, info.Arguments)
}

func TestSolarisKernelInfoBootArgs(t *testing.T) {
	in := `    System properties:
        name='boot-args' type=string items=1
            value='-v -B console=ttya'
        name='bootpath' type=string items=1
            value='/pci@0,0/pci-ide@1,1/ide@0/cmdk@0,0:a'
`
	props, err := ParseSolarisPrtconfProperties(strings.NewReader(in))
	require.NoError(t, err)

	info := solarisKernelInfo("11.3", props)
	// a UFS root has no ZFS boot dataset, so the boot device stands in
	assert.Equal(t, "/pci@0,0/pci-ide@1,1/ide@0/cmdk@0,0:a", info.Device)
	assert.Equal(t, map[string]string{"-v": "", "-B": "", "console": "ttya"}, info.Arguments)
}
