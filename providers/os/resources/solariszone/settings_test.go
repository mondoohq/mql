// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package solariszone

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func settingsOf(t *testing.T, fixture string) *Settings {
	t.Helper()
	cfg, err := ParseInfo(readFixture(t, fixture))
	require.NoError(t, err)
	s, err := cfg.Settings()
	require.NoError(t, err)
	return s
}

func TestSettingsExclusiveZone(t *testing.T) {
	s := settingsOf(t, "zonecfg-info-a-mqlzexcl.txt")

	require.NotNil(t, s.Autoboot)
	assert.True(t, *s.Autoboot)
	require.NotNil(t, s.Bootargs)
	assert.Equal(t, "-m verbose", *s.Bootargs)
	assert.Equal(t, []string{"default", "proc_priocntl", "dtrace_user"}, s.Limitpriv)
	require.NotNil(t, s.FileMacProfile)
	assert.Equal(t, "fixed-configuration", *s.FileMacProfile)
	assert.Equal(t, []string{"hsfs", "pcfs"}, s.FsAllowed)
	assert.Equal(t, "FSS", *s.SchedulingClass)
	assert.Equal(t, "1a2b3c4d", *s.Hostid)

	assert.Equal(t, int64(1<<30), *s.MemoryCapBytes)
	assert.Equal(t, int64(2<<30), *s.SwapCapBytes)
	assert.Equal(t, int64(512<<20), *s.LockedMemoryCapBytes)
	assert.Equal(t, 1.5, *s.CPUCap)
	assert.Equal(t, "", s.DedicatedCPUs)
	assert.Equal(t, int64(2000), *s.MaxLwps)
	assert.Equal(t, int64(1000), *s.MaxProcesses)

	require.Len(t, s.Networks, 2)
	n0 := s.Networks[0]
	assert.Equal(t, "anet", n0.Type)
	assert.Equal(t, "net0", n0.Name)
	assert.Equal(t, "auto", n0.LowerLink)
	assert.Equal(t, []string{"10.0.5.20/24"}, n0.AllowedAddresses)
	assert.Equal(t, []string{"10.0.5.1"}, n0.Defrouter)
	assert.Equal(t, []string{"mac-nospoof", "ip-nospoof"}, n0.LinkProtection)
	assert.Equal(t, "auto", n0.MacAddress)
	assert.Nil(t, n0.VlanID)
	assert.Equal(t, "auto", n0.Properties["ring-group"])
	_, hasEmpty := n0.Properties["mtu"]
	assert.False(t, hasEmpty, "properties without a value are left out")

	n1 := s.Networks[1]
	assert.Equal(t, "net1", n1.Name)
	require.NotNil(t, n1.VlanID)
	assert.Equal(t, int64(42), *n1.VlanID)
	// the default link protection, which `info` without -a leaves out
	assert.Equal(t, []string{"mac-nospoof"}, n1.LinkProtection)
	assert.Empty(t, n1.AllowedAddresses)

	assert.Equal(t, []Filesystem{{
		Dir:     "/data",
		Special: "/export/mqlshare",
		Type:    "lofs",
		Options: []string{"ro", "nodevices"},
	}}, s.Filesystems)

	assert.Equal(t, []Device{{
		Match:          "/dev/zvol/rdsk/rpool/swap",
		AllowPartition: false,
		AllowRawIO:     true,
	}}, s.Devices)

	assert.Equal(t, []string{"rpool/mqlzdata"}, s.Datasets)
}

func TestSettingsSharedZone(t *testing.T) {
	s := settingsOf(t, "zonecfg-info-a-mqlzshared.txt")

	require.NotNil(t, s.Autoboot)
	assert.False(t, *s.Autoboot)
	assert.Equal(t, []string{}, s.Limitpriv, "unset limitpriv is empty, not null")
	assert.Equal(t, "", *s.FileMacProfile)
	assert.Nil(t, s.MemoryCapBytes)
	assert.Nil(t, s.CPUCap)
	assert.Nil(t, s.MaxLwps)

	// two net resources on the same link, told apart by address
	require.Len(t, s.Networks, 2)
	for i, addr := range []string{"10.0.6.30/24", "10.0.6.31/24"} {
		n := s.Networks[i]
		assert.Equal(t, "net", n.Type)
		assert.Equal(t, "net0", n.Name)
		assert.Equal(t, addr, n.Address)
		assert.Empty(t, n.LinkProtection)
	}
	assert.Empty(t, s.Filesystems)
	assert.Empty(t, s.Devices)
	assert.Empty(t, s.Datasets)
}

func TestSettingsDedicatedCPUZone(t *testing.T) {
	s := settingsOf(t, "zonecfg-info-a-mqlzded.txt")

	assert.Equal(t, "1-2", s.DedicatedCPUs)
	assert.Nil(t, s.CPUCap)
	// set with `add rctl` rather than `set max-lwps`
	require.NotNil(t, s.MaxLwps)
	assert.Equal(t, int64(3000), *s.MaxLwps)
	assert.Nil(t, s.MaxProcesses)
	require.Len(t, s.Networks, 1)
	assert.Equal(t, []string{"mac-nospoof"}, s.Networks[0].LinkProtection)
}

func TestSettingsGlobalZone(t *testing.T) {
	s := settingsOf(t, "zonecfg-info-a-global.txt")

	assert.Nil(t, s.Autoboot)
	assert.Nil(t, s.Bootargs)
	assert.Nil(t, s.Limitpriv)
	require.NotNil(t, s.FileMacProfile)
	assert.Equal(t, "", *s.FileMacProfile)
	assert.Equal(t, []string{}, s.FsAllowed)
	assert.Nil(t, s.MaxLwps)
	assert.Empty(t, s.Networks)
}

func TestSettingsMalformed(t *testing.T) {
	for _, in := range []string{
		"autoboot: maybe\n",
		"[max-lwps: lots]\n",
		"capped-memory:\n\tphysical: big\n",
		"capped-cpu:\n\t[ncpus: x]\n",
		"anet:\n\tvlan-id: abc\n",
		"device:\n\tallow-raw-io: sometimes\n",
	} {
		cfg, err := ParseInfo(in)
		require.NoError(t, err, in)
		_, err = cfg.Settings()
		assert.Error(t, err, in)
	}
}
