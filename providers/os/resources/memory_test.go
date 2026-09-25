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
	"go.mondoo.com/mql/utils/syncx"
)

// Output of windowsMemoryScript recorded on live hosts (EC2 t3.large, 8 GiB).
const (
	windowsMemoryOutput2022 = `{"TotalVisibleMemorySize":8283676,"AvailableBytes":6856503296,"CommittedBytes":1469177856,"CommitLimit":10495750144}` + "\r\n"
	windowsMemoryOutput2016 = `{"TotalVisibleMemorySize":8283660,"AvailableBytes":7139291136,"CommittedBytes":1175187456,"CommitLimit":10495733760}` + "\r\n"
)

var windowsPlatform = &inventory.Platform{
	Name:   "windows",
	Family: []string{"windows", "os"},
}

func TestParseWindowsMemory(t *testing.T) {
	tests := []struct {
		name                                  string
		output                                string
		total, available, committed, limitVal int64
	}{
		// TotalVisibleMemorySize is in KiB; the perf counters are already bytes.
		// 8283676 KiB * 1024 matches Win32_ComputerSystem.TotalPhysicalMemory
		// read on the same host.
		{"Windows Server 2022", windowsMemoryOutput2022, 8482484224, 6856503296, 1469177856, 10495750144},
		{"Windows Server 2016", windowsMemoryOutput2016, 8482467840, 7139291136, 1175187456, 10495733760},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := parseWindowsMemory([]byte(tc.output))
			require.NoError(t, err)
			require.NotNil(t, info.Total)
			assert.Equal(t, tc.total, *info.Total)
			require.NotNil(t, info.Available)
			assert.Equal(t, tc.available, *info.Available)
			require.NotNil(t, info.Committed)
			assert.Equal(t, tc.committed, *info.Committed)
			require.NotNil(t, info.CommitLimit)
			assert.Equal(t, tc.limitVal, *info.CommitLimit)
		})
	}
}

func TestParseWindowsMemoryNullCounter(t *testing.T) {
	info, err := parseWindowsMemory([]byte(`{"TotalVisibleMemorySize":null,"AvailableBytes":0,"CommittedBytes":1469177856}`))
	require.NoError(t, err)
	assert.Nil(t, info.Total, "a null KiB value must stay null, not become 0")
	assert.Nil(t, info.CommitLimit, "an absent counter must stay null")
	require.NotNil(t, info.Available, "a reported zero is a value")
	assert.Equal(t, int64(0), *info.Available)
}

func TestParseWindowsMemoryEmptyOutput(t *testing.T) {
	// A script rejected before PowerShell runs exits 0 with no output. That
	// must surface as an error, never as a snapshot of nulls.
	_, err := parseWindowsMemory([]byte("  \r\n"))
	assert.Error(t, err)
}

func TestParseWindowsMemoryMalformed(t *testing.T) {
	_, err := parseWindowsMemory([]byte(`Get-CimInstance : Invalid class`))
	assert.Error(t, err)
}

// noCommandConnection is a connection that cannot run commands, like a
// container image or a disk snapshot.
type noCommandConnection struct {
	*mock.Connection
}

func (c *noCommandConnection) Capabilities() shared.Capabilities {
	return shared.Capability_File
}

func newMemoryMock(t *testing.T, pf *inventory.Platform, stdout, stderr string, exit int) *mock.Connection {
	t.Helper()
	return newMemoryMockData(t, pf, &mock.TomlData{
		Commands: map[string]*mock.Command{
			powershell.Encode(windowsMemoryScript): {Stdout: stdout, Stderr: stderr, ExitStatus: exit},
		},
	})
}

func newMemoryMockData(t *testing.T, pf *inventory.Platform, data *mock.TomlData) *mock.Connection {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(data))
	require.NoError(t, err)
	return conn
}

func newMemoryResource(t *testing.T, conn shared.Connection) *mqlMemory {
	t.Helper()
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	raw, err := CreateResource(runtime, "memory", map[string]*llx.RawData{})
	require.NoError(t, err)
	return raw.(*mqlMemory)
}

func TestMemoryWindows(t *testing.T) {
	m := newMemoryResource(t, newMemoryMock(t, windowsPlatform, windowsMemoryOutput2022, "", 0))

	total := m.GetTotal()
	require.NoError(t, total.Error)
	assert.Equal(t, int64(8482484224), total.Data)

	available := m.GetAvailable()
	require.NoError(t, available.Error)
	assert.Equal(t, int64(6856503296), available.Data)

	committed := m.GetCommitted()
	require.NoError(t, committed.Error)
	assert.Equal(t, int64(1469177856), committed.Data)

	limit := m.GetCommitLimit()
	require.NoError(t, limit.Error)
	assert.Equal(t, int64(10495750144), limit.Data)
}

func TestMemoryWindowsNullCounterIsNull(t *testing.T) {
	m := newMemoryResource(t, newMemoryMock(t, windowsPlatform, `{"TotalVisibleMemorySize":8283676}`, "", 0))

	limit := m.GetCommitLimit()
	require.NoError(t, limit.Error)
	assert.True(t, limit.IsNull(), "a counter the target did not report reads null, not 0")

	total := m.GetTotal()
	require.NoError(t, total.Error)
	assert.False(t, total.IsNull())
}

func TestMemoryWindowsScriptFailure(t *testing.T) {
	m := newMemoryResource(t, newMemoryMock(t, windowsPlatform, "", "Get-CimInstance : Invalid class", 1))

	total := m.GetTotal()
	require.Error(t, total.Error)
	assert.Contains(t, total.Error.Error(), "Invalid class")
}

func TestMemoryWithoutRunningSystemIsNotApplicable(t *testing.T) {
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	for _, pf := range []*inventory.Platform{windowsPlatform, linux} {
		conn := &noCommandConnection{newMemoryMock(t, pf, windowsMemoryOutput2022, "", 0)}
		m := newMemoryResource(t, conn)

		total := m.GetTotal()
		require.Error(t, total.Error, pf.Name)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(total.Error), pf.Name)
	}
}

func TestMemoryUnsupportedPlatformIsUnclassified(t *testing.T) {
	// OpenBSD has memory; that the provider does not read it yet is our gap,
	// not a property of the target, so it must not claim not applicable.
	openbsd := &inventory.Platform{Name: "openbsd", Family: []string{"bsd", "unix", "os"}}
	m := newMemoryResource(t, newMemoryMock(t, openbsd, windowsMemoryOutput2022, "", 0))

	total := m.GetTotal()
	require.Error(t, total.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(total.Error))
	assert.Contains(t, total.Error.Error(), "openbsd")
}

// /proc/meminfo recorded in a live ubuntu:24.04 container (8 GiB VM), cut to
// the lines around the four values. free -b on the same host reported
// 8318976000 total, which is MemTotal * 1024.
const linuxMeminfo = `MemTotal:        8124000 kB
MemFree:         7233588 kB
MemAvailable:    7484544 kB
Buffers:           19800 kB
Cached:           374112 kB
SwapTotal:       1048572 kB
SwapFree:        1048572 kB
CommitLimit:     5110572 kB
Committed_AS:    1479604 kB
VmallocTotal:   135288315904 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
`

var linuxPlatform = &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}

func TestParseLinuxMeminfo(t *testing.T) {
	info, err := parseLinuxMeminfo([]byte(linuxMeminfo))
	require.NoError(t, err)
	require.NotNil(t, info.Total)
	assert.Equal(t, int64(8318976000), *info.Total)
	require.NotNil(t, info.Available)
	assert.Equal(t, int64(7664173056), *info.Available)
	require.NotNil(t, info.Committed)
	assert.Equal(t, int64(1515114496), *info.Committed)
	require.NotNil(t, info.CommitLimit)
	assert.Equal(t, int64(5233225728), *info.CommitLimit)
}

func TestParseLinuxMeminfoOldKernel(t *testing.T) {
	// Kernels before 3.14 have no MemAvailable; that is null, not 0.
	info, err := parseLinuxMeminfo([]byte("MemTotal:        1015472 kB\nMemFree:          612340 kB\nCommitLimit:      507736 kB\nCommitted_AS:     254012 kB\n"))
	require.NoError(t, err)
	assert.Nil(t, info.Available)
	require.NotNil(t, info.Total)
	assert.Equal(t, int64(1039843328), *info.Total)
}

func TestParseLinuxMeminfoMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"empty":        "",
		"no MemTotal":  "MemFree: 7233588 kB\n",
		"bad number":   "MemTotal: lots kB\n",
		"unknown unit": "MemTotal: 8124000 MB\n",
		"no value":     "MemTotal:\n",
	} {
		_, err := parseLinuxMeminfo([]byte(data))
		assert.Error(t, err, name)
	}
}

func TestMemoryLinux(t *testing.T) {
	m := newMemoryResource(t, newMemoryMockData(t, linuxPlatform, &mock.TomlData{
		Files: map[string]*mock.MockFileData{"/proc/meminfo": {Content: linuxMeminfo}},
	}))

	total := m.GetTotal()
	require.NoError(t, total.Error)
	assert.Equal(t, int64(8318976000), total.Data)

	limit := m.GetCommitLimit()
	require.NoError(t, limit.Error)
	assert.Equal(t, int64(5233225728), limit.Data)
}

func TestMemoryLinuxMissingMeminfo(t *testing.T) {
	m := newMemoryResource(t, newMemoryMockData(t, linuxPlatform, &mock.TomlData{}))

	total := m.GetTotal()
	require.Error(t, total.Error)
	assert.Contains(t, total.Error.Error(), "/proc/meminfo")
}

// Output of macosMemoryCommand recorded on macOS 27.0 (Apple silicon, 24 GiB,
// 16 KiB pages).
const macosMemoryOutput = `hw.memsize: 25769803776
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                     7015.
Pages active:                                 304073.
Pages inactive:                               300360.
Pages speculative:                              2540.
Pages throttled:                                   0.
Pages wired down:                             298060.
Pages purgeable:                                6682.
"Translation faults":                     5953400673.
Pages copy-on-write:                       286862084.
Pages zero filled:                        2617257205.
Pages reactivated:                         898866172.
Pages purged:                               66841660.
File-backed pages:                            216533.
Anonymous pages:                              390440.
Pages stored in compressor:                  1197922.
Pages occupied by compressor:                 606830.
Decompressions:                            829130344.
Compressions:                              935667987.
Pageins:                                   249599481.
Pageouts:                                     901338.
Swapins:                                    11348870.
Swapouts:                                   13517198.
`

var macosPlatform = &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}

func TestParseMacosMemory(t *testing.T) {
	info, err := parseMacosMemory([]byte(macosMemoryOutput))
	require.NoError(t, err)
	require.NotNil(t, info.Total)
	assert.Equal(t, int64(25769803776), *info.Total)
	// (7015 free + 216533 file-backed + 6682 purgeable) * 16384. Speculative
	// pages are already inside file-backed and must not be added again.
	require.NotNil(t, info.Available)
	assert.Equal(t, int64(3772088320), *info.Available)
	assert.Nil(t, info.Committed, "macOS keeps no commit accounting")
	assert.Nil(t, info.CommitLimit, "macOS keeps no commit accounting")
}

func TestParseMacosMemoryIntelPageSize(t *testing.T) {
	// Intel Macs use 4 KiB pages; the page size must come from the header.
	info, err := parseMacosMemory([]byte("hw.memsize: 17179869184\nMach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 100.\nPages purgeable: 10.\nFile-backed pages: 890.\n"))
	require.NoError(t, err)
	require.NotNil(t, info.Available)
	assert.Equal(t, int64(1000*4096), *info.Available)
}

func TestParseMacosMemoryPartial(t *testing.T) {
	info, err := parseMacosMemory([]byte("hw.memsize: 25769803776\n"))
	require.NoError(t, err)
	assert.Nil(t, info.Available, "no vm_stat output means available is unknown, not 0")

	_, err = parseMacosMemory([]byte("Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 7015.\n"))
	assert.Error(t, err, "no hw.memsize")

	_, err = parseMacosMemory([]byte("hw.memsize: 1\nMach Virtual Memory Statistics: (page size of many bytes)\n"))
	assert.Error(t, err, "bad page size")
}

func TestMemoryMacos(t *testing.T) {
	m := newMemoryResource(t, newMemoryMockData(t, macosPlatform, &mock.TomlData{
		Commands: map[string]*mock.Command{macosMemoryCommand: {Stdout: macosMemoryOutput}},
	}))

	available := m.GetAvailable()
	require.NoError(t, available.Error)
	assert.Equal(t, int64(3772088320), available.Data)

	committed := m.GetCommitted()
	require.NoError(t, committed.Error)
	assert.True(t, committed.IsNull())
}

// Output of freebsdMemoryCommand recorded on FreeBSD 14.5-RELEASE (EC2
// t3.micro, 1 GiB, 1 GiB swap). top on the same host reported 644M Inact and
// 43M Free, which is the 687.7 MiB of available.
const freebsdMemoryOutput = `hw.physmem: 987672576
hw.pagesize: 4096
vm.stats.vm.v_free_count: 11147
vm.stats.vm.v_inactive_count: 164911
vm.swap_reserved: 434823168
`

var freebsdPlatform = &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}}

func TestParseFreebsdMemory(t *testing.T) {
	info, err := parseFreebsdMemory([]byte(freebsdMemoryOutput))
	require.NoError(t, err)
	require.NotNil(t, info.Total)
	assert.Equal(t, int64(987672576), *info.Total)
	// (11147 free + 164911 inactive) * 4096
	require.NotNil(t, info.Available)
	assert.Equal(t, int64(721133568), *info.Available)
	require.NotNil(t, info.Committed)
	assert.Equal(t, int64(434823168), *info.Committed)
	assert.Nil(t, info.CommitLimit, "FreeBSD reports no commit limit")
}

func TestParseFreebsdMemoryPartial(t *testing.T) {
	// A name sysctl -i skipped leaves its value unknown, not 0.
	info, err := parseFreebsdMemory([]byte("hw.physmem: 987672576\nhw.pagesize: 4096\nvm.stats.vm.v_free_count: 11147\n"))
	require.NoError(t, err)
	assert.Nil(t, info.Available)
	assert.Nil(t, info.Committed)

	_, err = parseFreebsdMemory([]byte("hw.pagesize: 4096\n"))
	assert.Error(t, err, "no hw.physmem")

	_, err = parseFreebsdMemory([]byte("hw.physmem: lots\n"))
	assert.Error(t, err, "bad number")
}

func TestMemoryFreebsd(t *testing.T) {
	m := newMemoryResource(t, newMemoryMockData(t, freebsdPlatform, &mock.TomlData{
		Commands: map[string]*mock.Command{freebsdMemoryCommand: {Stdout: freebsdMemoryOutput}},
	}))

	available := m.GetAvailable()
	require.NoError(t, available.Error)
	assert.Equal(t, int64(721133568), available.Data)

	limit := m.GetCommitLimit()
	require.NoError(t, limit.Error)
	assert.True(t, limit.IsNull())
}

// Output of solarisMemoryCommand recorded on Oracle Solaris 11.4 SRU 86 (OCI
// VM.Standard.E5.Flex, 8 GB). kstat separates name and value with a tab.
// prtconf on the same host reported 8187 Megabytes.
const solarisMemoryOutput = "4096\n" +
	"unix:0:system_pages:physmem\t2095708\n" +
	"unix:0:system_pages:freemem\t1433903\n" +
	"total: 316132k bytes allocated + 200072k reserved = 516204k used, 7567260k available\n"

func TestParseSolarisMemory(t *testing.T) {
	info, err := parseSolarisMemory([]byte(solarisMemoryOutput))
	require.NoError(t, err)
	require.NotNil(t, info.Total)
	assert.Equal(t, int64(8584019968), *info.Total) // 2095708 pages * 4096
	require.NotNil(t, info.Available)
	assert.Equal(t, int64(5873266688), *info.Available) // 1433903 pages * 4096
	require.NotNil(t, info.Committed)
	assert.Equal(t, int64(528592896), *info.Committed) // 516204k used
	require.NotNil(t, info.CommitLimit)
	assert.Equal(t, int64(8277467136), *info.CommitLimit) // (516204k + 7567260k)
}

func TestParseSolarisMemoryMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"empty":         "",
		"no physmem":    "4096\nunix:0:system_pages:freemem\t1433903\n",
		"no pagesize":   "unix:0:system_pages:physmem\t2095708\n",
		"bad kstat":     "4096\nunix:0:system_pages:physmem\tmany\n",
		"bad swap":      "4096\nunix:0:system_pages:physmem\t2095708\ntotal: 316132k bytes allocated\n",
		"swap unit":     "4096\nunix:0:system_pages:physmem\t2095708\ntotal: 1k bytes allocated + 1k reserved = 516204M used, 7567260k available\n",
		"stray output":  "4096\n8192\nunix:0:system_pages:physmem\t2095708\n",
		"zero pagesize": "0\nunix:0:system_pages:physmem\t2095708\n",
	} {
		_, err := parseSolarisMemory([]byte(data))
		assert.Error(t, err, name)
	}
}

func TestMemorySolarisInLinuxFamily(t *testing.T) {
	// Solaris 11.4 ships an os-release and is detected into the linux family.
	// It must still read the Solaris counters, not /proc/meminfo, which it
	// does not have.
	solaris := &inventory.Platform{Name: "solaris", Family: []string{"linux", "unix", "os"}}
	m := newMemoryResource(t, newMemoryMockData(t, solaris, &mock.TomlData{
		Commands: map[string]*mock.Command{solarisMemoryCommand: {Stdout: solarisMemoryOutput}},
	}))

	total := m.GetTotal()
	require.NoError(t, total.Error)
	assert.Equal(t, int64(8584019968), total.Data)

	limit := m.GetCommitLimit()
	require.NoError(t, limit.Error)
	assert.Equal(t, int64(8277467136), limit.Data)
}
