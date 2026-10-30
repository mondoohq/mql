// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package procfs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseProcCpuX64(t *testing.T) {
	trans, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/cpu-info-x64.toml"))
	require.NoError(t, err)

	f, err := trans.FileSystem().Open("/proc/cpuinfo")
	require.NoError(t, err)
	defer f.Close()

	cpuInfo, err := ParseCpuInfo(f)
	require.NoError(t, err)

	assert.NotNil(t, cpuInfo, "cpuInfo is not nil")

	proc1 := Processor{
		Id:              0,
		VendorID:        "GenuineIntel",
		CPUFamily:       "6",
		Model:           "94",
		ModelName:       "Intel(R) Core(TM) i7-6700K CPU @ 4.00GHz",
		Stepping:        "3",
		Microcode:       "",
		CPUMHz:          4000,
		CacheSize:       8192,
		PhysicalID:      0,
		Siblings:        0x1,
		CoreID:          0x0,
		CPUCores:        0x1,
		ApicID:          "0",
		InitialApicID:   "0",
		FPU:             "yes",
		FPUException:    "yes",
		CpuIDLevel:      0x16,
		WP:              "yes",
		Flags:           []string{"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "pbe", "syscall", "nx", "pdpe1gb", "lm", "constant_tsc", "rep_good", "nopl", "xtopology", "nonstop_tsc", "cpuid", "pni", "pclmulqdq", "dtes64", "ds_cpl", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pcid", "sse4_1", "sse4_2", "movbe", "popcnt", "aes", "xsave", "avx", "f16c", "rdrand", "hypervisor", "lahf_lm", "abm", "3dnowprefetch", "pti", "fsgsbase", "bmi1", "hle", "avx2", "bmi2", "erms", "rtm", "xsaveopt", "arat"},
		Bugs:            []string{"cpu_meltdown", "spectre_v1", "spectre_v2", "spec_store_bypass", "l1tf", "mds", "swapgs", "taa", "itlb_multihit"},
		BogoMips:        7999.96,
		CLFlushSize:     0x40,
		CacheAlignment:  0x40,
		AddressSizes:    "39 bits physical, 48 bits virtual",
		PowerManagement: "",
	}

	// the second proc is identical
	proc2 := proc1
	proc2.Id = 1
	proc2.PhysicalID = 1
	proc2.ApicID = "1"
	proc2.InitialApicID = "1"
	proc2.BogoMips = 1425.15

	assert.Equal(t, &CpuInfo{
		Processors: []Processor{
			proc1,
			proc2,
		},
	}, cpuInfo)
}

func TestParseProcCpuArm(t *testing.T) {
	trans, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/cpu-info-aarch64.toml"))
	require.NoError(t, err)

	f, err := trans.FileSystem().Open("/proc/cpuinfo")
	require.NoError(t, err)
	defer f.Close()

	cpuInfo, err := ParseCpuInfo(f)
	require.NoError(t, err)

	assert.NotNil(t, cpuInfo, "cpuInfo is not nil")

	proc1 := Processor{
		Id:              0x0,
		VendorID:        "",
		CPUFamily:       "",
		Model:           "",
		ModelName:       "",
		Stepping:        "",
		Microcode:       "",
		CPUMHz:          0,
		CacheSize:       0,
		PhysicalID:      0x0,
		Siblings:        0x0,
		CoreID:          0x0,
		CPUCores:        0x0,
		ApicID:          "",
		InitialApicID:   "",
		FPU:             "",
		FPUException:    "",
		CpuIDLevel:      0x0,
		WP:              "",
		Flags:           []string{"fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp", "asimdhp", "cpuid", "asimdrdm", "lrcpc", "dcpop", "asimddp", "ssbs"},
		Bugs:            []string(nil),
		BogoMips:        243.75,
		CLFlushSize:     0x0,
		CacheAlignment:  0x0,
		AddressSizes:    "",
		PowerManagement: "",
	}
	proc2 := proc1
	proc2.Id = 1

	assert.Equal(t, &CpuInfo{
		Processors: []Processor{
			proc1,
			proc2,
		},
	}, cpuInfo)
}

func TestParseCpuInfoCacheSizeWithoutUnit(t *testing.T) {
	// A cache size value with no unit token must not panic on value[1].
	input := "processor\t: 0\n" +
		"cache size\t: 8192\n"

	cpuInfo, err := ParseCpuInfo(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, cpuInfo.Processors, 1)
	assert.Equal(t, int64(8192), cpuInfo.Processors[0].CacheSize)
}

func TestParseCpuInfoCacheSizeMB(t *testing.T) {
	// A cache size in MB is scaled to KB.
	input := "processor\t: 0\n" +
		"cache size\t: 16 MB\n"

	cpuInfo, err := ParseCpuInfo(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, cpuInfo.Processors, 1)
	assert.Equal(t, int64(16*1024), cpuInfo.Processors[0].CacheSize)
}
