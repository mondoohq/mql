// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

func TestParseSystemdSize(t *testing.T) {
	valid := map[string]int64{
		"0":         0,
		"512":       512,
		"512B":      512,
		"1K":        1024,
		"2G":        2 << 30,
		"32G":       32 << 30,
		"767M":      767 << 20,
		"1.5G":      3 << 29,
		"1G 512M":   3 << 29,
		" 4 K":      4096,
		"+1K":       1024,
		"1T":        1 << 40,
		"1P":        1 << 50,
		"7E":        7 << 60,
		"8E":        -1, // does not fit in an int64
		"15E 1023P": -1,
	}
	for in, want := range valid {
		got, err := parseSystemdSize(in)
		if assert.NoError(t, err, in) {
			assert.Equal(t, want, got, in)
		}
	}

	invalid := []string{
		"",
		"infinity",
		"-1",
		"-0",
		"1k",    // suffixes are case-sensitive
		"1g",    // same
		"1GB",   // "B" after "G" is a second, smaller component with no number
		"1M 1G", // components must be in decreasing order
		"1X",    // unknown suffix
		"0x10",  // base 10 only
		"G",     // no number
		"16E",   // overflows uint64
		"18446744073709551616",
		"abc",
		" 4 K ", // systemd rejects trailing whitespace; its config parser strips it first
	}
	for _, in := range invalid {
		_, err := parseSystemdSize(in)
		assert.Error(t, err, in)
	}
}

func TestCorePatternPipesToSystemdCoredump(t *testing.T) {
	assert.True(t, corePatternPipesToSystemdCoredump("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F\n"))
	// Ubuntu 22.04 installs it under /lib
	assert.True(t, corePatternPipesToSystemdCoredump("|/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h %d"))
	assert.False(t, corePatternPipesToSystemdCoredump("core\n"))
	assert.False(t, corePatternPipesToSystemdCoredump("|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E"))
	assert.False(t, corePatternPipesToSystemdCoredump("/var/crash/systemd-coredump"), "a file path, not a pipe")
	assert.False(t, corePatternPipesToSystemdCoredump("|"))
	assert.False(t, corePatternPipesToSystemdCoredump(""))
}

func coredumpParams(kv ...string) []parsers.UnitParam {
	res := make([]parsers.UnitParam, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		res = append(res, parsers.UnitParam{Name: kv[i], Value: kv[i+1]})
	}
	return res
}

func TestEffectiveCoredumpSettings(t *testing.T) {
	t.Run("unset, installed: storage default, sizes null", func(t *testing.T) {
		s := effectiveCoredumpSettings(nil, true)
		require.NotNil(t, s.storage)
		assert.Equal(t, "external", *s.storage)
		assert.Nil(t, s.processSizeMax)
		assert.Nil(t, s.externalSizeMax)
		assert.Empty(t, s.params)
	})

	t.Run("unset, not installed: no invented default", func(t *testing.T) {
		s := effectiveCoredumpSettings(nil, false)
		assert.Nil(t, s.storage)
		assert.Nil(t, s.processSizeMax)
	})

	t.Run("explicit values without systemd-coredump are still reported", func(t *testing.T) {
		s := effectiveCoredumpSettings(coredumpParams("Storage", "none"), false)
		require.NotNil(t, s.storage)
		assert.Equal(t, "none", *s.storage)
	})

	t.Run("last valid assignment wins", func(t *testing.T) {
		s := effectiveCoredumpSettings(coredumpParams(
			"Storage", "journal",
			"ProcessSizeMax", "1G",
			"Storage", "none",
			"ProcessSizeMax", "0",
			"ExternalSizeMax", "10M",
		), true)
		assert.Equal(t, "none", *s.storage)
		assert.Equal(t, int64(0), *s.processSizeMax)
		assert.Equal(t, int64(10<<20), *s.externalSizeMax)
	})

	t.Run("invalid assignments are ignored, previous value holds", func(t *testing.T) {
		s := effectiveCoredumpSettings(coredumpParams(
			"Storage", "none",
			"Storage", "None", // case-sensitive in systemd
			"ProcessSizeMax", "0",
			"ProcessSizeMax", "infinity", // not accepted for ProcessSizeMax
			"ExternalSizeMax", "1G",
			"ExternalSizeMax", "lots",
		), true)
		assert.Equal(t, "none", *s.storage)
		assert.Equal(t, int64(0), *s.processSizeMax)
		assert.Equal(t, int64(1<<30), *s.externalSizeMax)
		// params keeps the raw last assignment
		assert.Equal(t, "None", s.params["Storage"])
		assert.Equal(t, "infinity", s.params["ProcessSizeMax"])
	})

	t.Run("only invalid storage falls back to the default", func(t *testing.T) {
		s := effectiveCoredumpSettings(coredumpParams("Storage", "NONE"), true)
		assert.Equal(t, "external", *s.storage)
	})

	t.Run("ExternalSizeMax infinity", func(t *testing.T) {
		s := effectiveCoredumpSettings(coredumpParams("ExternalSizeMax", "infinity"), true)
		assert.Equal(t, int64(-1), *s.externalSizeMax)
	})
}

func TestCoredumpAssignmentsOnlyReadCoredumpSection(t *testing.T) {
	a, err := coredumpAssignments(
		[]string{"/etc/systemd/coredump.conf", "/etc/systemd/coredump.conf.d/10.conf"},
		[]string{
			"[Coredump]\n#Storage=journal\nStorage=external\n[Other]\nStorage=journal\n",
			"[Coredump]\nStorage=none\n",
		},
	)
	require.NoError(t, err)
	assert.Equal(t, coredumpParams("Storage", "external", "Storage", "none"), a)
}

func coredumpMockFile(content string) *mock.MockFileData {
	return &mock.MockFileData{StatData: mock.FileInfo{Mode: 0o644}, Content: content}
}

func coredumpMockDir() *mock.MockFileData {
	return &mock.MockFileData{StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}}
}

func TestSystemdCoredumpResource(t *testing.T) {
	t.Run("drop-ins override the vendor main file", func(t *testing.T) {
		runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
			"/proc/sys/kernel/core_pattern":              coredumpMockFile("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F\n"),
			"/usr/lib/systemd/systemd-coredump":          coredumpMockFile(""),
			"/usr/lib/systemd/coredump.conf":             coredumpMockFile("[Coredump]\n#Storage=external\nProcessSizeMax=2G\n"),
			"/usr/lib/systemd/coredump.conf.d":           coredumpMockDir(),
			"/usr/lib/systemd/coredump.conf.d/50-a.conf": coredumpMockFile("[Coredump]\nStorage=journal\n"),
			"/etc/systemd/coredump.conf.d":               coredumpMockDir(),
			"/etc/systemd/coredump.conf.d/50-a.conf":     coredumpMockFile("[Coredump]\nStorage=none\n"),
			"/etc/systemd/coredump.conf.d/60-b.conf":     coredumpMockFile("[Coredump]\nProcessSizeMax=0\n"),
		})
		raw, err := CreateResource(runtime, ResourceSystemdCoredump, nil)
		require.NoError(t, err)
		c := raw.(*mqlSystemdCoredump)

		active := c.GetActive()
		require.NoError(t, active.Error)
		assert.True(t, active.Data)

		storage := c.GetStorage()
		require.NoError(t, storage.Error)
		assert.Equal(t, "none", storage.Data)

		psm := c.GetProcessSizeMax()
		require.NoError(t, psm.Error)
		assert.False(t, psm.IsNull())
		assert.Equal(t, int64(0), psm.Data)

		esm := c.GetExternalSizeMax()
		require.NoError(t, esm.Error)
		assert.True(t, esm.IsNull())

		files := c.GetFiles()
		require.NoError(t, files.Error)
		paths := []string{}
		for _, f := range files.Data {
			paths = append(paths, f.(*mqlFile).Path.Data)
		}
		assert.Equal(t, []string{
			"/usr/lib/systemd/coredump.conf",
			"/etc/systemd/coredump.conf.d/50-a.conf",
			"/etc/systemd/coredump.conf.d/60-b.conf",
		}, paths)

		params := c.GetParams()
		require.NoError(t, params.Error)
		assert.Equal(t, map[string]any{"Storage": "none", "ProcessSizeMax": "0"}, params.Data)
	})

	t.Run("host without systemd-coredump", func(t *testing.T) {
		runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
			"/proc/sys/kernel/core_pattern": coredumpMockFile("core\n"),
		})
		raw, err := CreateResource(runtime, ResourceSystemdCoredump, nil)
		require.NoError(t, err)
		c := raw.(*mqlSystemdCoredump)

		active := c.GetActive()
		require.NoError(t, active.Error)
		assert.False(t, active.IsNull())
		assert.False(t, active.Data)

		storage := c.GetStorage()
		require.NoError(t, storage.Error)
		assert.True(t, storage.IsNull(), "no default storage without systemd-coredump")

		assert.True(t, c.GetProcessSizeMax().IsNull())
		assert.Empty(t, c.GetFiles().Data)
		assert.Empty(t, c.GetParams().Data)
	})

	t.Run("installed but not wired to the kernel, core pattern unreadable", func(t *testing.T) {
		runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
			"/lib/systemd/systemd-coredump": coredumpMockFile(""),
			"/etc/systemd/coredump.conf":    coredumpMockFile("[Coredump]\n#Storage=external\n"),
		})
		raw, err := CreateResource(runtime, ResourceSystemdCoredump, nil)
		require.NoError(t, err)
		c := raw.(*mqlSystemdCoredump)

		active := c.GetActive()
		require.NoError(t, active.Error)
		assert.True(t, active.IsNull(), "an image has no core pattern to read")

		storage := c.GetStorage()
		require.NoError(t, storage.Error)
		assert.Equal(t, "external", storage.Data)
	})
}
