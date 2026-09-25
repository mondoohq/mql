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
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			powershell.Encode(windowsMemoryScript): {Stdout: stdout, Stderr: stderr, ExitStatus: exit},
		},
	}))
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
	// Linux has memory; that the provider does not read it yet is our gap,
	// not a property of the target, so it must not claim not applicable.
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	m := newMemoryResource(t, newMemoryMock(t, linux, windowsMemoryOutput2022, "", 0))

	total := m.GetTotal()
	require.Error(t, total.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(total.Error))
}
