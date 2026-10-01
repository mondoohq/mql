// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package wmiquery

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withQuery(t *testing.T, f func(string, []string) ([]Row, error)) {
	t.Helper()
	orig := query
	query = f
	t.Cleanup(func() { query = orig })
}

// The WMI library panics on some failures of its own (COM setup, a nil
// session); Query must turn that into an error.
func TestQueryRecoversPanic(t *testing.T) {
	withQuery(t, func(string, []string) ([]Row, error) {
		panic("couldn't initialize the WmiSessionManager")
	})
	rows, err := Query("SELECT Name FROM Win32_OperatingSystem", "Name")
	require.Error(t, err)
	assert.Nil(t, rows)
	assert.Contains(t, err.Error(), "panicked")
	assert.Contains(t, err.Error(), "Win32_OperatingSystem")
}

func TestQueryPassesErrorsAndResults(t *testing.T) {
	want := errors.New("access denied")
	withQuery(t, func(string, []string) ([]Row, error) { return nil, want })
	_, err := Query("SELECT x FROM y", "x")
	assert.ErrorIs(t, err, want)

	withQuery(t, func(_ string, props []string) ([]Row, error) {
		assert.Equal(t, []string{"Name"}, props)
		return []Row{{"Name": "host"}}, nil
	})
	rows, err := Query("SELECT Name FROM y", "Name")
	require.NoError(t, err)
	assert.Equal(t, "host", rows[0].String("Name"))
}

// Real queries on the machine that runs the test.
func TestQueryLive(t *testing.T) {
	rows, err := Query("SELECT Caption, Version, OSType, TotalVisibleMemorySize FROM Win32_OperatingSystem",
		"Caption", "Version", "OSType", "TotalVisibleMemorySize")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.NotEmpty(t, rows[0].String("Caption"))
	assert.NotEmpty(t, rows[0].String("Version"))

	osType, ok := rows[0].Int64("OSType")
	require.True(t, ok, "OSType is a uint16")
	assert.Equal(t, int64(18), osType, "18 is WINNT")

	// a uint64, which WMI sends as a string
	mem, ok := rows[0].Int64("TotalVisibleMemorySize")
	require.True(t, ok, "TotalVisibleMemorySize: %T %v", rows[0]["TotalVisibleMemorySize"], rows[0]["TotalVisibleMemorySize"])
	assert.Positive(t, mem)
}

// ChassisTypes is the value whose type the struct-based WMI library could not
// read: it panicked when ChassisTypes was declared []uint16.
func TestQueryChassisTypesLive(t *testing.T) {
	rows, err := Query("SELECT ChassisTypes FROM Win32_SystemEnclosure", "ChassisTypes")
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	types, ok := rows[0].Int64s("ChassisTypes")
	require.True(t, ok, "ChassisTypes: %T %v", rows[0]["ChassisTypes"], rows[0]["ChassisTypes"])
	assert.NotEmpty(t, types)
}

func TestQueryUnknownPropertyLive(t *testing.T) {
	_, err := Query("SELECT Caption FROM Win32_OperatingSystem", "NoSuchProperty")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NoSuchProperty")
}

func TestQueryNoRowsLive(t *testing.T) {
	rows, err := Query("SELECT Name FROM Win32_Service WHERE Name = 'no-such-service-mql'", "Name")
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// Queries from several goroutines each set COM up on their own locked thread.
func TestQueryConcurrentLive(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			rows, err := Query("SELECT Version FROM Win32_OperatingSystem", "Version")
			if assert.NoError(t, err) && assert.Len(t, rows, 1) {
				assert.NotEmpty(t, rows[0].String("Version"))
			}
		})
	}
	wg.Wait()
}
