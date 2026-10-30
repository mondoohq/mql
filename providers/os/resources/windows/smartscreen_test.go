// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSmartScreenSettings_Configured(t *testing.T) {
	data, err := os.ReadFile("testdata/smartscreen_configured.json")
	require.NoError(t, err)

	s, err := ParseSmartScreenSettings(data)
	require.NoError(t, err)

	assert.Equal(t, new(true), s.ExplorerEnabled())
	require.NotNil(t, s.ShellSmartScreenLevel)
	assert.Equal(t, "Block", *s.ShellSmartScreenLevel)
	assert.Equal(t, new(true), s.EdgeEnabled())
	assert.Equal(t, new(true), s.EdgePuaEnabled())
	assert.Equal(t, new(true), s.EdgePreventOverrideEnabled())
	assert.Equal(t, new(true), s.EdgePreventOverrideForFilesEnabled())
	assert.Equal(t, new(true), s.StoreAppsEnabled())
}

// No SmartScreen policy at all, as on stock Windows 10 22H2 and Windows 11
// 25H2 client installs: every surface is null (Windows applies its own
// default), not false (turned off by policy).
func TestParseSmartScreenSettings_NotConfigured(t *testing.T) {
	data, err := os.ReadFile("testdata/smartscreen_notconfigured.json")
	require.NoError(t, err)

	s, err := ParseSmartScreenSettings(data)
	require.NoError(t, err)

	assert.Nil(t, s.ExplorerEnabled())
	assert.Nil(t, s.ShellSmartScreenLevel)
	assert.Nil(t, s.EdgeEnabled())
	assert.Nil(t, s.EdgePuaEnabled())
	assert.Nil(t, s.EdgePreventOverrideEnabled())
	assert.Nil(t, s.EdgePreventOverrideForFilesEnabled())
	assert.Nil(t, s.StoreAppsEnabled())
}

// A policy that turns a surface off reads false, distinct from not configured.
func TestParseSmartScreenSettings_ExplicitlyDisabled(t *testing.T) {
	s, err := ParseSmartScreenSettings([]byte(`{"EnableSmartScreen":0,"ShellSmartScreenLevel":"Warn","EdgeSmartScreenEnabled":0,"EdgePreventOverrideForFiles":0}`))
	require.NoError(t, err)
	assert.Equal(t, new(false), s.ExplorerEnabled())
	require.NotNil(t, s.ShellSmartScreenLevel)
	assert.Equal(t, "Warn", *s.ShellSmartScreenLevel)
	assert.Equal(t, new(false), s.EdgeEnabled())
	assert.Equal(t, new(false), s.EdgePreventOverrideForFilesEnabled())
	assert.Nil(t, s.EdgePuaEnabled())
}

// A surface may be configured while others are not (e.g. Explorer on, Edge off).
func TestParseSmartScreenSettings_Mixed(t *testing.T) {
	s, err := ParseSmartScreenSettings([]byte(`{"EnableSmartScreen":1,"ShellSmartScreenLevel":"Block","EdgeSmartScreenEnabled":0}`))
	require.NoError(t, err)
	assert.Equal(t, new(true), s.ExplorerEnabled())
	assert.Equal(t, new(false), s.EdgeEnabled())
	// untouched surfaces are unconfigured, not disabled
	assert.Nil(t, s.StoreAppsEnabled())
}

func TestParseSmartScreenSettings_Malformed(t *testing.T) {
	_, err := ParseSmartScreenSettings([]byte("not json"))
	require.Error(t, err)
}

// enabledFlag only treats an explicit 1 as enabled; any other present value
// is "not enabled", and an absent value stays unknown.
func TestSmartScreenEnabledFlag(t *testing.T) {
	one := int64(1)
	two := int64(2)
	zero := int64(0)
	assert.Equal(t, new(true), enabledFlag(&one))
	assert.Equal(t, new(false), enabledFlag(&two))
	assert.Equal(t, new(false), enabledFlag(&zero))
	assert.Nil(t, enabledFlag(nil))
}

func TestSmartScreenResult(t *testing.T) {
	t.Run("a failed read is an error, not an all-null reading", func(t *testing.T) {
		_, err := smartScreenResult(nil, 1, []byte("Get-Item : Requested registry access is not allowed.\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Requested registry access is not allowed.")
	})

	t.Run("a failure without stderr names the exit status", func(t *testing.T) {
		_, err := smartScreenResult(nil, 1, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 1")
	})

	t.Run("success parses stdout", func(t *testing.T) {
		s, err := smartScreenResult([]byte(`{"EnableSmartScreen":1}`), 0, nil)
		require.NoError(t, err)
		assert.Equal(t, new(true), s.ExplorerEnabled())
	})
}

// Real SmartScreen policy readings from Windows Server 2016 (10.0.14393) and
// 2022 (10.0.20348); Server 2019 (10.0.17763) matched 2022 exactly.
//
// No SmartScreen policy is configured on either host, so every policy toggle
// is absent and has to stay null rather than becoming an explicit 0 that would
// read as "administratively disabled". The one value that does exist is the
// Store apps web-content evaluation setting, and it genuinely differs by
// version: 0 on 2016, 1 on 2019 and later. That is a real reading, so it has
// to survive as one.
func TestParseSmartScreenSettings_ServerBaselines(t *testing.T) {
	for _, tc := range []struct {
		name         string
		fixture      string
		storeEnabled bool
	}{
		{"Windows Server 2016", "smartscreen_server2016.json", false},
		{"Windows Server 2022", "smartscreen_server2022.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.fixture)
			require.NoError(t, err)

			s, err := ParseSmartScreenSettings(data)
			require.NoError(t, err)

			assert.Nil(t, s.ExplorerEnabled())
			assert.Nil(t, s.EdgeEnabled())
			assert.Nil(t, s.EdgePuaEnabled())
			assert.Nil(t, s.EdgePreventOverrideEnabled())
			assert.Nil(t, s.EdgePreventOverrideForFilesEnabled())
			assert.Nil(t, s.ShellSmartScreenLevel)

			assert.Equal(t, new(tc.storeEnabled), s.StoreAppsEnabled())
		})
	}
}
