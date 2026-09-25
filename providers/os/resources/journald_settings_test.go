// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

func TestParseSystemdBoolean(t *testing.T) {
	for _, value := range []string{"1", "yes", "YES", "Yes", "y", "true", "True", "t", "on", "ON"} {
		v, ok := parseSystemdBoolean(value)
		require.True(t, ok, value)
		require.True(t, v, value)
	}
	for _, value := range []string{"0", "no", "NO", "n", "false", "FALSE", "f", "off", "Off"} {
		v, ok := parseSystemdBoolean(value)
		require.True(t, ok, value)
		require.False(t, v, value)
	}
	for _, value := range []string{"", "2", "enabled", "yess", "persistent"} {
		_, ok := parseSystemdBoolean(value)
		require.False(t, ok, value)
	}
}

func TestParseJournaldCompress(t *testing.T) {
	tests := []struct {
		value   string
		want    bool
		isValid bool
	}{
		{value: "", want: true, isValid: true},
		{value: "no", want: false, isValid: true},
		{value: "Off", want: false, isValid: true},
		{value: "0", want: false, isValid: true},
		{value: "YES", want: true, isValid: true},
		{value: "512", want: true, isValid: true},
		{value: "512K", want: true, isValid: true},
		{value: "1.5M", want: true, isValid: true},
		{value: "1G 512M", want: true, isValid: true},
		{value: "maybe", isValid: false},
		{value: "-1K", isValid: false},
		{value: "512KB", isValid: false},
	}
	for _, tt := range tests {
		got, ok := parseJournaldCompress(tt.value)
		require.Equal(t, tt.isValid, ok, tt.value)
		if ok {
			require.Equal(t, tt.want, got, tt.value)
		}
	}
}

func TestResolveJournaldSettingsDefaults(t *testing.T) {
	got := resolveJournaldSettings(nil)
	require.Equal(t, "auto", got.storage)
	require.True(t, got.compress)
	require.False(t, got.forwardToSyslog)
}

func TestResolveJournaldSettingsLastValidAssignmentWins(t *testing.T) {
	got := resolveJournaldSettings([]parsers.UnitParam{
		{Name: "Storage", Value: "volatile"},
		{Name: "Storage", Value: "persistent"},
		// journald rejects these, so the earlier valid values stay
		{Name: "Storage", Value: "Volatile"},
		{Name: "Storage", Value: ""},
		{Name: "Compress", Value: "no"},
		{Name: "Compress", Value: "sometimes"},
		{Name: "ForwardToSyslog", Value: "On"},
		{Name: "ForwardToSyslog", Value: ""},
		// setting names are case-sensitive in journald
		{Name: "forwardtosyslog", Value: "no"},
	})
	require.Equal(t, "persistent", got.storage)
	require.False(t, got.compress)
	require.True(t, got.forwardToSyslog)

	// an empty Compress= restores the default
	got = resolveJournaldSettings([]parsers.UnitParam{
		{Name: "Compress", Value: "no"},
		{Name: "Compress", Value: ""},
	})
	require.True(t, got.compress)
}

func journaldBinary() *mock.MockFileData {
	return &mock.MockFileData{
		StatData: mock.FileInfo{Mode: 0o755},
		Content:  "ELF",
	}
}

func journaldDir() *mock.MockFileData {
	return &mock.MockFileData{
		StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
	}
}

func journaldConf(content string) *mock.MockFileData {
	return &mock.MockFileData{
		StatData: mock.FileInfo{Mode: 0o644},
		Content:  content,
	}
}

func TestJournaldConfigTypedSettingsFollowDropins(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/usr/lib/systemd/systemd-journald":                  journaldBinary(),
		"/etc/systemd/journald.conf":                         journaldConf("[Journal]\nStorage=volatile\nCompress=no\nForwardToSyslog=yes\n"),
		"/etc/systemd/journald.conf.d":                       journaldDir(),
		"/etc/systemd/journald.conf.d/10-storage.conf":       journaldConf("[Journal]\nStorage=persistent\n"),
		"/etc/systemd/journald.conf.d/30-compress.conf":      journaldConf("[Journal]\nCompress=TRUE\n"),
		"/usr/lib/systemd/journald.conf.d":                   journaldDir(),
		"/usr/lib/systemd/journald.conf.d/20-forward.conf":   journaldConf("[Journal]\nForwardToSyslog=off\n"),
		"/usr/lib/systemd/journald.conf.d/40-other-sec.conf": journaldConf("[Upload]\nStorage=none\n"),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "persistent", true, false)
}

func TestJournaldConfigTypedSettingsMaskedVendorDropin(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/usr/lib/systemd/systemd-journald":            journaldBinary(),
		"/etc/systemd/journald.conf":                   journaldConf("[Journal]\n#ForwardToSyslog=yes\n"),
		"/usr/lib/systemd/journald.conf.d":             journaldDir(),
		"/usr/lib/systemd/journald.conf.d/syslog.conf": journaldConf("[Journal]\nForwardToSyslog=yes\n"),
		"/etc/systemd/journald.conf.d":                 journaldDir(),
		// an empty file of the same name masks the vendor drop-in
		"/etc/systemd/journald.conf.d/syslog.conf": journaldConf(""),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "auto", true, false)
}

func TestJournaldConfigTypedSettingsVendorDropinWithoutMainFile(t *testing.T) {
	// Debian and Ubuntu ship ForwardToSyslog=yes as a vendor drop-in
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/lib/systemd/systemd-journald":                journaldBinary(),
		"/usr/lib/systemd/journald.conf.d":             journaldDir(),
		"/usr/lib/systemd/journald.conf.d/syslog.conf": journaldConf("[Journal]\nForwardToSyslog=yes\n"),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "auto", true, true)
}

func TestJournaldConfigTypedSettingsNullWithoutJournald(t *testing.T) {
	cases := map[string]map[string]*mock.MockFileData{
		"no files": {},
		"stray config": {
			"/etc/systemd/journald.conf": journaldConf("[Journal]\nStorage=persistent\nCompress=yes\nForwardToSyslog=yes\n"),
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			runtime := journaldMockRuntime(t, files)
			raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
			require.NoError(t, err)
			config := raw.(*mqlJournaldConfig)

			storage := config.GetStorage()
			require.NoError(t, storage.Error)
			require.True(t, storage.IsNull())
			compress := config.GetCompress()
			require.NoError(t, compress.Error)
			require.True(t, compress.IsNull())
			forward := config.GetForwardToSyslog()
			require.NoError(t, forward.Error)
			require.True(t, forward.IsNull())
		})
	}
}

func TestJournaldConfigTypedSettingsCustomPath(t *testing.T) {
	// no journald binary: an explicitly requested file is read regardless,
	// and the default search path is not consulted
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/etc/systemd/journald.conf":           journaldConf("[Journal]\nStorage=none\nForwardToSyslog=no\n"),
		"/srv/journald.conf":                   journaldConf("[Journal]\nStorage=volatile\nCompress=off\n"),
		"/srv/journald.conf.d":                 journaldDir(),
		"/srv/journald.conf.d/10-forward.conf": journaldConf("[Journal]\nForwardToSyslog=1\n"),
	})

	raw, err := NewResource(runtime, ResourceJournaldConfig, map[string]*llx.RawData{
		"path": llx.StringData("/srv/journald.conf"),
	})
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "volatile", false, true)

	raw, err = NewResource(runtime, ResourceJournaldConfig, map[string]*llx.RawData{
		"path": llx.StringData("/srv/missing.conf"),
	})
	require.NoError(t, err)
	missing := raw.(*mqlJournaldConfig).GetStorage()
	require.Error(t, missing.Error)
}

func requireJournaldSettings(t *testing.T, config *mqlJournaldConfig, storage string, compress, forwardToSyslog bool) {
	t.Helper()

	gotStorage := config.GetStorage()
	require.NoError(t, gotStorage.Error)
	require.False(t, gotStorage.IsNull())
	require.Equal(t, storage, gotStorage.Data)

	gotCompress := config.GetCompress()
	require.NoError(t, gotCompress.Error)
	require.False(t, gotCompress.IsNull())
	require.Equal(t, compress, gotCompress.Data)

	gotForward := config.GetForwardToSyslog()
	require.NoError(t, gotForward.Error)
	require.False(t, gotForward.IsNull())
	require.Equal(t, forwardToSyslog, gotForward.Data)
}
