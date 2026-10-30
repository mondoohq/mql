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
		"/etc/systemd/journald.conf":                   journaldConf("[Journal]\n#ForwardToSyslog=no\n"),
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

// journald.conf as Ubuntu 16.04 (systemd 229) ships it. Ubuntu 18.04, 20.04 and
// 22.04 document the same defaults.
const ubuntu1604JournaldConf = `#  This file is part of systemd.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See journald.conf(5) for details.

[Journal]
#Storage=auto
#Compress=yes
#Seal=yes
#SplitMode=uid
#MaxFileSec=1month
#ForwardToSyslog=yes
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
`

// journald.conf as Ubuntu 26.04 (systemd 259) ships it.
const ubuntu2604JournaldConf = `#  This file is part of systemd.
#
# Entries in this file show the compile time defaults. Local configuration
# should be created by either modifying this file (or a copy of it placed in
# /etc/ if the original file is shipped in /usr/), or by creating "drop-ins" in
# the /etc/systemd/journald.conf.d/ directory. The latter is generally
# recommended. Defaults can be restored by simply deleting the main
# configuration file and all drop-ins located in /etc/.
#
# Use 'systemd-analyze cat-config systemd/journald.conf' to display the full config.
#
# See journald.conf(5) for details.

[Journal]
#Storage=persistent
#Compress=yes
#Seal=yes
#SplitMode=uid
#ForwardToSyslog=no
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
`

const debianSyslogDropin = `# Undo upstream commit 46b131574fdd7d77 for now. For details see
#  http://lists.freedesktop.org/archives/systemd-devel/2014-November/025550.html

[Journal]
ForwardToSyslog=yes
`

func TestJournaldCompiledDefaults(t *testing.T) {
	require.Equal(t, []parsers.UnitParam{
		{Name: "Storage", Value: "auto"},
		{Name: "Compress", Value: "yes"},
		{Name: "ForwardToSyslog", Value: "yes"},
	}, journaldCompiledDefaults(ubuntu1604JournaldConf))

	require.Equal(t, []parsers.UnitParam{
		{Name: "Storage", Value: "persistent"},
		{Name: "Compress", Value: "yes"},
		{Name: "ForwardToSyslog", Value: "no"},
	}, journaldCompiledDefaults(ubuntu2604JournaldConf))

	// a commented setting outside [Journal] is not a journald default, and a
	// file without commented settings documents none
	require.Empty(t, journaldCompiledDefaults("[Upload]\n#ForwardToSyslog=yes\n"))
	require.Empty(t, journaldCompiledDefaults("[Journal]\nStorage=volatile\n"))
}

// Debian and Ubuntu up to 22.04 build journald to forward to syslog unless told
// otherwise, and there is no drop-in saying so. Reporting false there made a
// check that logs reach a syslog daemon fail on a host where they did.
func TestJournaldConfigTypedSettingsDebianCompiledDefault(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/lib/systemd/systemd-journald": journaldBinary(),
		"/etc/systemd/journald.conf":    journaldConf(ubuntu1604JournaldConf),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "auto", true, true)
}

// An explicit assignment still overrides the compiled default.
func TestJournaldConfigTypedSettingsAssignmentOverridesCompiledDefault(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/lib/systemd/systemd-journald":        journaldBinary(),
		"/etc/systemd/journald.conf":           journaldConf(ubuntu1604JournaldConf),
		"/etc/systemd/journald.conf.d":         journaldDir(),
		"/etc/systemd/journald.conf.d/50.conf": journaldConf("[Journal]\nForwardToSyslog=no\nStorage=volatile\n"),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "volatile", true, false)
}

// Ubuntu 26.04 builds journald to store persistently, and forwards to syslog
// through the vendor drop-in rather than the compiled default.
func TestJournaldConfigTypedSettingsUbuntu2604(t *testing.T) {
	runtime := journaldMockRuntime(t, map[string]*mock.MockFileData{
		"/usr/lib/systemd/systemd-journald":            journaldBinary(),
		"/etc/systemd/journald.conf":                   journaldConf(ubuntu2604JournaldConf),
		"/usr/lib/systemd/journald.conf.d":             journaldDir(),
		"/usr/lib/systemd/journald.conf.d/syslog.conf": journaldConf(debianSyslogDropin),
	})

	raw, err := CreateResource(runtime, ResourceJournaldConfig, nil)
	require.NoError(t, err)

	requireJournaldSettings(t, raw.(*mqlJournaldConfig), "persistent", true, true)
}
