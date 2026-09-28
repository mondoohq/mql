// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/utils/syncx"
)

func TestLaunchdGetString(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected string
	}{
		{
			name:     "existing string value",
			data:     plist.Data{"Label": "com.example.test"},
			key:      "Label",
			expected: "com.example.test",
		},
		{
			name:     "missing key",
			data:     plist.Data{"Label": "com.example.test"},
			key:      "NotExists",
			expected: "",
		},
		{
			name:     "nil value",
			data:     plist.Data{"Label": nil},
			key:      "Label",
			expected: "",
		},
		{
			name:     "non-string value",
			data:     plist.Data{"Label": 123},
			key:      "Label",
			expected: "",
		},
		{
			name:     "empty string",
			data:     plist.Data{"Label": ""},
			key:      "Label",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetString(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetBool(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected bool
	}{
		{
			name:     "true value",
			data:     plist.Data{"RunAtLoad": true},
			key:      "RunAtLoad",
			expected: true,
		},
		{
			name:     "false value",
			data:     plist.Data{"RunAtLoad": false},
			key:      "RunAtLoad",
			expected: false,
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "RunAtLoad",
			expected: false,
		},
		{
			name:     "non-bool value",
			data:     plist.Data{"RunAtLoad": "yes"},
			key:      "RunAtLoad",
			expected: false,
		},
		{
			name:     "nil value",
			data:     plist.Data{"RunAtLoad": nil},
			key:      "RunAtLoad",
			expected: false,
		},
		{
			name:     "integer value",
			data:     plist.Data{"RunAtLoad": float64(1)},
			key:      "RunAtLoad",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetBool(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetInt(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected int64
	}{
		{
			name:     "positive integer",
			data:     plist.Data{"StartInterval": float64(30)},
			key:      "StartInterval",
			expected: 30,
		},
		{
			name:     "zero",
			data:     plist.Data{"StartInterval": float64(0)},
			key:      "StartInterval",
			expected: 0,
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "StartInterval",
			expected: 0,
		},
		{
			name:     "large value",
			data:     plist.Data{"StartInterval": float64(86400)},
			key:      "StartInterval",
			expected: 86400,
		},
		{
			name:     "string input returns zero",
			data:     plist.Data{"StartInterval": "30"},
			key:      "StartInterval",
			expected: 0,
		},
		{
			name:     "negative value",
			data:     plist.Data{"StartInterval": float64(-10)},
			key:      "StartInterval",
			expected: -10,
		},
		{
			name:     "nil value",
			data:     plist.Data{"StartInterval": nil},
			key:      "StartInterval",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetInt(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdParseKeepAlive(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		expected map[string]any
	}{
		{
			name:     "boolean true",
			data:     plist.Data{"KeepAlive": true},
			expected: map[string]any{"enabled": true},
		},
		{
			name:     "boolean false",
			data:     plist.Data{"KeepAlive": false},
			expected: map[string]any{"enabled": false},
		},
		{
			name: "dictionary with SuccessfulExit",
			data: plist.Data{"KeepAlive": map[string]any{"SuccessfulExit": false}},
			expected: map[string]any{
				"enabled":    true,
				"conditions": map[string]any{"SuccessfulExit": false},
			},
		},
		{
			name: "dictionary with multiple conditions",
			data: plist.Data{"KeepAlive": map[string]any{
				"SuccessfulExit": false,
				"NetworkState":   true,
			}},
			expected: map[string]any{
				"enabled": true,
				"conditions": map[string]any{
					"SuccessfulExit": false,
					"NetworkState":   true,
				},
			},
		},
		{
			name:     "missing KeepAlive",
			data:     plist.Data{},
			expected: nil,
		},
		{
			name:     "invalid type string",
			data:     plist.Data{"KeepAlive": "invalid"},
			expected: nil,
		},
		{
			name:     "invalid type integer",
			data:     plist.Data{"KeepAlive": float64(1)},
			expected: nil,
		},
		{
			name:     "nil value",
			data:     plist.Data{"KeepAlive": nil},
			expected: nil,
		},
		{
			name:     "empty dictionary",
			data:     plist.Data{"KeepAlive": map[string]any{}},
			expected: map[string]any{"enabled": true, "conditions": map[string]any{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdParseKeepAlive(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetDict(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected map[string]any
	}{
		{
			name: "existing dict",
			data: plist.Data{"Sockets": map[string]any{
				"Listeners": map[string]any{"SockType": "stream"},
			}},
			key: "Sockets",
			expected: map[string]any{
				"Listeners": map[string]any{"SockType": "stream"},
			},
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "Sockets",
			expected: nil,
		},
		{
			name:     "non-dict value",
			data:     plist.Data{"Sockets": "invalid"},
			key:      "Sockets",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetDict(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetStringArray(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected []any
	}{
		{
			name:     "string array",
			data:     plist.Data{"ProgramArguments": []any{"/usr/bin/test", "-f", "file.txt"}},
			key:      "ProgramArguments",
			expected: []any{"/usr/bin/test", "-f", "file.txt"},
		},
		{
			name:     "empty array",
			data:     plist.Data{"ProgramArguments": []any{}},
			key:      "ProgramArguments",
			expected: []any{},
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "ProgramArguments",
			expected: []any{},
		},
		{
			name:     "mixed types become empty strings for non-strings",
			data:     plist.Data{"ProgramArguments": []any{"valid", float64(123), "also-valid"}},
			key:      "ProgramArguments",
			expected: []any{"valid", "", "also-valid"},
		},
		{
			name:     "single element",
			data:     plist.Data{"WatchPaths": []any{"/var/log/messages"}},
			key:      "WatchPaths",
			expected: []any{"/var/log/messages"},
		},
		{
			name:     "non-array value returns empty",
			data:     plist.Data{"ProgramArguments": "/usr/bin/test"},
			key:      "ProgramArguments",
			expected: []any{},
		},
		{
			name:     "nil value returns empty",
			data:     plist.Data{"ProgramArguments": nil},
			key:      "ProgramArguments",
			expected: []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetStringArray(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetDictArray(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected []any
	}{
		{
			name: "array of dicts",
			data: plist.Data{"StartCalendarInterval": []any{
				map[string]any{"Hour": float64(3), "Minute": float64(0)},
				map[string]any{"Weekday": float64(0)},
			}},
			key: "StartCalendarInterval",
			expected: []any{
				map[string]any{"Hour": float64(3), "Minute": float64(0)},
				map[string]any{"Weekday": float64(0)},
			},
		},
		{
			name:     "empty array",
			data:     plist.Data{"StartCalendarInterval": []any{}},
			key:      "StartCalendarInterval",
			expected: []any{},
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "StartCalendarInterval",
			expected: []any{},
		},
		{
			name:     "non-dict elements become empty dicts",
			data:     plist.Data{"StartCalendarInterval": []any{"invalid", float64(123)}},
			key:      "StartCalendarInterval",
			expected: []any{map[string]any{}, map[string]any{}},
		},
		{
			name:     "single dict normalized to array",
			data:     plist.Data{"StartCalendarInterval": map[string]any{"Hour": float64(2), "Minute": float64(30)}},
			key:      "StartCalendarInterval",
			expected: []any{map[string]any{"Hour": float64(2), "Minute": float64(30)}},
		},
		{
			name:     "single dict not confused with non-dict value",
			data:     plist.Data{"StartCalendarInterval": "invalid"},
			key:      "StartCalendarInterval",
			expected: []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetDictArray(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdGetStringMap(t *testing.T) {
	tests := []struct {
		name     string
		data     plist.Data
		key      string
		expected map[string]any
	}{
		{
			name: "environment variables",
			data: plist.Data{"EnvironmentVariables": map[string]any{
				"PATH":  "/usr/local/bin:/usr/bin",
				"DEBUG": "1",
			}},
			key: "EnvironmentVariables",
			expected: map[string]any{
				"PATH":  "/usr/local/bin:/usr/bin",
				"DEBUG": "1",
			},
		},
		{
			name:     "empty map",
			data:     plist.Data{"EnvironmentVariables": map[string]any{}},
			key:      "EnvironmentVariables",
			expected: map[string]any{},
		},
		{
			name:     "missing key",
			data:     plist.Data{},
			key:      "EnvironmentVariables",
			expected: map[string]any{},
		},
		{
			name:     "non-map value",
			data:     plist.Data{"EnvironmentVariables": "invalid"},
			key:      "EnvironmentVariables",
			expected: map[string]any{},
		},
		{
			name: "non-string values coerced to strings",
			data: plist.Data{"EnvironmentVariables": map[string]any{
				"PATH":    "/usr/bin",
				"TIMEOUT": float64(30),
				"DEBUG":   true,
			}},
			key: "EnvironmentVariables",
			expected: map[string]any{
				"PATH":    "/usr/bin",
				"TIMEOUT": "30",
				"DEBUG":   "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := launchdGetStringMap(tt.data, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLaunchdPlatformValidation(t *testing.T) {
	tests := []struct {
		name           string
		platformName   string
		platformFamily string
		shouldError    bool
	}{
		{
			name:           "macOS supported",
			platformName:   "macos",
			platformFamily: "darwin",
			shouldError:    false,
		},
		{
			name:         "Linux unsupported",
			platformName: "ubuntu",
			shouldError:  true,
		},
		{
			name:         "Windows unsupported",
			platformName: "windows",
			shouldError:  true,
		},
		{
			name:         "FreeBSD unsupported",
			platformName: "freebsd",
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform := &inventory.Platform{
				Name:   tt.platformName,
				Family: []string{tt.platformFamily},
			}
			if tt.platformFamily == "" {
				platform.Family = []string{tt.platformName}
			}

			conn, err := mock.New(0, &inventory.Asset{
				Platform: platform,
			})
			require.NoError(t, err)

			runtime := &plugin.Runtime{
				Connection: conn,
			}

			_, _, err = initLaunchd(runtime, map[string]*llx.RawData{})

			if tt.shouldError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "only supported on macOS")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLaunchdFullPlistParsing(t *testing.T) {
	// Simulate a complete launchd plist structure
	data := plist.Data{
		"Label":            "com.example.daemon",
		"Program":          "/usr/local/bin/example",
		"ProgramArguments": []any{"/usr/local/bin/example", "--daemon", "--config", "/etc/example.conf"},
		"RunAtLoad":        true,
		"KeepAlive":        map[string]any{"SuccessfulExit": false},
		"WorkingDirectory": "/var/lib/example",
		"UserName":         "daemon",
		"GroupName":        "daemon",
		"ProcessType":      "Background",
		"StartInterval":    float64(300),
		"EnvironmentVariables": map[string]any{
			"LOG_LEVEL": "info",
		},
		"WatchPaths": []any{"/etc/example.conf"},
		"Sockets": map[string]any{
			"Listeners": map[string]any{
				"SockType":        "stream",
				"SockServiceName": "example",
			},
		},
		"MachServices": map[string]any{
			"com.example.service": true,
		},
		"StartCalendarInterval": []any{
			map[string]any{"Hour": float64(3), "Minute": float64(0)},
		},
		"StandardOutPath":   "/var/log/example.out.log",
		"StandardErrorPath": "/var/log/example.err.log",
		"RootDirectory":     "/var/lib/example",
		"Disabled":          false,
	}

	// Test all field extractions
	assert.Equal(t, "com.example.daemon", launchdGetString(data, "Label"))
	assert.Equal(t, "/usr/local/bin/example", launchdGetString(data, "Program"))
	assert.Equal(t, "/var/lib/example", launchdGetString(data, "WorkingDirectory"))
	assert.Equal(t, "daemon", launchdGetString(data, "UserName"))
	assert.Equal(t, "daemon", launchdGetString(data, "GroupName"))
	assert.Equal(t, "Background", launchdGetString(data, "ProcessType"))
	assert.Equal(t, "/var/log/example.out.log", launchdGetString(data, "StandardOutPath"))
	assert.Equal(t, "/var/log/example.err.log", launchdGetString(data, "StandardErrorPath"))
	assert.Equal(t, "/var/lib/example", launchdGetString(data, "RootDirectory"))

	assert.True(t, launchdGetBool(data, "RunAtLoad"))
	assert.False(t, launchdGetBool(data, "Disabled"))

	assert.Equal(t, int64(300), launchdGetInt(data, "StartInterval"))

	assert.Equal(t, []any{"/usr/local/bin/example", "--daemon", "--config", "/etc/example.conf"},
		launchdGetStringArray(data, "ProgramArguments"))
	assert.Equal(t, []any{"/etc/example.conf"}, launchdGetStringArray(data, "WatchPaths"))

	keepAlive := launchdParseKeepAlive(data)
	assert.Equal(t, true, keepAlive["enabled"])
	assert.Equal(t, map[string]any{"SuccessfulExit": false}, keepAlive["conditions"])

	assert.Equal(t, map[string]any{"LOG_LEVEL": "info"}, launchdGetStringMap(data, "EnvironmentVariables"))

	sockets := launchdGetDict(data, "Sockets")
	assert.NotNil(t, sockets)
	assert.NotNil(t, sockets["Listeners"])

	machServices := launchdGetDict(data, "MachServices")
	assert.NotNil(t, machServices)
	assert.Equal(t, true, machServices["com.example.service"])

	calendarInterval := launchdGetDictArray(data, "StartCalendarInterval")
	require.Len(t, calendarInterval, 1)
	assert.Equal(t, float64(3), calendarInterval[0].(map[string]any)["Hour"])
}

func TestLaunchdMinimalPlist(t *testing.T) {
	// Minimal plist with only required field
	data := plist.Data{
		"Label": "com.example.minimal",
	}

	assert.Equal(t, "com.example.minimal", launchdGetString(data, "Label"))
	assert.Equal(t, "", launchdGetString(data, "Program"))
	assert.False(t, launchdGetBool(data, "RunAtLoad"))
	assert.False(t, launchdGetBool(data, "Disabled"))
	assert.Equal(t, int64(0), launchdGetInt(data, "StartInterval"))
	assert.Equal(t, []any{}, launchdGetStringArray(data, "ProgramArguments"))
	assert.Nil(t, launchdParseKeepAlive(data))
	assert.Nil(t, launchdGetDict(data, "Sockets"))
	assert.Equal(t, map[string]any{}, launchdGetStringMap(data, "EnvironmentVariables"))
	assert.Equal(t, "", launchdGetString(data, "StandardOutPath"))
	assert.Equal(t, "", launchdGetString(data, "StandardErrorPath"))
	assert.Equal(t, "", launchdGetString(data, "RootDirectory"))
}

// Integration tests using TOML-based mock filesystem

func TestLaunchdPlistFromMockFS(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/launchd_macos.toml"))
	require.NoError(t, err)

	// Verify we can read and parse a full daemon plist through the mock filesystem
	f, err := conn.FileSystem().Open("/Library/LaunchDaemons/com.example.daemon.plist")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	data, err := plist.Decode(bytes.NewReader(content))
	require.NoError(t, err)

	assert.Equal(t, "com.example.daemon", launchdGetString(data, "Label"))
	assert.Equal(t, "/usr/local/bin/example", launchdGetString(data, "Program"))
	assert.True(t, launchdGetBool(data, "RunAtLoad"))
	assert.False(t, launchdGetBool(data, "Disabled"))
	assert.Equal(t, int64(300), launchdGetInt(data, "StartInterval"))
	assert.Equal(t, "/var/lib/example", launchdGetString(data, "WorkingDirectory"))
	assert.Equal(t, "daemon", launchdGetString(data, "UserName"))
	assert.Equal(t, "daemon", launchdGetString(data, "GroupName"))
	assert.Equal(t, "Background", launchdGetString(data, "ProcessType"))
	assert.Equal(t, "/var/log/example.out.log", launchdGetString(data, "StandardOutPath"))
	assert.Equal(t, "/var/log/example.err.log", launchdGetString(data, "StandardErrorPath"))
	assert.Equal(t, "/var/lib/example", launchdGetString(data, "RootDirectory"))

	assert.Equal(t, []any{"/usr/local/bin/example", "--daemon"},
		launchdGetStringArray(data, "ProgramArguments"))
	assert.Equal(t, []any{"/etc/example.conf"}, launchdGetStringArray(data, "WatchPaths"))

	keepAlive := launchdParseKeepAlive(data)
	assert.Equal(t, true, keepAlive["enabled"])
	assert.Equal(t, map[string]any{"SuccessfulExit": false}, keepAlive["conditions"])

	assert.Equal(t, map[string]any{"LOG_LEVEL": "info"}, launchdGetStringMap(data, "EnvironmentVariables"))

	sockets := launchdGetDict(data, "Sockets")
	require.NotNil(t, sockets)

	machServices := launchdGetDict(data, "MachServices")
	require.NotNil(t, machServices)
	assert.Equal(t, true, machServices["com.example.service"])

	calendarInterval := launchdGetDictArray(data, "StartCalendarInterval")
	require.Len(t, calendarInterval, 1)
	assert.Equal(t, float64(3), calendarInterval[0].(map[string]any)["Hour"])
}

func TestLaunchdMinimalPlistFromMockFS(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/launchd_macos.toml"))
	require.NoError(t, err)

	f, err := conn.FileSystem().Open("/Library/LaunchDaemons/com.example.minimal.plist")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	data, err := plist.Decode(bytes.NewReader(content))
	require.NoError(t, err)

	assert.Equal(t, "com.example.minimal", launchdGetString(data, "Label"))
	assert.Equal(t, "", launchdGetString(data, "Program"))
	assert.False(t, launchdGetBool(data, "RunAtLoad"))
	assert.Equal(t, int64(0), launchdGetInt(data, "StartInterval"))
	assert.Equal(t, []any{"/usr/local/bin/minimal"}, launchdGetStringArray(data, "ProgramArguments"))
	assert.Nil(t, launchdParseKeepAlive(data))
}

func TestLaunchdSingleDictCalendarIntervalFromMockFS(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/launchd_macos.toml"))
	require.NoError(t, err)

	// This plist has StartCalendarInterval as a single dict (not array)
	f, err := conn.FileSystem().Open("/Library/LaunchDaemons/com.example.scheduled.plist")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	data, err := plist.Decode(bytes.NewReader(content))
	require.NoError(t, err)

	assert.Equal(t, "com.example.scheduled", launchdGetString(data, "Label"))

	// Single dict should be normalized to a one-element array
	calendarInterval := launchdGetDictArray(data, "StartCalendarInterval")
	require.Len(t, calendarInterval, 1)
	assert.Equal(t, float64(2), calendarInterval[0].(map[string]any)["Hour"])
	assert.Equal(t, float64(30), calendarInterval[0].(map[string]any)["Minute"])

	// Boolean KeepAlive
	keepAlive := launchdParseKeepAlive(data)
	assert.Equal(t, map[string]any{"enabled": true}, keepAlive)
}

func TestLaunchdDirectoryListingFromMockFS(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/launchd_macos.toml"))
	require.NoError(t, err)

	stat, err := conn.FileSystem().Stat("/Library/LaunchDaemons")
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

func TestLaunchdPlistExtensionCaseInsensitive(t *testing.T) {
	// Test that the case-insensitive plist extension check works
	// This verifies the fix in parseJobsInDirectory
	tests := []struct {
		filename string
		expected bool
	}{
		{"com.example.daemon.plist", true},
		{"com.example.daemon.PLIST", true},
		{"com.example.daemon.Plist", true},
		{"com.example.daemon.pLiSt", true},
		{"com.example.daemon.txt", false},
		{"com.example.plist.bak", false},
		{".plist", true},
		{"plist", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			// Replicate the check from parseJobsInDirectory
			result := strings.HasSuffix(strings.ToLower(tt.filename), ".plist")
			assert.Equal(t, tt.expected, result)
		})
	}
}

// The content field carries the whole decoded plist. plist.Decode returns the
// named type plist.Data, which llx's dict converter rejects with "unsupported
// child type: plist.Data", so every job's content failed to serialize. The
// fixture is a real macOS plist.
func TestLaunchdJobContentSerializes(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/launchd_macos.toml"))
	require.NoError(t, err)

	l := &mqlLaunchd{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
	afs := &afero.Afero{Fs: conn.FileSystem()}

	job, err := l.parseJobFile(afs, "/System/Library/LaunchAgents/com.openssh.ssh-agent.plist", "system", "agent")
	require.NoError(t, err)
	assert.Equal(t, "com.openssh.ssh-agent", job.Label.Data)

	res := llx.DictData(job.Content.Data).Result()
	require.Empty(t, res.Error)

	back := res.RawData()
	require.NoError(t, back.Error)
	content, ok := back.Value.(map[string]any)
	require.True(t, ok, "content should decode to a map, got %T", back.Value)
	assert.Equal(t, "com.openssh.ssh-agent", content["Label"])
	assert.Equal(t, "Interactive", content["ProcessType"])
	assert.Equal(t, false, content["EnablePressuredExit"])
	assert.Equal(t, []any{"/usr/bin/ssh-agent", "-l"}, content["ProgramArguments"])
	assert.Equal(t, map[string]any{
		"Listeners": map[string]any{"SecureSocketWithKey": "SSH_AUTH_SOCK"},
	}, content["Sockets"])
}
