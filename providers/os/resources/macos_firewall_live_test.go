// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseGlobalState(t *testing.T) {
	for name, tt := range map[string]struct {
		stdout string
		want   int64
		ok     bool
	}{
		"enabled":     {"Firewall is enabled. (State = 1)\n", 1, true},
		"block all":   {"Firewall is enabled. (State = 2)\n", 2, true},
		"disabled":    {"Firewall is disabled. (State = 0)\n", 0, true},
		"no state no": {"Firewall is enabled.\n", 1, true},
		"managed":     {"Firewall settings cannot be modified from command line on managed Mac computers.\n", 0, false},
		"empty":       {"", 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			v, ok := parseGlobalState(tt.stdout)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.want, v)
			}
		})
	}
}

// An unreadable setting must not collapse to false. "the firewall is off" and
// "we could not read the firewall" are different findings.
func TestParseOnOff(t *testing.T) {
	for name, tt := range map[string]struct {
		stdout string
		want   bool
		ok     bool
	}{
		"stealth on":     {"Firewall stealth mode is on\n", true, true},
		"stealth off":    {"Firewall stealth mode is off\n", false, true},
		"blockall on":    {"Firewall has block all state set to enabled.\n", true, true},
		"blockall off":   {"Firewall has block all state set to disabled.\n", false, true},
		"managed mac":    {"Firewall settings cannot be modified from command line on managed Mac computers.\n", false, false},
		"unrecognised":   {"something else entirely\n", false, false},
		"empty is not a": {"", false, false},
		// A bare "enabled."/"disabled." is not a toggle answer. The
		// --getallowsigned reply ends that way, and a logging line can too, so
		// matching the suffix would let one getter be read as another.
		"logging detail line": {"Logging enabled. Detail level: brief\n", false, false},
		"allowsigned line":    {"Automatically allow built-in signed software ENABLED.\n", false, false},
		// "is on" must be a whole word, not a prefix of something else.
		"is one": {"Firewall stealth mode is one of several settings\n", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			v, ok := parseOnOff(tt.stdout)
			assert.Equal(t, tt.ok, ok, "recognised")
			if tt.ok {
				assert.Equal(t, tt.want, v)
			}
		})
	}
}

func TestParseAllowSigned(t *testing.T) {
	builtin, downloaded, ok := parseAllowSigned(
		"Automatically allow built-in signed software ENABLED. \n" +
			"Automatically allow downloaded signed software ENABLED. \n")
	assert.True(t, ok)
	assert.True(t, builtin)
	assert.True(t, downloaded)

	builtin, downloaded, ok = parseAllowSigned(
		"Automatically allow built-in signed software ENABLED. \n" +
			"Automatically allow downloaded signed software DISABLED. \n")
	assert.True(t, ok)
	assert.True(t, builtin)
	assert.False(t, downloaded)

	// A partial reply must not be reported as two falses.
	_, _, ok = parseAllowSigned("Automatically allow built-in signed software ENABLED. \n")
	assert.False(t, ok)

	_, _, ok = parseAllowSigned("Firewall settings cannot be modified from command line on managed Mac computers.\n")
	assert.False(t, ok)
}

func TestParseListApps(t *testing.T) {
	// socketfilterfw --listapps on macOS 26.5.
	got := parseListApps(`Total number of apps = 3 

1 : /opt/homebrew/Cellar/qemu/10.1.2/bin/qemu-system-x86_64 
             (Block incoming connections)

2 : /Applications/Example App.app 
             (Allow incoming connections)

3 : /usr/local/bin/tool 
             ( Allow incoming connections )
`)
	assert.Equal(t, []firewallAppEntry{
		{name: "/opt/homebrew/Cellar/qemu/10.1.2/bin/qemu-system-x86_64", state: 0},
		{name: "/Applications/Example App.app", state: 1},
		{name: "/usr/local/bin/tool", state: 1},
	}, got)

	assert.Empty(t, parseListApps("Total number of apps = 0 \n"))
}

const socketfilterfwManagedReply = "Firewall settings cannot be modified from command line on managed Mac computers.\n"

func newFirewallTestRuntime(t *testing.T, data *mock.TomlData) *mqlMacosFirewall {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}},
	}, mock.WithData(data))
	require.NoError(t, err)
	return &mqlMacosFirewall{MqlRuntime: &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}}
}

// TestFirewallManagedMac is shaped on a macOS 26.5 Mac with a firewall
// configuration profile: no ALF preferences file, socketfilterfw answering
// some getters and refusing others, and the profile's settings in Managed
// Preferences.
func TestFirewallManagedMac(t *testing.T) {
	fw := newFirewallTestRuntime(t, &mock.TomlData{
		Commands: map[string]*mock.Command{
			socketfilterfwPath + " --getglobalstate": {Stdout: "Firewall is enabled. (State = 1)\n"},
			socketfilterfwPath + " --getstealthmode": {Stdout: "Firewall stealth mode is on\n"},
			socketfilterfwPath + " --getloggingmode": {Stdout: socketfilterfwManagedReply},
			socketfilterfwPath + " --listapps": {Stdout: `Total number of apps = 1 

1 : /Applications/Example.app 
             (Allow incoming connections)
`},
		},
		Files: map[string]*mock.MockFileData{
			managedFirewallPlist: {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>EnableFirewall</key><true/>
	<key>EnableLogging</key><true/>
	<key>EnableStealthMode</key><true/>
	<key>LoggingOption</key><string>detail</string>
</dict></plist>
`},
		},
	})

	enabled, err := fw.enabled()
	require.NoError(t, err)
	assert.True(t, enabled)

	stealth, err := fw.stealthEnabled()
	require.NoError(t, err)
	assert.True(t, stealth)

	logging, err := fw.loggingEnabled()
	require.NoError(t, err, "socketfilterfw refuses on a managed Mac; the profile answers")
	assert.True(t, logging)

	detail, err := fw.loggingDetail()
	require.NoError(t, err)
	assert.Equal(t, "detail", detail)

	apps, err := fw.applications()
	require.NoError(t, err)
	require.Len(t, apps, 1)
	app := apps[0].(*mqlMacosFirewallApp)
	assert.Equal(t, "/Applications/Example.app", app.Name.Data)
	assert.Equal(t, int64(1), app.State.Data)
}

// The live answer wins over the profile when socketfilterfw gives one.
func TestFirewallLiveStateWinsOverProfile(t *testing.T) {
	fw := newFirewallTestRuntime(t, &mock.TomlData{
		Commands: map[string]*mock.Command{
			socketfilterfwPath + " --getloggingmode": {Stdout: "Log mode is off\n"},
		},
		Files: map[string]*mock.MockFileData{
			managedFirewallPlist: {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>EnableLogging</key><true/></dict></plist>
`},
		},
	})
	logging, err := fw.loggingEnabled()
	require.NoError(t, err)
	assert.False(t, logging)
}

// With no preferences file, no readable socketfilterfw answer and no profile,
// the setting is an error, never a confident false.
func TestFirewallNoSourceIsAnError(t *testing.T) {
	fw := newFirewallTestRuntime(t, &mock.TomlData{
		Commands: map[string]*mock.Command{
			socketfilterfwPath + " --getloggingmode": {Stdout: socketfilterfwManagedReply},
		},
	})
	_, err := fw.loggingEnabled()
	assert.ErrorIs(t, err, errFirewallStateUnavailable)
}

// With no preferences file, loggingDetail's error names the sources it read,
// not the ALF key lookup that failed first.
func TestFirewallLoggingDetailUnavailable(t *testing.T) {
	fw := newFirewallTestRuntime(t, &mock.TomlData{})
	_, err := fw.loggingDetail()
	require.ErrorIs(t, err, errFirewallLoggingDetailUnavailable)
	assert.NotContains(t, err.Error(), "loggingoption")

	fw = newFirewallTestRuntime(t, &mock.TomlData{
		Files: map[string]*mock.MockFileData{
			managedFirewallPlist: {Content: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>LoggingOption</key><string>verbose</string></dict></plist>
`},
		},
	})
	_, err = fw.loggingDetail()
	require.ErrorIs(t, err, errFirewallLoggingDetailUnavailable)
	assert.Contains(t, err.Error(), `LoggingOption "verbose"`)
}

// With no ALF preferences file, no configuration profile, and socketfilterfw
// declining, every fallback path reads the absent profile as a nil map. Reading
// a nil map yields the zero value, so each path returns its "unavailable"
// error rather than panicking or guessing.
func TestFirewallNoProfileNoLiveAnswer(t *testing.T) {
	fw := newFirewallTestRuntime(t, &mock.TomlData{
		Commands: map[string]*mock.Command{
			socketfilterfwPath + " --getglobalstate": {Stdout: socketfilterfwManagedReply},
			socketfilterfwPath + " --getstealthmode": {Stdout: socketfilterfwManagedReply},
		},
	})

	managed, err := fw.fetchManaged()
	require.NoError(t, err)
	require.Nil(t, managed, "no profile file")

	_, err = fw.globalState()
	assert.ErrorIs(t, err, errFirewallStateUnavailable)
	_, err = fw.stealthEnabled()
	assert.ErrorIs(t, err, errFirewallStateUnavailable)
	_, err = fw.loggingDetail()
	assert.ErrorIs(t, err, errFirewallLoggingDetailUnavailable)
}
