// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	howett "howett.net/plist"
)

func TestNormalizePreferenceDomain(t *testing.T) {
	for in, want := range map[string]string{
		"com.apple.screensaver":       "com.apple.screensaver",
		" com.apple.screensaver ":     "com.apple.screensaver",
		"com.apple.screensaver.plist": "com.apple.screensaver",
		"NSGlobalDomain":              ".GlobalPreferences",
		"-g":                          ".GlobalPreferences",
		".GlobalPreferences":          ".GlobalPreferences",
	} {
		got, err := normalizePreferenceDomain(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "..", "../../etc/hosts", "com.apple/x", `com.apple\x`} {
		_, err := normalizePreferenceDomain(in)
		assert.Error(t, err, in)
	}
}

func TestMergePreferences(t *testing.T) {
	values, sources := mergePreferences([]prefLayer{
		{source: "managed", values: map[string]any{"askForPassword": true}},
		{source: "byHost", values: nil},
		{source: "preferences", values: map[string]any{"askForPassword": false, "idleTime": 600.0, "nested": map[string]any{"a": 1.0}}},
		{source: "system", values: map[string]any{"idleTime": 1200.0, "moduleName": "Flurry", "nested": map[string]any{"b": 2.0}}},
	})
	assert.Equal(t, map[string]any{
		"askForPassword": true,
		"idleTime":       600.0,
		"moduleName":     "Flurry",
		// A dictionary value is taken whole from the first layer, never merged.
		"nested": map[string]any{"a": 1.0},
	}, values)
	assert.Equal(t, map[string]any{
		"askForPassword": "managed",
		"idleTime":       "preferences",
		"moduleName":     "system",
		"nested":         "preferences",
	}, sources)

	values, sources = mergePreferences(nil)
	assert.Empty(t, values)
	assert.NotNil(t, values)
	assert.Empty(t, sources)
}

func TestMcxAlwaysValues(t *testing.T) {
	// Shaped on /Library/Managed Preferences/<user>/complete.plist of an
	// MDM-enrolled Mac on macOS 26.
	complete := map[string]any{
		"com.apple.screensaver": map[string]any{
			"askForPassword": map[string]any{
				"mcxdomain": "always",
				"source":    []any{"mcx_computer_com.apple.screensaver_ef823883"},
				"value":     true,
			},
			"idleTime":   map[string]any{"mcxdomain": "once", "value": 300.0},
			"moduleName": map[string]any{"mcxdomain": "often", "value": "Flurry"},
			"noValue":    map[string]any{"mcxdomain": "always"},
			"notAnEntry": "x",
		},
	}
	assert.Equal(t, map[string]any{"askForPassword": true}, mcxAlwaysValues(complete, "com.apple.screensaver"))
	assert.Nil(t, mcxAlwaysValues(complete, "com.apple.loginwindow"))
	assert.Nil(t, mcxAlwaysValues(nil, "com.apple.screensaver"))
}

func TestByHostCandidates(t *testing.T) {
	names := []string{
		"com.apple.screensaver." + testUUID + ".plist",
		"com.apple.screensaver.001122AABBCC.plist",
		// Another domain that starts with this one.
		"com.apple.screensaver.Basic." + testUUID + ".plist",
		"com.apple.screensaver." + testUUID + ".plist.lockfile",
		"com.apple.controlcenter." + testUUID + ".plist",
	}
	assert.Equal(t, []string{testUUID, "001122AABBCC"}, byHostCandidates(names, "com.apple.screensaver"))
	assert.Equal(t, []string{testUUID}, byHostCandidates(names, "com.apple.screensaver.Basic"))
	assert.Empty(t, byHostCandidates(names, "com.apple.Bluetooth"))
}

func xmlPlist(t *testing.T, v map[string]any) []byte {
	var buf bytes.Buffer
	require.NoError(t, howett.NewEncoderForFormat(&buf, howett.XMLFormat).Encode(v))
	return buf.Bytes()
}

func binaryPlist(t *testing.T, v map[string]any) []byte {
	var buf bytes.Buffer
	require.NoError(t, howett.NewEncoderForFormat(&buf, howett.BinaryFormat).Encode(v))
	return buf.Bytes()
}

func noCommands(t *testing.T) func(string) (string, error) {
	return func(command string) (string, error) {
		t.Errorf("unexpected command %q", command)
		return "", errors.New("unexpected command")
	}
}

func TestMacosPrefReaderReadPlist(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, "/xml.plist", xmlPlist(t, map[string]any{"askForPassword": true, "askForPasswordDelay": 5}))
	writeMemFSFile(t, fs, "/binary.plist", binaryPlist(t, map[string]any{"askForPassword": false}))
	writeMemFSFile(t, fs, "/broken.plist", []byte("<plist><dict><key>a</key>"))
	r := &macosPrefReader{fs: fs, run: noCommands(t)}

	got, err := r.readPlist("/xml.plist")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"askForPassword": true, "askForPasswordDelay": 5.0}, got)

	got, err = r.readPlist("/binary.plist")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"askForPassword": false}, got)

	got, err = r.readPlist("/missing.plist")
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = r.readPlist("/broken.plist")
	assert.ErrorContains(t, err, "/broken.plist")
}

// deniedStatFs refuses to stat one path too, as macOS does for a sandbox
// container the scan may not look into.
type deniedStatFs struct {
	deniedFs
}

func (d deniedStatFs) Stat(name string) (os.FileInfo, error) {
	if name == d.denied {
		return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
	}
	return d.Fs.Stat(name)
}

func TestMacosPrefReaderUnreadableIsAnError(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, "/Library/Preferences/com.apple.screensaver.plist", xmlPlist(t, map[string]any{"idleTime": 300}))
	r := &macosPrefReader{fs: deniedFs{Fs: fs, denied: "/Library/Preferences/com.apple.screensaver.plist"}, run: noCommands(t)}

	_, err := r.readPlist("/Library/Preferences/com.apple.screensaver.plist")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestMacosPrefReaderByHostFile(t *testing.T) {
	dir := "/Users/alice/Library/Preferences/ByHost/"

	// One host: its file is used without asking ioreg, so file system scans
	// read it too.
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, dir+"com.apple.screensaver."+testUUID+".plist", xmlPlist(t, map[string]any{"idleTime": 60}))
	r := &macosPrefReader{fs: fs, run: noCommands(t)}
	got, err := r.byHostFile("/Users/alice", "com.apple.screensaver")
	require.NoError(t, err)
	assert.Equal(t, dir+"com.apple.screensaver."+testUUID+".plist", got)

	got, err = r.byHostFile("/Users/alice", "com.apple.Bluetooth")
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = r.byHostFile("/Users/nobody-home", "com.apple.screensaver")
	require.NoError(t, err)
	assert.Empty(t, got)

	// Several hosts, as in a home migrated from another Mac: the hardware
	// UUID picks this Mac's file, and ioreg runs once.
	writeMemFSFile(t, fs, dir+"com.apple.screensaver.00000000-1111-2222-3333-444444444444.plist", xmlPlist(t, map[string]any{"idleTime": 900}))
	calls := 0
	r = &macosPrefReader{fs: fs, run: func(command string) (string, error) {
		calls++
		assert.Equal(t, hardwareUUIDCmd, command)
		return ioregOutput, nil
	}}
	for range 2 {
		got, err = r.byHostFile("/Users/alice", "com.apple.screensaver")
		require.NoError(t, err)
		assert.Equal(t, dir+"com.apple.screensaver."+testUUID+".plist", got)
	}
	assert.Equal(t, 1, calls)

	// Several hosts and no hardware UUID: an error, not a guess.
	r = &macosPrefReader{fs: fs, run: func(string) (string, error) { return "", errors.New("ioreg: not found") }}
	_, err = r.byHostFile("/Users/alice", "com.apple.screensaver")
	assert.Error(t, err)
}

func TestMacosPrefReaderUserPreferencesFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, "/Users/alice/Library/Preferences/com.apple.Safari.plist", xmlPlist(t, map[string]any{"stale": true}))
	r := &macosPrefReader{fs: fs, run: noCommands(t)}

	got, err := r.userPreferencesFile("/Users/alice", "com.apple.Safari")
	require.NoError(t, err)
	assert.Equal(t, "/Users/alice/Library/Preferences/com.apple.Safari.plist", got)

	container := "/Users/alice/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist"
	writeMemFSFile(t, fs, container, xmlPlist(t, map[string]any{"SendDoNotTrackHTTPHeader": true}))
	got, err = r.userPreferencesFile("/Users/alice", "com.apple.Safari")
	require.NoError(t, err)
	assert.Equal(t, container, got)

	// A container the scan may not look into is an error, not the stale file.
	r = &macosPrefReader{fs: deniedStatFs{deniedFs{Fs: fs, denied: container}}, run: noCommands(t)}
	_, err = r.userPreferencesFile("/Users/alice", "com.apple.Safari")
	assert.ErrorIs(t, err, os.ErrPermission)
}

func newTestMacosPreferences(t *testing.T, fs afero.Fs, domain string) *mqlMacosPreferences {
	runtime := memFSRuntime(t, fs)
	res, err := NewResource(runtime, "macos.preferences", map[string]*llx.RawData{"domain": llx.StringData(domain)})
	require.NoError(t, err)
	p := res.(*mqlMacosPreferences)
	p.reader = &macosPrefReader{fs: fs, run: noCommands(t)}
	return p
}

func newTestMacosPreferencesUser(t *testing.T, p *mqlMacosPreferences, name string) *mqlMacosPreferencesUser {
	res, err := CreateResource(p.MqlRuntime, "macos.preferences.user", map[string]*llx.RawData{
		"__id":   llx.StringData("macos.preferences/" + p.Domain.Data + "/" + name),
		"domain": llx.StringData(p.Domain.Data),
	})
	require.NoError(t, err)
	u := res.(*mqlMacosPreferencesUser)
	u.parent = p
	u.name = name
	u.home = "/Users/" + name
	return u
}

func TestMacosPreferencesComputer(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, "/Library/Managed Preferences/com.apple.screensaver.plist",
		binaryPlist(t, map[string]any{"askForPassword": true, "askForPasswordDelay": 0}))
	writeMemFSFile(t, fs, "/Library/Preferences/com.apple.screensaver.plist",
		xmlPlist(t, map[string]any{"askForPassword": false, "moduleName": "Flurry"}))

	p := newTestMacosPreferences(t, fs, "com.apple.screensaver")
	assert.Equal(t, "macos.preferences/com.apple.screensaver", p.MqlID())

	values := p.GetValues()
	require.NoError(t, values.Error)
	assert.Equal(t, map[string]any{"askForPassword": true, "askForPasswordDelay": 0.0, "moduleName": "Flurry"}, values.Data)

	sources := p.GetSources()
	require.NoError(t, sources.Error)
	assert.Equal(t, map[string]any{"askForPassword": "managed", "askForPasswordDelay": "managed", "moduleName": "system"}, sources.Data)

	// A domain no file sets has empty, not null, values.
	none := newTestMacosPreferences(t, fs, "com.apple.loginwindow")
	assert.Equal(t, map[string]any{}, none.GetManaged().Data)
	assert.Equal(t, map[string]any{}, none.GetSystem().Data)
	assert.Equal(t, map[string]any{}, none.GetValues().Data)

	global := newTestMacosPreferences(t, fs, "NSGlobalDomain")
	assert.Equal(t, ".GlobalPreferences", global.Domain.Data)
}

func TestMacosPreferencesUser(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Computer profile.
	writeMemFSFile(t, fs, "/Library/Managed Preferences/com.apple.screensaver.plist",
		xmlPlist(t, map[string]any{"askForPassword": true, "loginWindowIdleTime": 1200}))
	// User profile, which macOS writes together with the computer's values.
	writeMemFSFile(t, fs, "/Library/Managed Preferences/alice/com.apple.screensaver.plist",
		xmlPlist(t, map[string]any{"askForPassword": true, "askForPasswordDelay": 5}))
	writeMemFSFile(t, fs, "/Library/Managed Preferences/alice/complete.plist", xmlPlist(t, map[string]any{
		"com.apple.screensaver": map[string]any{
			"askForPasswordDelay": map[string]any{"mcxdomain": "always", "value": 60},
			"tokenRemovalAction":  map[string]any{"mcxdomain": "always", "value": 1},
			"idleTime":            map[string]any{"mcxdomain": "once", "value": 30},
		},
	}))
	writeMemFSFile(t, fs, "/Users/alice/Library/Preferences/ByHost/com.apple.screensaver."+testUUID+".plist",
		binaryPlist(t, map[string]any{"idleTime": 600, "askForPassword": false}))
	writeMemFSFile(t, fs, "/Users/alice/Library/Preferences/com.apple.screensaver.plist",
		xmlPlist(t, map[string]any{"idleTime": 300, "showClock": true}))
	writeMemFSFile(t, fs, "/Library/Preferences/com.apple.screensaver.plist",
		xmlPlist(t, map[string]any{"showClock": false, "moduleName": "Flurry"}))

	p := newTestMacosPreferences(t, fs, "com.apple.screensaver")
	alice := newTestMacosPreferencesUser(t, p, "alice")

	managed := alice.GetManaged()
	require.NoError(t, managed.Error)
	assert.Equal(t, map[string]any{
		// The domain's plist wins over complete.plist.
		"askForPassword":      true,
		"askForPasswordDelay": 5.0,
		// complete.plist's always-enforced entry, not its set-once one.
		"tokenRemovalAction": 1.0,
		// The computer profile applies where the user's files are silent.
		"loginWindowIdleTime": 1200.0,
	}, managed.Data)

	values := alice.GetValues()
	require.NoError(t, values.Error)
	assert.Equal(t, map[string]any{
		"askForPassword":      true,
		"askForPasswordDelay": 5.0,
		"tokenRemovalAction":  1.0,
		"loginWindowIdleTime": 1200.0,
		"idleTime":            600.0,
		"showClock":           true,
		"moduleName":          "Flurry",
	}, values.Data)

	sources := alice.GetSources()
	require.NoError(t, sources.Error)
	assert.Equal(t, map[string]any{
		"askForPassword":      "managed",
		"askForPasswordDelay": "managed",
		"tokenRemovalAction":  "managed",
		"loginWindowIdleTime": "managed",
		"idleTime":            "byHost",
		"showClock":           "preferences",
		"moduleName":          "system",
	}, sources.Data)

	// A user without a managed directory or preference files still gets the
	// computer's managed and system values.
	bob := newTestMacosPreferencesUser(t, p, "bob")
	values = bob.GetValues()
	require.NoError(t, values.Error)
	assert.Equal(t, map[string]any{
		"askForPassword":      true,
		"loginWindowIdleTime": 1200.0,
		"showClock":           false,
		"moduleName":          "Flurry",
	}, values.Data)
	assert.Equal(t, map[string]any{}, bob.GetByHost().Data)
	assert.Equal(t, map[string]any{}, bob.GetPreferences().Data)
}

func TestMacosPreferencesUserUnreadableIsAnError(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeMemFSFile(t, fs, "/Users/alice/Library/Preferences/com.apple.screensaver.plist", xmlPlist(t, map[string]any{"idleTime": 300}))
	p := newTestMacosPreferences(t, fs, "com.apple.screensaver")
	p.reader = &macosPrefReader{fs: deniedFs{Fs: fs, denied: "/Users/alice/Library/Preferences/com.apple.screensaver.plist"}, run: noCommands(t)}
	alice := newTestMacosPreferencesUser(t, p, "alice")

	assert.ErrorIs(t, alice.GetPreferences().Error, os.ErrPermission)
	assert.ErrorIs(t, alice.GetValues().Error, os.ErrPermission)
}

func TestMacosPreferencesUserDetached(t *testing.T) {
	fs := afero.NewMemMapFs()
	runtime := memFSRuntime(t, fs)
	res, err := CreateResource(runtime, "macos.preferences.user", map[string]*llx.RawData{
		"__id":   llx.StringData("macos.preferences/x/alice"),
		"domain": llx.StringData("x"),
	})
	require.NoError(t, err)
	u := res.(*mqlMacosPreferencesUser)
	assert.ErrorIs(t, u.GetValues().Error, errPreferencesUserDetached)
	assert.ErrorIs(t, u.GetUser().Error, errPreferencesUserDetached)
}
