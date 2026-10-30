// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/utils/syncx"
)

type optionalFeatureRecordingConnection struct {
	*mock.Connection
	mu       sync.Mutex
	commands []string
}

func (c *optionalFeatureRecordingConnection) RunCommand(command string) (*shared.Command, error) {
	c.mu.Lock()
	c.commands = append(c.commands, command)
	c.mu.Unlock()
	return c.Connection.RunCommand(command)
}

// The enumeration must not pay for DISM's detailed per-feature lookup: every
// check that filters on a feature state runs it, and it costs tens of seconds on
// a Windows client. Display name and description are loaded on demand instead,
// once for the whole enumeration.
func TestOptionalFeaturesDefersDetailQuery(t *testing.T) {
	listCmd := powershell.Encode(windows.QUERY_OPTIONAL_FEATURES)
	detailCmd := powershell.Encode(windows.QUERY_OPTIONAL_FEATURE_DETAILS)

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			listCmd: {Stdout: `[
				{"FeatureName": "SMB1Protocol", "State": 2},
				{"FeatureName": "TelnetClient", "State": 0}
			]`},
			detailCmd: {Stdout: `[
				{"FeatureName": "SMB1Protocol", "DisplayName": "SMB 1.0/CIFS File Sharing Support", "Description": "Support for the SMB 1.0/CIFS file sharing protocol", "State": 2},
				{"FeatureName": "TelnetClient", "DisplayName": "Telnet Client", "Description": "Telnet Client uses the Telnet protocol", "State": 0}
			]`},
		},
	}))
	require.NoError(t, err)

	conn := &optionalFeatureRecordingConnection{Connection: mockConn}
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	features, err := (&mqlWindows{MqlRuntime: runtime}).optionalFeatures()
	require.NoError(t, err)
	require.Len(t, features, 2)
	assert.Equal(t, []string{listCmd}, conn.commands, "the enumeration only lists features")

	smb := features[0].(*mqlWindowsOptionalFeature)
	assert.Equal(t, "SMB1Protocol", smb.GetName().Data)
	assert.Equal(t, int64(2), smb.GetState().Data)
	assert.True(t, smb.GetEnabled().Data)

	telnet := features[1].(*mqlWindowsOptionalFeature)
	assert.Equal(t, "TelnetClient", telnet.GetName().Data)
	assert.False(t, telnet.GetEnabled().Data)

	displayName := smb.GetDisplayName()
	require.NoError(t, displayName.Error)
	assert.Equal(t, "SMB 1.0/CIFS File Sharing Support", displayName.Data)

	description := telnet.GetDescription()
	require.NoError(t, description.Error)
	assert.Equal(t, "Telnet Client uses the Telnet protocol", description.Data)

	assert.Equal(t, []string{listCmd, detailCmd}, conn.commands,
		"details are loaded once for the whole enumeration")
}

// A feature looked up by name never enumerates the image.
func TestInitOptionalFeatureUsesTargetedLookup(t *testing.T) {
	lookupCmd := powershell.Encode(windows.OptionalFeatureQuery("SMB1Protocol"))

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			lookupCmd: {Stdout: `{
				"FeatureName": "SMB1Protocol",
				"DisplayName": "SMB 1.0/CIFS File Sharing Support",
				"Description": "Support for the SMB 1.0/CIFS file sharing protocol",
				"State": 2
			}`},
		},
	}))
	require.NoError(t, err)

	conn := &optionalFeatureRecordingConnection{Connection: mockConn}
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	args, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
		"name": llx.StringData("SMB1Protocol"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{lookupCmd}, conn.commands)
	assert.Equal(t, "SMB 1.0/CIFS File Sharing Support", args["displayName"].Value)
	assert.Equal(t, int64(2), args["state"].Value)
	assert.Equal(t, true, args["enabled"].Value)
}

func newOptionalFeatureRuntime(t *testing.T, commands map[string]*mock.Command) (*plugin.Runtime, *optionalFeatureRecordingConnection) {
	t.Helper()
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)

	conn := &optionalFeatureRecordingConnection{Connection: mockConn}
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}, conn
}

// Every lookup of a feature runs the resource's init, so the same name read
// from several checks must not start Get-WindowsOptionalFeature each time.
func TestInitOptionalFeatureQueriesEachNameOnce(t *testing.T) {
	smbCmd := powershell.Encode(windows.OptionalFeatureQuery("SMB1Protocol"))
	telnetCmd := powershell.Encode(windows.OptionalFeatureQuery("TelnetClient"))
	runtime, conn := newOptionalFeatureRuntime(t, map[string]*mock.Command{
		smbCmd:    {Stdout: `{"FeatureName": "SMB1Protocol", "DisplayName": "SMB 1.0/CIFS File Sharing Support", "Description": "SMB 1.0", "State": 0}`},
		telnetCmd: {Stdout: `{"FeatureName": "TelnetClient", "DisplayName": "Telnet Client", "Description": "Telnet", "State": 2}`},
	})

	for range 3 {
		args, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
			"name": llx.StringData("SMB1Protocol"),
		})
		require.NoError(t, err)
		assert.Equal(t, "SMB1Protocol", args["name"].Value)
		assert.Equal(t, false, args["enabled"].Value)
		assert.Equal(t, int64(0), args["state"].Value)
		assert.Equal(t, "SMB 1.0/CIFS File Sharing Support", args["displayName"].Value)
	}

	args, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
		"name": llx.StringData("TelnetClient"),
	})
	require.NoError(t, err)
	assert.Equal(t, true, args["enabled"].Value)

	assert.Equal(t, []string{smbCmd, telnetCmd}, conn.commands, "one query per distinct name")
}

// Concurrent lookups of one name wait for the first query instead of
// starting their own, and lookups of other names are not held up by it.
func TestInitOptionalFeatureConcurrentLookups(t *testing.T) {
	smbCmd := powershell.Encode(windows.OptionalFeatureQuery("SMB1Protocol"))
	telnetCmd := powershell.Encode(windows.OptionalFeatureQuery("TelnetClient"))
	runtime, conn := newOptionalFeatureRuntime(t, map[string]*mock.Command{
		smbCmd:    {Stdout: `{"FeatureName": "SMB1Protocol", "DisplayName": "SMB 1.0/CIFS File Sharing Support", "Description": "SMB 1.0", "State": 0}`},
		telnetCmd: {Stdout: `{"FeatureName": "TelnetClient", "DisplayName": "Telnet Client", "Description": "Telnet", "State": 2}`},
	})

	// the windows resource that holds the cache, as a scan has it by then
	_, err := NewResource(runtime, "windows", nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 8 {
		name := "SMB1Protocol"
		if i%2 == 1 {
			name = "TelnetClient"
		}
		wg.Go(func() {
			args, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
				"name": llx.StringData(name),
			})
			assert.NoError(t, err)
			assert.Equal(t, name, args["name"].Value)
		})
	}
	wg.Wait()

	assert.ElementsMatch(t, []string{smbCmd, telnetCmd}, conn.commands, "one query per distinct name")
}

// A name the image does not have fails every lookup, but is queried once.
// Get-WindowsOptionalFeature answers an unknown name with exit 0 and no output
// (Windows 10, elevated).
func TestInitOptionalFeatureRemembersNotFound(t *testing.T) {
	missingCmd := powershell.Encode(windows.OptionalFeatureQuery("NoSuchFeature"))
	runtime, conn := newOptionalFeatureRuntime(t, map[string]*mock.Command{
		missingCmd: {Stdout: ""},
	})

	for range 2 {
		_, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
			"name": llx.StringData("NoSuchFeature"),
		})
		require.EqualError(t, err, "could not find feature NoSuchFeature")
	}
	assert.Equal(t, []string{missingCmd}, conn.commands)
}

// DISM expands `*` and `?` in -FeatureName, so only an exact name match counts,
// also when the outcome comes from the cache.
func TestInitOptionalFeatureRequiresExactName(t *testing.T) {
	wildcardCmd := powershell.Encode(windows.OptionalFeatureQuery("SMB1*"))
	runtime, conn := newOptionalFeatureRuntime(t, map[string]*mock.Command{
		wildcardCmd: {Stdout: `[
			{"FeatureName": "SMB1Protocol", "State": 0},
			{"FeatureName": "SMB1Protocol-Client", "State": 0}
		]`},
	})

	for range 2 {
		_, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
			"name": llx.StringData("SMB1*"),
		})
		require.EqualError(t, err, "could not find feature SMB1*")
	}
	assert.Equal(t, []string{wildcardCmd}, conn.commands)
}

// A query that fails (no elevation, a DISM error) is not an absent feature:
// every lookup reports the failure and queries again, so a transient error
// does not stick for the rest of the scan.
func TestInitOptionalFeatureDoesNotCacheFailedQuery(t *testing.T) {
	smbCmd := powershell.Encode(windows.OptionalFeatureQuery("SMB1Protocol"))
	runtime, conn := newOptionalFeatureRuntime(t, map[string]*mock.Command{
		smbCmd: {ExitStatus: 1, Stderr: "Get-WindowsOptionalFeature : The requested operation requires elevation.\r\n    + CategoryInfo          : NotSpecified: (:) [Get-WindowsOptionalFeature], COMException\r\n"},
	})

	for range 2 {
		_, _, err := initWindowsOptionalFeature(runtime, map[string]*llx.RawData{
			"name": llx.StringData("SMB1Protocol"),
		})
		require.EqualError(t, err, "could not query optional feature SMB1Protocol: The requested operation requires elevation.")
	}
	assert.Equal(t, []string{smbCmd, smbCmd}, conn.commands, "a failed query is run again")
}
