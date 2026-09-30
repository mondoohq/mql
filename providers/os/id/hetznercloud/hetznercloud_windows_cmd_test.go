// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hetznercloud

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

var windowsPlatform = &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}

// On Windows the metadata document is read with an encoded PowerShell
// script, not the Unix curl command line (curl is Invoke-WebRequest there,
// which rejects curl's flags).
func TestWindowsIdentify(t *testing.T) {
	cmd := powershell.Encode(windowsMetadataScript)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			cmd: {Stdout: "instance-id: 110512417\nhostname: win-8gb-hil-1\nregion: us-west\n"},
		},
	}))
	require.NoError(t, err)

	resolver, err := Resolve(conn, windowsPlatform)
	require.NoError(t, err)
	ident, err := resolver.Identify()
	require.NoError(t, err)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/hetzner/instances/110512417", ident.InstanceID)
	assert.Equal(t, "win-8gb-hil-1", ident.Hostname)
	assert.Equal(t, "us-west", ident.Region)
}

func TestWindowsMetadataCommand(t *testing.T) {
	m := &commandInstanceMetadata{platform: windowsPlatform}
	cmd := m.metadataCommand()
	assert.True(t, strings.HasPrefix(cmd, "powershell.exe -NoProfile -EncodedCommand "), cmd)
	assert.NotContains(t, cmd, "curl")
	assert.Contains(t, windowsMetadataScript, metadataSvcURL)

	linux := &commandInstanceMetadata{platform: &inventory.Platform{Name: "ubuntu", Family: []string{"linux", "unix", "os"}}}
	assert.True(t, strings.HasPrefix(linux.metadataCommand(), "curl "))
}

// A service that does not answer is an error, not an empty identity.
func TestWindowsIdentifyFails(t *testing.T) {
	cmd := powershell.Encode(windowsMetadataScript)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{cmd: {Stderr: "Unable to connect to the remote server", ExitStatus: 1}},
	}))
	require.NoError(t, err)
	resolver, err := Resolve(conn, windowsPlatform)
	require.NoError(t, err)
	_, err = resolver.Identify()
	require.Error(t, err)
}
