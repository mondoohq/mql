// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/id/ids"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestGatherPlatformInfoAction1Endpoint(t *testing.T) {
	const (
		endpoint = "e6b635e9-975f-4a5c-8115-ac626dbbcece"
		want     = "//platformid.api.mondoo.app/runtime/action1/endpoints/" + endpoint
		idFile   = "/var/opt/action1/agent_id.txt"
		macFile  = "/var/local/action1/agent_id.txt"
		script   = `(Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Action1' -Name 'agent.guid' -ErrorAction SilentlyContinue).'agent.guid'`
	)
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	windows := &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}}
	gather := func(t *testing.T, data *mock.TomlData, pf *inventory.Platform) []string {
		t.Helper()
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(data))
		require.NoError(t, err)
		info, err := gatherPlatformInfo(conn, pf, ids.IdDetector_Action1Endpoint)
		require.NoError(t, err)
		return info.IDs
	}
	fileAt := func(path, content string) *mock.TomlData {
		return &mock.TomlData{Files: map[string]*mock.MockFileData{path: {Path: path, Content: content}}}
	}
	file := func(content string) *mock.TomlData { return fileAt(idFile, content) }
	mac := &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}
	registry := func(stdout string) *mock.TomlData {
		return &mock.TomlData{Commands: map[string]*mock.Command{powershell.Encode(script): {Stdout: stdout}}}
	}

	t.Run("linux without an agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, &mock.TomlData{}, linux))
	})
	t.Run("linux reads the agent's id file", func(t *testing.T) {
		assert.Equal(t, []string{want}, gather(t, file(endpoint+"\n"), linux))
	})
	t.Run("an id in another case matches the API's form", func(t *testing.T) {
		assert.Equal(t, []string{want}, gather(t, file("E6B635E9-975F-4A5C-8115-AC626DBBCECE"), linux))
	})
	t.Run("a value that is not a GUID yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, file("not-an-endpoint"), linux))
	})
	t.Run("windows without an agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, registry(""), windows))
	})
	t.Run("windows reads the agent's registry value", func(t *testing.T) {
		assert.Equal(t, []string{want}, gather(t, registry(endpoint+"\r\n"), windows))
	})
	t.Run("macos without an agent yields no id", func(t *testing.T) {
		assert.Empty(t, gather(t, &mock.TomlData{}, mac))
	})
	t.Run("macos reads the agent's id file", func(t *testing.T) {
		assert.Equal(t, []string{want}, gather(t, fileAt(macFile, endpoint+"\n"), mac))
	})
	t.Run("macos does not read the linux path", func(t *testing.T) {
		assert.Empty(t, gather(t, file(endpoint), mac))
	})
	t.Run("a container yields no id", func(t *testing.T) {
		image := &inventory.Platform{Name: "ubuntu", Kind: "container-image", Family: []string{"debian", "linux", "unix", "os"}}
		assert.Empty(t, gather(t, file(endpoint), image))
	})
}
