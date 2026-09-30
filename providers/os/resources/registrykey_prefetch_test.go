// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/utils/syncx"
)

// remoteWindowsConnection stands for a connection that reads the registry over
// PowerShell (SSH, WinRM): a mock that is not recognized as one, counting the
// commands it runs.
type remoteWindowsConnection struct {
	*mock.Connection
	commands atomic.Int32
}

func (c *remoteWindowsConnection) RunCommand(command string) (*shared.Command, error) {
	c.commands.Add(1)
	return c.Connection.RunCommand(command)
}

func newRemoteWindowsRuntime(t *testing.T, commands map[string]*mock.Command) (*plugin.Runtime, *remoteWindowsConnection) {
	t.Helper()
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "windows", Family: []string{"windows"}},
	}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	conn := &remoteWindowsConnection{Connection: mockConn}
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}, conn
}

// Reads under a prefetched root are answered from one script: values, a key
// without values, and a key that does not exist.
func TestRegistrykeyReadsFromPrefetch(t *testing.T) {
	prefetch := powershell.Encode(registry.PrefetchScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies`, registry.PrefetchMaxOutput))
	runtime, conn := newRemoteWindowsRuntime(t, map[string]*mock.Command{
		prefetch: {Stdout: `K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies"
V
K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
V[{"key":"EnableSmartScreen","value":{"data":1,"kind":null,"type":"REG_DWORD","hex":null}}]
K"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent"
V
D
`},
	})

	property := func(path, name string) *mqlRegistrykeyProperty {
		o, err := NewResource(runtime, "registrykey.property", map[string]*llx.RawData{
			"path": llx.StringData(path),
			"name": llx.StringData(name),
		})
		require.NoError(t, err)
		return o.(*mqlRegistrykeyProperty)
	}
	key := func(path string) *mqlRegistrykey {
		o, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		require.NoError(t, err)
		return o.(*mqlRegistrykey)
	}

	p := property(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System`, "EnableSmartScreen")
	assert.True(t, p.GetExists().Data)
	assert.Equal(t, int64(1), p.GetData().Data)
	assert.Equal(t, "dword", p.GetType().Data)

	// another spelling of the same key
	p = property(`HKLM\Software\Policies\Microsoft\Windows\System`, "enablesmartscreen")
	assert.True(t, p.GetExists().Data)

	// a key without values exists
	k := key(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent`)
	assert.True(t, k.GetExists().Data)
	assert.Empty(t, k.GetItems().Data)

	// a key the root was read without does not exist
	k = key(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`)
	assert.False(t, k.GetExists().Data)
	p = property(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`, "AllowBasic")
	assert.False(t, p.GetExists().Data)

	assert.Equal(t, int32(1), conn.commands.Load(), "one script for the root, no read per key")
}

// A key outside every root, or under a root whose prefetch failed, is read
// alone, as before.
func TestRegistrykeyFallsBackToSingleRead(t *testing.T) {
	single := powershell.Encode(registry.GetRegistryKeyItemScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`))
	lsa := powershell.Encode(registry.GetRegistryKeyItemScript(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`))
	runtime, conn := newRemoteWindowsRuntime(t, map[string]*mock.Command{
		single: {Stdout: `[{"key":"ProductName","value":{"data":"Windows Server 2022 Datacenter","kind":null,"type":"REG_SZ","hex":null}}]`},
		// the prefetch of the Lsa root fails
		powershell.Encode(registry.PrefetchScript(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`, registry.PrefetchMaxOutput)): {ExitStatus: 1},
		lsa: {Stdout: `[{"key":"LimitBlankPasswordUse","value":{"data":1,"kind":null,"type":"REG_DWORD","hex":null}}]`},
	})

	for path, name := range map[string]string{
		`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: "ProductName",
		`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`:         "LimitBlankPasswordUse",
	} {
		o, err := NewResource(runtime, "registrykey.property", map[string]*llx.RawData{
			"path": llx.StringData(path),
			"name": llx.StringData(name),
		})
		require.NoError(t, err)
		assert.True(t, o.(*mqlRegistrykeyProperty).GetExists().Data, path)
	}
	assert.Equal(t, int32(3), conn.commands.Load(), "the failed prefetch, then one read per key")
}

// Recordings replay the single-key reads they hold, so a mock connection is
// never prefetched.
func TestRegistryPrefetchSkipsMocks(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: mockConn, Resources: &syncx.Map[plugin.Resource]{}}
	assert.Nil(t, registryPrefetch(runtime))

	runtime, _ = newRemoteWindowsRuntime(t, nil)
	p := registryPrefetch(runtime)
	require.NotNil(t, p)
	assert.Same(t, p, registryPrefetch(runtime), "one prefetch per connection")
}
