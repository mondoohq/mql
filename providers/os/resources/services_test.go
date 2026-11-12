// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// windowsServiceConnection answers every command with the Get-Service output
// in stdout, or fails it with err.
type windowsServiceConnection struct {
	*mock.Connection
	stdout []byte
	err    error

	mu       sync.Mutex
	commands int
}

func (c *windowsServiceConnection) RunCommand(command string) (*shared.Command, error) {
	c.mu.Lock()
	c.commands++
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	return &shared.Command{
		Command: command,
		Stdout:  bytes.NewBuffer(append([]byte(nil), c.stdout...)),
		Stderr:  &bytes.Buffer{},
	}, nil
}

func newWindowsServiceRuntime(t *testing.T, stdout []byte, err error) (*plugin.Runtime, *windowsServiceConnection) {
	t.Helper()
	mockConn, mockErr := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "windows",
			Version: "10.0.17763",
			Family:  []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{}))
	require.NoError(t, mockErr)

	conn := &windowsServiceConnection{Connection: mockConn, stdout: stdout, err: err}
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}, conn
}

func lookupService(t *testing.T, runtime *plugin.Runtime, name string) *mqlService {
	t.Helper()
	_, res, err := initService(runtime, map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	return res.(*mqlService)
}

func TestInitServiceWindowsListsOnce(t *testing.T) {
	stdout, err := os.ReadFile("services/testdata/windows2019.json")
	require.NoError(t, err)
	runtime, conn := newWindowsServiceRuntime(t, stdout, nil)

	cryptSvc := lookupService(t, runtime, "CryptSvc")
	assert.Equal(t, "CryptSvc", cryptSvc.Name.Data)
	assert.True(t, cryptSvc.Installed.Data)
	assert.True(t, cryptSvc.Running.Data)
	assert.True(t, cryptSvc.Enabled.Data)
	assert.Equal(t, "windows", cryptSvc.Type.Data)

	policyAgent := lookupService(t, runtime, "PolicyAgent")
	assert.True(t, policyAgent.Installed.Data)
	assert.False(t, policyAgent.Running.Data)
	assert.True(t, policyAgent.Enabled.Data)
	assert.Contains(t, policyAgent.Description.Data, "IPsec")

	phoneSvc := lookupService(t, runtime, "PhoneSvc.service")
	assert.Equal(t, "PhoneSvc", phoneSvc.Name.Data)
	assert.False(t, phoneSvc.Enabled.Data)

	for _, name := range []string{"nginx", "sshd", "cryptsvc"} {
		missing := lookupService(t, runtime, name)
		assert.Equal(t, name, missing.Name.Data)
		assert.False(t, missing.Installed.Data)
		assert.False(t, missing.Running.Data)
		assert.False(t, missing.Enabled.Data)
		assert.True(t, missing.Description.IsNull())
	}

	assert.Same(t, cryptSvc, lookupService(t, runtime, "CryptSvc"))
	assert.Equal(t, 1, conn.commands)
}

func TestInitServiceWindowsConcurrent(t *testing.T) {
	stdout, err := os.ReadFile("services/testdata/windows2019.json")
	require.NoError(t, err)
	runtime, conn := newWindowsServiceRuntime(t, stdout, nil)

	names := []string{"CryptSvc", "Power", "nginx", "wuauserv", "sshd", "PlugPlay"}
	var wg sync.WaitGroup
	for range 4 {
		for _, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, res, err := initService(runtime, map[string]*llx.RawData{
					"name": llx.StringData(name),
				})
				assert.NoError(t, err)
				assert.NotNil(t, res)
			}()
		}
	}
	wg.Wait()
	assert.Equal(t, 1, conn.commands)
}

func TestInitServiceWindowsListError(t *testing.T) {
	cmdErr := errors.New("powershell failed")
	runtime, _ := newWindowsServiceRuntime(t, nil, cmdErr)

	_, res, err := initService(runtime, map[string]*llx.RawData{
		"name": llx.StringData("CryptSvc"),
	})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.ErrorIs(t, err, cmdErr)
}

type serviceRecordingConnection struct {
	*mock.Connection
	commands []string
}

func (c *serviceRecordingConnection) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

func TestInitServiceUsesTargetedLookup(t *testing.T) {
	const showCmd = "systemctl show --property=Id,Names,LoadState,ActiveState,UnitFileState,Description dbus.service"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "ubuntu",
			Version: "22.04",
			Family:  []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=dbus.service",
					"Description=D-Bus System Message Bus",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
		Files: map[string]*mock.MockFileData{
			"/sbin/init": {
				Path: "/sbin/init",
				StatData: mock.FileInfo{
					Mode: 0o755,
					Size: 1,
				},
			},
		},
	}))
	require.NoError(t, err)

	conn := &serviceRecordingConnection{Connection: mockConn}
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	_, res, err := initService(runtime, map[string]*llx.RawData{
		"name": llx.StringData("dbus"),
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	svc := res.(*mqlService)
	assert.Equal(t, "dbus", svc.Name.Data)
	assert.True(t, svc.Installed.Data)
	assert.True(t, svc.Running.Data)
	assert.True(t, svc.Enabled.Data)
	assert.Equal(t, []string{showCmd}, conn.commands)
}
