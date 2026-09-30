// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/services"
	"go.mondoo.com/mql/utils/syncx"
)

type serviceRecordingConnection struct {
	*mock.Connection
	commands []string
}

func (c *serviceRecordingConnection) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

func TestInitServiceUsesTargetedLookup(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description dbus.service"

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

// A value the service manager could not read is null, not false: a service
// the scanner may not query must not pass as disabled or stopped.
func TestCreateServiceResourceUnknownIsNull(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	res, err := createServiceResource(runtime, &services.Service{
		Name: "Locked", Installed: true, Running: true, Type: "windows", ConfigUnknown: true,
	})
	require.NoError(t, err)
	svc := res.(*mqlService)
	assert.True(t, svc.Running.Data)
	assert.True(t, svc.Enabled.IsNull(), "enabled of a service whose configuration could not be read")
	assert.True(t, svc.Description.IsNull(), "description of a service whose configuration could not be read")

	res, err = createServiceResource(runtime, &services.Service{
		Name: "Hidden", Installed: true, Type: "windows", StatusUnknown: true, ConfigUnknown: true,
	})
	require.NoError(t, err)
	svc = res.(*mqlService)
	assert.True(t, svc.Running.IsNull(), "running of a service whose state could not be read")
	assert.True(t, svc.Enabled.IsNull())

	res, err = createServiceResource(runtime, &services.Service{Name: "Known", Installed: true, Enabled: false, Type: "windows"})
	require.NoError(t, err)
	svc = res.(*mqlService)
	assert.False(t, svc.Enabled.IsNull())
	assert.False(t, svc.Enabled.Data)
}
