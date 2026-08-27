// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type typedConnection struct {
	shared.Connection
	connType shared.ConnectionType
}

func (c *typedConnection) Type() shared.ConnectionType { return c.connType }

// The docker client is built from the provider process's environment, so it
// reaches the daemon on the machine running mql. For a remote transport that
// daemon belongs to the scanner, not the asset.
func TestCheckDockerDaemonIsTheAssets(t *testing.T) {
	allowed := []shared.ConnectionType{
		shared.Type_Local,
		shared.Type_DockerContainer,
		shared.Type_DockerImage,
		shared.Type_DockerSnapshot,
		shared.Type_DockerFile,
		shared.Type_DockerRegistry,
		shared.Type_ContainerRegistry,
		shared.Type_RegistryImage,
		"mock",
	}
	for _, ct := range allowed {
		t.Run("allows "+ct.String(), func(t *testing.T) {
			runtime := &plugin.Runtime{Connection: &typedConnection{connType: ct}}
			require.NoError(t, checkDockerDaemonIsTheAssets(runtime))
		})
	}

	refused := []shared.ConnectionType{
		shared.Type_SSH,
		shared.Type_Winrm,
		shared.Type_Vagrant,
		shared.Type_FileSystem,
		shared.Type_Tar,
		shared.Type_Device,
	}
	for _, ct := range refused {
		t.Run("refuses "+ct.String(), func(t *testing.T) {
			runtime := &plugin.Runtime{Connection: &typedConnection{connType: ct}}
			err := checkDockerDaemonIsTheAssets(runtime)
			require.Error(t, err, "%s must not be served by the scanner's daemon", ct)
			assert.Contains(t, err.Error(), ct.String())
		})
	}
}
