// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// Solaris used to reach the machine id through the linux family. It is not in
// that family, and losing the id would change the asset's platform ids.
func TestMachineIDProviderSolaris(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			// Oracle Solaris 11.4.86, which has no /etc/machine-id
			"/var/lib/dbus/machine-id": {Data: []byte("19e8c9fa26340934f60e1a526ad98be4\n")},
		},
	}))
	require.NoError(t, err)

	pf := &inventory.Platform{Name: "solaris", Family: []string{"unix", "os"}}
	provider, err := MachineIDProvider(conn, pf)
	require.NoError(t, err)
	require.NotNil(t, provider)

	id, err := provider.ID()
	require.NoError(t, err)
	assert.Equal(t, "19e8c9fa26340934f60e1a526ad98be4", id)
}
