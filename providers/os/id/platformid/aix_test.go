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

func TestAixIdProvider(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			// AIX 7.3 TL4 SP2
			"lsattr -El sys0 -a os_uuid -F value": {Stdout: "4c3a5e1f-0000-4000-8000-000000000001\n"},
		},
	}))
	require.NoError(t, err)

	pf := &inventory.Platform{Name: "aix", Family: []string{"unix", "os"}}
	provider, err := MachineIDProvider(conn, pf)
	require.NoError(t, err)
	require.NotNil(t, provider)

	id, err := provider.ID()
	require.NoError(t, err)
	assert.Equal(t, "4c3a5e1f-0000-4000-8000-000000000001", id)
}

func TestParseAixOsUUID(t *testing.T) {
	for _, raw := range []string{"", "\n", "00000000-0000-0000-0000-000000000000\n"} {
		_, err := parseAixOsUUID(raw)
		assert.Error(t, err, raw)
	}
}
