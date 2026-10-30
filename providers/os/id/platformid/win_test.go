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

// PowerShell terminates its output with CRLF. Returning it untrimmed put the
// line ending into the machine id, and from there into the asset identifier
// built in id/platform.go.
func TestPowershellWindowsMachineIdTrimsLineEnding(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}},
	}, mock.WithPath("./testdata/windows_machineid.toml"))
	require.NoError(t, err)

	guid, err := PowershellWindowsMachineId(conn)
	require.NoError(t, err)

	assert.Equal(t, "03ED6348-E1A9-4DE1-AA28-0CFEDB954237", guid)
	assert.NotContains(t, guid, "\r")
	assert.NotContains(t, guid, "\n")
}
