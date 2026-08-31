// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// CBL-Mariner 2.x is Azure Linux under its earlier name. It is rpm based but
// ships no /etc/redhat-release, so the redhat family declines it and it
// resolves as a platform of its own, the way azurelinux and amazonlinux do.
// Without a case naming it here nothing matched and packages reported an error
// on a system with a populated rpm database.
func TestResolveSystemPkgManagersMariner(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "mariner",
			Version: "2.0",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/packages_mariner.toml"))
	require.NoError(t, err)

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err, "CBL-Mariner has an rpm database, so a manager must resolve")
	require.Len(t, pms, 1)
	assert.IsType(t, &RpmPkgManager{}, pms[0])
	assert.Equal(t, "Rpm Package Manager", pms[0].Name())
}
