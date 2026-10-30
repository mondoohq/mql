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

// ALT Linux is rpm based but is not in the redhat family: it ships
// /etc/redhat-release and /etc/fedora-release carrying only "ALT Container", so
// detection gives it a resolver of its own under plain linux. Without a case of
// its own it matched nothing here, and packages errored on a system with a
// populated rpm database.
func TestResolveSystemPkgManagersAltLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "altlinux",
			Version: "11",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/packages_alt.toml"))
	require.NoError(t, err)

	pms, err := ResolveSystemPkgManagers(conn)
	require.NoError(t, err, "ALT Linux has an rpm database, so a manager must resolve")
	require.Len(t, pms, 1)
	assert.Equal(t, "Rpm Package Manager", pms[0].Name())
}
