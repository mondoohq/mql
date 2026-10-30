// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseUpstartServicesRunning(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"linux", "ubuntu"},
		},
	}, mock.WithPath("./testdata/ubuntu1404.toml"))
	require.NoError(t, err)

	upstart := UpstartServiceManager{SysVServiceManager{conn: mock}}

	// iterate over services and check if they are running
	services, err := upstart.List()
	require.NoError(t, err)
	assert.Equal(t, 9, len(services), "detected the right amount of services")

	// Enabled comes from the runlevel links, which arrive through their own
	// find command. Nothing here asserted it, so when the fixture's key stopped
	// matching what sysv.go runs, the lookup returned nothing and every sysv
	// service reported Enabled=false with the count above still passing. A
	// disabled service is a real state, so "all false" has to be told from
	// "nothing was read" by asserting both.
	byName := map[string]*Service{}
	for _, s := range services {
		byName[s.Name] = s
	}

	ssh := byName["ssh"]
	require.NotNil(t, ssh, "ssh is a sysv service in this fixture")
	assert.True(t, ssh.Enabled, "ssh is linked into the multi-user runlevels")

	cron := byName["cron"]
	require.NotNil(t, cron, "cron is a sysv service in this fixture")
	assert.False(t, cron.Enabled, "cron is installed but linked into no runlevel")
}
