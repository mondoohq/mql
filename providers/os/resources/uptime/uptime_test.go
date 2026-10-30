// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uptime_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/uptime"
)

func TestUptimeOnLinux(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/linux.toml"))
	require.NoError(t, err)

	ut, err := uptime.New(mock)
	require.NoError(t, err)

	required, err := ut.Duration()
	require.NoError(t, err)
	assert.Equal(t, "19m0s", required.String())
}

func TestUptimeOnLinuxLcDecimalDe(t *testing.T) {
	// LC_NUMERIC=de_DE.UTF-8 on Ubuntu 22.04
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/linux_de.toml"))
	require.NoError(t, err)

	ut, err := uptime.New(mock)
	require.NoError(t, err)

	required, err := ut.Duration()
	require.NoError(t, err)
	assert.Equal(t, "38h31m0s", required.String())
}

func TestUptimeOnFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"unix"},
		},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	ut, err := uptime.New(mock)
	require.NoError(t, err)

	required, err := ut.Duration()
	require.NoError(t, err)

	assert.Equal(t, "24m0s", required.String())
}

func TestUptimeOnWindows(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Family: []string{"windows"},
		},
	}, mock.WithPath("./testdata/windows.toml"))
	require.NoError(t, err)

	ut, err := uptime.New(mock)
	require.NoError(t, err)

	required, err := ut.Duration()
	require.NoError(t, err)

	assert.Equal(t, "3m45.8270365s", required.String())
}
