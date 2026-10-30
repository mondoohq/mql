// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestRebootLinux(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/ubuntu_reboot.toml")
	provider, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"linux", "debian", "ubuntu"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb := DebianReboot{conn: provider}
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.Equal(t, true, required)
}

func TestNoRebootLinux(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/ubuntu_noreboot.toml")
	provider, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"linux", "debian", "ubuntu"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb := DebianReboot{conn: provider}
	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.Equal(t, false, required)
}
