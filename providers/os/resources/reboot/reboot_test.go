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

func TestRebootOnUbuntu(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/ubuntu_reboot.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"linux", "debian", "ubuntu"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb, err := New(mock)
	require.NoError(t, err)

	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.Equal(t, true, required)
}

func TestRebootOnRhel(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/redhat_kernel_reboot.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "redhat",
			Family: []string{"linux", "redhat"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb, err := New(mock)
	require.NoError(t, err)

	required, err := lb.RebootPending()
	require.NoError(t, err)

	assert.Equal(t, true, required)
}

// openEuler, EulerOS and Huawei Cloud EulerOS are rpm distributions in their
// own euler family, outside redhat, and were reported as unsupported.
func TestRebootOnEulerFamily(t *testing.T) {
	for _, name := range []string{"openeuler", "euleros", "hce"} {
		t.Run(name, func(t *testing.T) {
			conn, err := mock.New(0, &inventory.Asset{
				Platform: &inventory.Platform{
					Name:   name,
					Family: []string{"euler", "linux", "unix", "os"},
				},
			}, mock.WithData(&mock.TomlData{}))
			require.NoError(t, err)

			lb, err := New(conn)
			require.NoError(t, err)
			assert.IsType(t, &RpmNewestKernel{}, lb)
		})
	}
}

func TestRebootOnWindows(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/windows_reboot.toml")
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithPath(filepath))
	require.NoError(t, err)

	lb, err := New(mock)
	require.NoError(t, err)

	required, err := lb.RebootPending()
	require.NoError(t, err)
	assert.Equal(t, true, required)
}
