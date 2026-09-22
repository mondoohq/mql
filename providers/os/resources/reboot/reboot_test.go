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

// TestRebootWithoutAPlatform covers an asset whose platform was never detected.
//
// The switch below used to read pf.Name in its first case, and pf comes straight
// off the asset. IsFamily is nil-safe and returns false, so a nil platform does
// not stop at the family checks -- it reaches the bare .Name read and panics.
// The plugin layer recovers that panic and answers the query with an error, so
// every check touching the resource reports "error" while the scan still exits
// 0: a wrong answer delivered confidently rather than a crash.
func TestRebootWithoutAPlatform(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{})
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err := New(conn)
		assert.Error(t, err, "an undetected platform is an error, not a reboot resolver")
	})
}
