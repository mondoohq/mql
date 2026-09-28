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

func TestFreebsdKernelChanged(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		pending bool
	}{
		{
			// FreeBSD 13.5: freebsd-update patched userland to -p14 but left
			// the kernel at -p13, so the running kernel is the installed one
			name:    "userland newer than kernel",
			out:     "13.5-RELEASE-p13\n13.5-RELEASE-p13\n",
			pending: false,
		},
		{
			name:    "kernel patch installed, not booted",
			out:     "14.5-RELEASE-p1\n14.5-RELEASE\n",
			pending: true,
		},
		{
			name:    "kernel upgraded to a new release",
			out:     "15.1-RELEASE\n15.0-RELEASE-p4\n",
			pending: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pending, err := freebsdKernelChanged(tc.out)
			require.NoError(t, err)
			assert.Equal(t, tc.pending, pending)
		})
	}

	_, err := freebsdKernelChanged("14.5-RELEASE\n")
	assert.Error(t, err)
}

func TestRebootOnFreebsd(t *testing.T) {
	path, err := filepath.Abs("./testdata/freebsd_kernel_patched.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath(path))
	require.NoError(t, err)

	rb, err := New(conn)
	require.NoError(t, err)
	pending, err := rb.RebootPending()
	require.NoError(t, err)
	assert.True(t, pending)
}

// In a jail /boot is usually absent and freebsd-version -k fails. That is no
// answer, so it must not read as "no reboot pending".
func TestRebootOnFreebsdWithoutKernel(t *testing.T) {
	path, err := filepath.Abs("./testdata/freebsd_no_kernel.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "freebsd",
			Family: []string{"bsd", "unix", "os"},
		},
	}, mock.WithPath(path))
	require.NoError(t, err)

	rb, err := New(conn)
	require.NoError(t, err)
	_, err = rb.RebootPending()
	assert.ErrorContains(t, err, "unable to locate kernel")
}
