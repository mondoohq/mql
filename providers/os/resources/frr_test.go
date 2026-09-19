// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frrMockConn adds a filesystem to mockConn so path discovery can be tested.
type frrMockConn struct {
	*mockConn
	fs afero.Fs
}

func (m *frrMockConn) FileSystem() afero.Fs { return m.fs }

func frrConnWithFiles(t *testing.T, paths ...string) *frrMockConn {
	t.Helper()
	fs := afero.NewMemMapFs()
	for _, p := range paths {
		require.NoError(t, afero.WriteFile(fs, p, []byte("hostname test\n"), 0o644))
	}
	return &frrMockConn{mockConn: connWithPlatform("ubuntu"), fs: fs}
}

// TestFrrConfPath_NativeAndContainerLayouts covers both execution shapes.
// FRR runs either on the host or inside a Host Based Networking container,
// and the same resource has to find the config in both cases.
func TestFrrConfPath_NativeAndContainerLayouts(t *testing.T) {
	tests := []struct {
		name    string
		present []string
		want    string
	}{
		{
			name:    "native host install",
			present: []string{"/etc/frr/frr.conf"},
			want:    "/etc/frr/frr.conf",
		},
		{
			name:    "scan inside the HBN container",
			present: []string{"/etc/frr/frr.conf", "/etc/frr/daemons"},
			want:    "/etc/frr/frr.conf",
		},
		{
			name:    "HBN container root seen from the host",
			present: []string{"/var/lib/hbn/etc/frr/frr.conf"},
			want:    "/var/lib/hbn/etc/frr/frr.conf",
		},
		{
			name:    "config rendered by the CRA agent",
			present: []string{"/etc/cra/frr.conf"},
			want:    "/etc/cra/frr.conf",
		},
		{
			name:    "source build under /usr/local",
			present: []string{"/usr/local/etc/frr/frr.conf"},
			want:    "/usr/local/etc/frr/frr.conf",
		},
		{
			name:    "native path wins over the container path",
			present: []string{"/etc/frr/frr.conf", "/var/lib/hbn/etc/frr/frr.conf"},
			want:    "/etc/frr/frr.conf",
		},
		{
			name:    "no config present falls back to the default path",
			present: nil,
			want:    "/etc/frr/frr.conf",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := frrConnWithFiles(t, tc.present...)
			got := firstExistingPath(conn, frrConfPaths, defaultFrrConf)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFrrVtyshConfPath(t *testing.T) {
	conn := frrConnWithFiles(t, "/var/lib/hbn/etc/frr/vtysh.conf")
	assert.Equal(t, "/var/lib/hbn/etc/frr/vtysh.conf",
		firstExistingPath(conn, frrVtyshConfPaths, defaultFrrVtyshConf))

	empty := frrConnWithFiles(t)
	assert.Equal(t, "/etc/frr/vtysh.conf",
		firstExistingPath(empty, frrVtyshConfPaths, defaultFrrVtyshConf))
}

func TestFrrVersionRegex(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "vtysh banner",
			in:   "FRRouting 8.5.4 (worker-01).\nCopyright 1996-2005 Kunihiro Ishiguro, et al.\n",
			want: "8.5.4",
		},
		{
			name: "package suffix is kept",
			in:   "FRRouting 10.3.1_git (leaf1).",
			want: "10.3.1_git",
		},
		{
			name: "unrelated output",
			in:   "command not found",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := reFrrVersion.FindStringSubmatch(tc.in)
			if tc.want == "" {
				assert.Nil(t, m)
				return
			}
			require.Len(t, m, 2)
			assert.Equal(t, tc.want, m[1])
		})
	}
}
