// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func dfMockRuntime(t *testing.T, df *mock.Command) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "solaris", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{"df -P -k": df},
		Files:    map[string]*mock.MockFileData{},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// An unprivileged df on Solaris 11.4 cannot stat /var/share/sstore/repo,
// exits 1, and still prints every other mount (abridged from a real run). A
// single unreadable mount point used to cost every mount its size.
func TestDfPartialOutput(t *testing.T) {
	runtime := dfMockRuntime(t, &mock.Command{
		Stdout: "Filesystem           1024-blocks        Used   Available Capacity  Mounted on\n" +
			"rpool/ROOT/11.4.86.201.2    51331392     1291512    39406676     4%    /\n" +
			"swap                   15333840         188    15333652     1%    /tmp\n",
		Stderr:     "df: cannot statvfs /var/share/sstore/repo: Permission denied\n",
		ExitStatus: 1,
	})

	obj, err := CreateResource(runtime, "mount", nil)
	require.NoError(t, err)
	entries, err := obj.(*mqlMount).fetchDfEntries()
	require.NoError(t, err)

	require.Contains(t, entries, "/tmp")
	assert.Equal(t, int64(15333840*1024), entries["/tmp"].Size)
	assert.Contains(t, entries, "/")
}

// A df that prints nothing at all could not answer: no capacity, no error.
func TestDfFailedOutright(t *testing.T) {
	runtime := dfMockRuntime(t, &mock.Command{
		Stderr:     "sh: df: not found\n",
		ExitStatus: 127,
	})

	obj, err := CreateResource(runtime, "mount", nil)
	require.NoError(t, err)
	entries, err := obj.(*mqlMount).fetchDfEntries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}
