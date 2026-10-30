// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Helpers shared by more than one resource's tests. Anything used by a single
// resource belongs in that resource's own <resource>_test.go instead.
package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
)

// mockConn implements shared.Connection with only the Asset() method populated.
type mockConn struct {
	asset *inventory.Asset
}

func (m *mockConn) ID() uint32                                         { return 0 }
func (m *mockConn) ParentID() uint32                                   { return 0 }
func (m *mockConn) RunCommand(command string) (*shared.Command, error) { return nil, nil }
func (m *mockConn) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}
func (m *mockConn) FileSystem() afero.Fs               { return nil }
func (m *mockConn) Name() string                       { return "mock" }
func (m *mockConn) Type() shared.ConnectionType        { return "mock" }
func (m *mockConn) Asset() *inventory.Asset            { return m.asset }
func (m *mockConn) UpdateAsset(asset *inventory.Asset) {}
func (m *mockConn) Capabilities() shared.Capabilities  { return 0 }

// connWithPlatform returns a mockConn with the given platform name set.
func connWithPlatform(name string) *mockConn {
	return &mockConn{
		asset: &inventory.Asset{
			Platform: &inventory.Platform{
				Name: name,
			},
		},
	}
}

// The fixtures under testdata/windows-registry are verbatim output of the two
// PowerShell collection scripts the registrykey resource runs
// (GetRegistryKeyItemScript and GetRegistryKeyChildItemsScript), captured from
// four stock Windows Server hosts over SSH. They carry no host name, no
// machine-unique SID, and no address.
//
// They exist so the pure decode functions behind windows.lsa and
// windows.schannel are exercised against what Windows actually writes, rather
// than against hand-built maps that agree with the implementation by
// construction.
const windowsRegistryFixtureDir = "./testdata/windows-registry"

var windowsFixtureVersions = []string{"ws2016", "ws2019", "ws2022", "ws2025"}

// loadFixtureItems parses a captured registry-value listing and lower-cases the
// value names exactly as readLsaKey and readSchannelKey do.
func loadFixtureItems(t *testing.T, version, name string) map[string]registry.RegistryKeyItem {
	t.Helper()

	f, err := os.Open(filepath.Join(windowsRegistryFixtureDir, version, name+".json"))
	require.NoError(t, err)
	defer f.Close()

	entries, err := registry.ParsePowershellRegistryKeyItems(f)
	require.NoError(t, err)

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res
}

func loadFixtureChildren(t *testing.T, version, name string) []registry.RegistryKeyChild {
	t.Helper()

	f, err := os.Open(filepath.Join(windowsRegistryFixtureDir, version, name+".json"))
	require.NoError(t, err)
	defer f.Close()

	children, err := registry.ParsePowershellRegistryKeyChildren(f)
	require.NoError(t, err)
	return children
}
