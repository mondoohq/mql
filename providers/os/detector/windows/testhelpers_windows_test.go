// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// mockLocalConnection implements shared.Connection and returns Type_Local.
// It is used by multiple test files in this package.
type mockLocalConnection struct{}

func (m *mockLocalConnection) ID() uint32                                         { return 0 }
func (m *mockLocalConnection) ParentID() uint32                                   { return 0 }
func (m *mockLocalConnection) RunCommand(command string) (*shared.Command, error) { return nil, nil }
func (m *mockLocalConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}
func (m *mockLocalConnection) FileSystem() afero.Fs               { return afero.NewOsFs() }
func (m *mockLocalConnection) Name() string                       { return "mock-local" }
func (m *mockLocalConnection) Type() shared.ConnectionType        { return shared.Type_Local }
func (m *mockLocalConnection) Asset() *inventory.Asset            { return &inventory.Asset{} }
func (m *mockLocalConnection) UpdateAsset(asset *inventory.Asset) {}
func (m *mockLocalConnection) Capabilities() shared.Capabilities {
	return shared.Capability_None
}
