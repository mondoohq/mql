// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container

import (
	"errors"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/discovery/container_registry"
)

var _ shared.Connection = &RegistryConnection{}

type RegistryConnection struct {
	plugin.Connection
	asset *inventory.Asset
}

func (r *RegistryConnection) Capabilities() shared.Capabilities {
	return shared.Capabilities(0)
}

func (r *RegistryConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, plugin.ErrFileInfoNotImplemented
}

func (r *RegistryConnection) FileSystem() afero.Fs {
	panic("unimplemented")
}

func (r *RegistryConnection) RunCommand(command string) (*shared.Command, error) {
	return nil, errors.New("unimplemented")
}

func (r *RegistryConnection) Type() shared.ConnectionType {
	return shared.Type_ContainerRegistry
}

func (r *RegistryConnection) UpdateAsset(asset *inventory.Asset) {
	r.asset = asset
}

func NewRegistryConnection(id uint32, asset *inventory.Asset) (*RegistryConnection, error) {
	conn := &RegistryConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
	}

	return conn, nil
}

func (r *RegistryConnection) Name() string {
	return "container-registry"
}

func (r *RegistryConnection) ID() uint32 {
	return r.Connection.ID()
}

func (r *RegistryConnection) ParentID() uint32 {
	return r.Connection.ParentID()
}

func (r *RegistryConnection) Close() error {
	return nil
}

func (r *RegistryConnection) Asset() *inventory.Asset {
	return r.asset
}

func (r *RegistryConnection) DiscoverImages() (*inventory.Inventory, error) {
	opts, err := container_registry.RemoteOptionsFromConfigOptions(r.asset.Connections[0])
	if err != nil {
		return nil, err
	}

	resolver := container_registry.NewImageLister(opts...)
	host := r.asset.Connections[0].Host
	assets, err := resolver.ListImages(host)
	if err != nil {
		return nil, err
	}
	return inventory.New(inventory.WithAssets(assets...)), nil
}
