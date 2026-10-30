// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.TailscaleConnection)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Asset().Connections[0].Discover.Targets)
	list, err := discover(runtime, targets)
	if err != nil {
		return in, err
	}

	in.Spec.Assets = list
	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryDevices,
			connection.DiscoveryUsers,
		}
	}
	return targets
}

func discover(runtime *plugin.Runtime, targets []string) ([]*inventory.Asset, error) {
	conn := runtime.Connection.(*connection.TailscaleConnection)
	conf := conn.Asset().Connections[0]
	assetList := []*inventory.Asset{}

	cf, err := getMqlTailscale(runtime)
	if err != nil {
		return nil, err
	}

	for _, target := range targets {
		switch target {
		case connection.DiscoveryUsers:
			users, err := cf.users()
			if err != nil {
				return nil, err
			}
			for _, resource := range users {
				user := resource.(*mqlTailscaleUser)
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewTailscaleUserIdentifier(user.Id.Data)},
					Name:        user.DisplayName.Data,
					Platform:    connection.NewTailscaleUserPlatform(user.Id.Data),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{
						conf.Clone(
							inventory.WithoutDiscovery(),
							inventory.WithParentConnectionId(conn.ID()),
						),
					},
				}
				assetList = append(assetList, asset)
			}

		case connection.DiscoveryDevices:
			devices, err := cf.devices()
			if err != nil {
				return nil, err
			}
			for _, resource := range devices {
				device := resource.(*mqlTailscaleDevice)
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewTailscaleDeviceIdentifier(device.Id.Data)},
					Name:        device.Hostname.Data,
					Platform:    connection.NewTailscaleDevicePlatform(device.Id.Data),
					Labels:      map[string]string{}, // can we use device.tags here?
					Connections: []*inventory.Config{
						conf.Clone(
							inventory.WithoutDiscovery(),
							inventory.WithParentConnectionId(conn.ID()),
						),
					},
				}
				assetList = append(assetList, asset)
			}
		default:
			continue
		}
	}

	return assetList, nil
}

// getMqlTailscale returns the tailnet resource discovery lists devices and
// users from. It goes through NewResource so the resource's init runs and its
// tailnet, and therefore its cache key, is populated. Building it with the raw
// constructor would leave both empty.
func getMqlTailscale(runtime *plugin.Runtime) (*mqlTailscale, error) {
	res, err := NewResource(runtime, "tailscale", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	return res.(*mqlTailscale), nil
}
