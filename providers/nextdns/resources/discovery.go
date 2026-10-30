// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nextdns/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.NextdnsConnection)
	conf := conn.Asset().Connections[0]

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conf.Discover.Targets)
	for _, target := range targets {
		switch target {
		case connection.DiscoveryAccounts:
			asset := &inventory.Asset{
				PlatformIds: []string{connection.NewNextdnsAccountIdentifier(conn.AccountID())},
				Name:        "NextDNS Account",
				Platform:    connection.NewNextdnsAccountPlatform(conn.AccountID()),
				Labels:      map[string]string{},
				Connections: []*inventory.Config{conf.Clone(
					inventory.WithoutDiscovery(),
					inventory.WithParentConnectionId(conn.ID()),
				)},
			}
			in.Spec.Assets = append(in.Spec.Assets, asset)

		case connection.DiscoveryProfiles:
			profiles, err := fetchProfiles(conn)
			if err != nil {
				return nil, err
			}
			for _, p := range profiles {
				childConf := conf.Clone(
					inventory.WithoutDiscovery(),
					inventory.WithParentConnectionId(conn.ID()),
				)
				if childConf.Options == nil {
					childConf.Options = map[string]string{}
				}
				childConf.Options[connection.OptionProfile] = p.ID

				name := p.Name
				if name == "" {
					name = p.ID
				}
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewNextdnsProfileIdentifier(p.ID)},
					Name:        name,
					Platform:    connection.NewNextdnsProfilePlatform(p.ID),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{childConf},
				}
				in.Spec.Assets = append(in.Spec.Assets, asset)
			}
		}
	}

	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll) {
		return []string{
			connection.DiscoveryAccounts,
			connection.DiscoveryProfiles,
		}
	}
	// "auto" is the default, and it intentionally omits the account asset. The
	// NextDNS API currently exposes no account-level information (no
	// subscription status, 2FA status, or owner email; the account id is only a
	// synthetic fingerprint of the API key), so discovering the account by
	// default would just add an empty asset. It stays reachable through an
	// explicit `--discover accounts` (or `--discover all`).
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryProfiles,
		}
	}
	return targets
}
