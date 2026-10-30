// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/mongodbatlas/connection"
	"go.mondoo.com/mql/providers/mongodbatlas/resources"
)

func (s *Service) discover(conn *connection.MongoDBAtlasConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// Only the organization plane discovers child assets (projects).
	if conn.Plane() != connection.PlaneOrg {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conf.Options)
}
