// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/providers/databricks/resources"
)

func (s *Service) discover(conn *connection.DatabricksConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// Only the account plane discovers child assets (workspaces).
	if conn.Plane() != connection.PlaneAccount {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conf.Options)
}
