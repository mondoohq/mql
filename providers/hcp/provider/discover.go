// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/hcp/connection"
	"go.mondoo.com/mql/providers/hcp/resources"
)

func (s *Service) discover(conn *connection.HcpConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// Only organization- and project-scoped connections discover children;
	// leaf resource assets do not re-discover.
	switch conn.Scope() {
	case connection.ScopeOrg, connection.ScopeProject:
	default:
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conf.Options)
}
