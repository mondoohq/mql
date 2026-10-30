// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/providers/alicloud/resources"
)

// discover runs fine-grained asset discovery for the account connection,
// returning one child asset per discovered service object. It is a no-op when
// discovery is disabled on the connection.
func (s *Service) discover(conn *connection.AlicloudConnection) (*inventory.Inventory, error) {
	conns := conn.Asset().Connections
	if len(conns) == 0 {
		return nil, nil
	}
	conf := conns[0]
	if conf.Discover == nil {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conf)
}
