// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"github.com/pkg/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/atlassian/connection/admin"
	"go.mondoo.com/mql/providers/atlassian/connection/confluence"
	"go.mondoo.com/mql/providers/atlassian/connection/jira"
	"go.mondoo.com/mql/providers/atlassian/connection/scim"
	"go.mondoo.com/mql/providers/atlassian/connection/shared"
)

const (
	DiscoveryOrganization = "organization"
)

const (
	Admin shared.ConnectionType = "atlassian"
)

func NewConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (shared.Connection, error) {
	var conn shared.Connection
	var err error
	switch conf.Options["product"] {
	case "admin":
		conn, err = admin.NewConnection(id, asset, conf)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create admin connection")
		}
	case "jira":
		conn, err = jira.NewConnection(id, asset, conf)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create Jira connection")
		}
	case string(confluence.Confluence):
		conn, err = confluence.NewConnection(id, asset, conf)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create Confluence connection")
		}
	case "scim":
		conn, err = scim.NewConnection(id, asset, conf)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create SCIM connection")
		}
	}
	return conn, nil
}
