// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/provisioning"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover enumerates the account's workspaces and emits each as a child asset
// connected to that workspace's API plane.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.DatabricksConnection)
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}

	acc := conn.Account()
	if acc == nil {
		return in, nil
	}

	conf := conn.Asset().Connections[0]
	if conf.Discover == nil ||
		!stringx.ContainsAnyOf(conf.Discover.Targets, connection.DiscoveryAll, connection.DiscoveryAuto, connection.DiscoveryWorkspaces) {
		return in, nil
	}

	workspaces, err := acc.Workspaces.List(context.Background())
	if err != nil {
		return in, err
	}

	for i := range workspaces {
		ws := workspaces[i]
		workspaceID := strconv.FormatInt(ws.WorkspaceId, 10)

		// Clone preserves the OAuth credentials and options (including client-id);
		// we then flip the clone to the workspace plane and drop the account id so
		// the child connects as a single workspace rather than the account.
		wsConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if wsConf.Options == nil {
			wsConf.Options = map[string]string{}
		}
		wsConf.Options[connection.OptionPlane] = connection.PlaneWorkspace
		wsConf.Options[connection.OptionHost] = workspaceHost(acc, ws)
		wsConf.Options[connection.OptionWorkspaceID] = workspaceID
		delete(wsConf.Options, connection.OptionAccountID)

		asset := &inventory.Asset{
			PlatformIds: []string{connection.NewDatabricksWorkspaceIdentifier(workspaceID)},
			Name:        ws.WorkspaceName,
			Platform:    connection.NewDatabricksWorkspacePlatform(workspaceID),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{wsConf},
		}
		in.Spec.Assets = append(in.Spec.Assets, asset)
	}

	return in, nil
}

// workspaceHost derives a workspace's API host from the account configuration,
// matching the SDK's own per-cloud deployment URL logic.
func workspaceHost(acc *databricks.AccountClient, ws provisioning.Workspace) string {
	env := acc.Config.Environment()
	if env.DnsZone == "" {
		return acc.Config.Host
	}
	return env.DeploymentURL(ws.DeploymentName)
}
