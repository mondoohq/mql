// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// adminPrincipalIDs returns the set of principal IDs (users, groups, or service
// principals) that hold at least one active Microsoft Entra directory role
// assignment. The set is fetched once per connection (cached on the connection,
// so it is freed with it) so that microsoft.user.isAdministrator resolves from
// memory instead of issuing a request per user.
// requires RoleManagement.Read.Directory permission
func adminPrincipalIDs(runtime *plugin.Runtime) (map[string]struct{}, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)

	return conn.AdminPrincipalIDs(func() (map[string]struct{}, error) {
		graphClient, err := conn.GraphClient()
		if err != nil {
			return nil, err
		}

		ctx := context.Background()
		resp, err := graphClient.RoleManagement().Directory().RoleAssignments().Get(ctx, nil)
		if err != nil {
			return nil, transformError(err)
		}
		assignments, err := iterate[models.UnifiedRoleAssignmentable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleAssignmentCollectionResponseFromDiscriminatorValue)
		if err != nil {
			return nil, err
		}

		set := make(map[string]struct{}, len(assignments))
		for _, assignment := range assignments {
			if principalID := assignment.GetPrincipalId(); principalID != nil {
				set[*principalID] = struct{}{}
			}
		}
		return set, nil
	})
}

// isAdministrator reports whether the user is directly assigned at least one
// active Microsoft Entra directory role.
func (a *mqlMicrosoftUser) isAdministrator() (bool, error) {
	if a.Id.Data == "" {
		return false, nil
	}

	admins, err := adminPrincipalIDs(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	_, ok := admins[a.Id.Data]
	return ok, nil
}
