// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeApplicationRoleInternal struct {
	cacheOwner string
}

// roles lists the roles an installed application defines. SHOW APPLICATION
// ROLES is scoped to one application, so this runs per application rather than
// account-wide.
func (r *mqlSnowflakeApplication) roles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	applicationName := r.Name.Data
	roles, err := conn.Client().ApplicationRoles.Show(context.Background(),
		sdk.NewShowApplicationRoleRequest().WithApplicationName(sdk.NewAccountObjectIdentifier(applicationName)))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(roles))
	for i := range roles {
		mqlRole, err := newMqlSnowflakeApplicationRole(r.MqlRuntime, applicationName, roles[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

func newMqlSnowflakeApplicationRole(runtime *plugin.Runtime, applicationName string, role sdk.ApplicationRole) (*mqlSnowflakeApplicationRole, error) {
	r, err := CreateResource(runtime, "snowflake.applicationRole", map[string]*llx.RawData{
		// An application role's name is unique only within its application, so
		// the application name is part of the id.
		"__id":            llx.StringData(`"` + applicationName + `"."` + role.Name + `"`),
		"name":            llx.StringData(role.Name),
		"applicationName": llx.StringData(applicationName),
		"ownerRoleType":   llx.StringData(role.OwnerRoleType),
		"comment":         llx.StringData(role.Comment),
		"createdAt":       snowflakeTime(role.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlRole := r.(*mqlSnowflakeApplicationRole)
	mqlRole.cacheOwner = role.Owner
	return mqlRole, nil
}

func (r *mqlSnowflakeApplicationRole) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}
