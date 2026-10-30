// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// account-level grants: SHOW GRANTS ON ACCOUNT
func (r *mqlSnowflakeAccount) grants() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)

	grants, err := showGrantsRaw(conn, "SHOW GRANTS ON ACCOUNT")
	if err != nil {
		return nil, err
	}

	return convertGrants(r.MqlRuntime, grants)
}

// SHOW GRANTS TO ROLE <role>
func (r *mqlSnowflakeRole) grants() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	grants, err := account.grantsToRole(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return convertGrants(r.MqlRuntime, grants)
}

// SHOW GRANTS TO USER <user>: the roles granted to the user.
//
// This statement reports only the role, so privilege resolves to null rather
// than to an empty string that would read as a privilege actually named "".
//
// grantOption is false rather than null. GRANT ROLE takes no WITH GRANT OPTION
// clause, so a user can never re-grant a role they hold, and false states that
// correctly. Leaving it null would be the worse answer: MQL's three-valued
// logic passes an assertion built from nulls, so a policy asserting that no
// grant is re-grantable would silently succeed on every row here.
func (r *mqlSnowflakeUser) grants() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	grants, err := account.grantsToUser(r.Name.Data)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(grants))
	for _, g := range grants {
		id := r.Name.Data + "/" + string(sdk.ObjectTypeUser) + "//" + string(sdk.ObjectTypeRole) + "/" + g.role
		res, err := CreateResource(r.MqlRuntime, "snowflake.grant", map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"privilege":   llx.NilData,
			"grantedOn":   llx.StringData(string(sdk.ObjectTypeRole)),
			"name":        llx.StringData(g.role),
			"grantedTo":   llx.StringData(string(sdk.ObjectTypeUser)),
			"granteeName": llx.StringData(r.Name.Data),
			"grantOption": llx.BoolData(false),
			"createdAt":   g.createdOn,
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlSnowflakeGrant).cacheGrantedBy = g.grantedBy
		list = append(list, res)
	}
	return list, nil
}

// SHOW GRANTS OF ROLE <role> -- enumerate grantees (users and roles) holding this role.
// Each grant entry has granteeName + grantedTo so callers can filter by USER vs ROLE.
func (r *mqlSnowflakeRole) grantees() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	grants, err := account.grantsOfRole(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return convertGrants(r.MqlRuntime, grants)
}

// childRoles returns the roles granted to this role, one level down.
func (r *mqlSnowflakeRole) childRoles() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := directChildRoles(account, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return resolveRoles(r.MqlRuntime, account, names)
}

// parentRoles returns the roles this role is granted to, one level up.
func (r *mqlSnowflakeRole) parentRoles() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := directParentRoles(account, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return resolveRoles(r.MqlRuntime, account, names)
}

// users returns the users this role is granted to directly.
func (r *mqlSnowflakeRole) users() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := directRoleUsers(account, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return resolveUsers(r.MqlRuntime, account, names)
}

// effectiveRoles returns every role whose privileges this role inherits.
func (r *mqlSnowflakeRole) effectiveRoles() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := inheritedRoles(account, []string{r.Name.Data})
	if err != nil {
		return nil, err
	}
	return resolveRoles(r.MqlRuntime, account, names)
}

// effectiveUsers returns every user that holds this role, directly or through
// an intermediate role.
func (r *mqlSnowflakeRole) effectiveUsers() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := roleHolders(account, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return resolveUsers(r.MqlRuntime, account, names)
}

// effectiveGrants returns the privileges this role holds directly plus those it
// inherits from the roles granted to it.
func (r *mqlSnowflakeRole) effectiveGrants() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	inherited, err := inheritedRoles(account, []string{r.Name.Data})
	if err != nil {
		return nil, err
	}
	return collectGrants(r.MqlRuntime, account, append([]string{r.Name.Data}, inherited...))
}

// roles returns the roles granted to the user directly.
func (r *mqlSnowflakeUser) roles() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	names, err := directUserRoles(account, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return resolveRoles(r.MqlRuntime, account, names)
}

// effectiveRoles returns the user's direct roles plus every role those roles
// inherit.
func (r *mqlSnowflakeUser) effectiveRoles() ([]any, error) {
	account, names, err := userEffectiveRoleNames(r)
	if err != nil {
		return nil, err
	}
	return resolveRoles(r.MqlRuntime, account, names)
}

// effectiveGrants returns every privilege the user reaches through their roles.
func (r *mqlSnowflakeUser) effectiveGrants() ([]any, error) {
	account, names, err := userEffectiveRoleNames(r)
	if err != nil {
		return nil, err
	}
	return collectGrants(r.MqlRuntime, account, names)
}

// userEffectiveRoleNames resolves the user's direct roles and the roles those
// inherit, in that order, so the direct grants lead the result.
func userEffectiveRoleNames(r *mqlSnowflakeUser) (*mqlSnowflakeAccount, []string, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, nil, err
	}
	direct, err := directUserRoles(account, r.Name.Data)
	if err != nil {
		return nil, nil, err
	}
	inherited, err := inheritedRoles(account, direct)
	if err != nil {
		return nil, nil, err
	}
	return account, append(direct, inherited...), nil
}

// accountAdmins returns all users that hold the ACCOUNTADMIN role, either
// directly or transitively via role-to-role grants.
func (r *mqlSnowflakeAccount) accountAdmins() ([]any, error) {
	names, err := roleHolders(r, "ACCOUNTADMIN")
	if err != nil {
		return nil, err
	}
	return resolveUsers(r.MqlRuntime, r, names)
}

// granteeRole resolves the grantee when the privilege was granted to a role.
func (r *mqlSnowflakeGrant) granteeRole() (*mqlSnowflakeRole, error) {
	if r.GrantedTo.Data != string(sdk.ObjectTypeRole) {
		r.GranteeRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOwnerRole(r.MqlRuntime, r.GranteeName.Data, &r.GranteeRole)
}

// granteeUser resolves the grantee when the role was granted to a user.
func (r *mqlSnowflakeGrant) granteeUser() (*mqlSnowflakeUser, error) {
	if r.GrantedTo.Data != string(sdk.ObjectTypeUser) {
		r.GranteeUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveUser(r.MqlRuntime, r.GranteeName.Data, &r.GranteeUser)
}

// mqlSnowflakeGrantInternal holds the name of the granting role, which SHOW
// GRANTS reports as a bare string and grantedByRole resolves to a role.
type mqlSnowflakeGrantInternal struct {
	cacheGrantedBy string
}

// grantedByRole resolves the role that issued the grant.
func (r *mqlSnowflakeGrant) grantedByRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheGrantedBy, &r.GrantedByRole)
}

// resolveUser resolves a user name to a user resource, reporting the reference
// as null when the session cannot list the user rather than failing the query.
func resolveUser(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlSnowflakeUser]) (*mqlSnowflakeUser, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	index, err := account.userIndex()
	if err != nil {
		return nil, err
	}
	user, ok := index[name]
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlSnowflakeUser(runtime, user)
}

// grants returns the privileges granted on the database (SHOW GRANTS ON DATABASE).
func (r *mqlSnowflakeDatabase) grants() ([]any, error) {
	return showObjectGrants(r.MqlRuntime, sdk.ObjectTypeDatabase, sdk.NewAccountObjectIdentifier(r.Name.Data))
}

// futureGrants returns the grants that will apply to objects created in the
// database later (SHOW FUTURE GRANTS IN DATABASE).
func (r *mqlSnowflakeDatabase) futureGrants() ([]any, error) {
	id := sdk.NewAccountObjectIdentifier(r.Name.Data)
	return showFutureGrants(r.MqlRuntime, sdk.ObjectTypeDatabase, id)
}

// grants returns the privileges granted on the schema (SHOW GRANTS ON SCHEMA).
func (r *mqlSnowflakeSchema) grants() ([]any, error) {
	return showObjectGrants(r.MqlRuntime, sdk.ObjectTypeSchema,
		sdk.NewDatabaseObjectIdentifier(r.DatabaseName.Data, r.Name.Data))
}

// futureGrants returns the grants that will apply to objects created in the
// schema later (SHOW FUTURE GRANTS IN SCHEMA).
func (r *mqlSnowflakeSchema) futureGrants() ([]any, error) {
	id := sdk.NewDatabaseObjectIdentifier(r.DatabaseName.Data, r.Name.Data)
	return showFutureGrants(r.MqlRuntime, sdk.ObjectTypeSchema, id)
}

// grants returns the objects an outbound share exposes (SHOW GRANTS TO SHARE).
//
// An inbound share is owned by the account that created it, so this account
// grants nothing to it and the statement does not accept its qualified name.
func (r *mqlSnowflakeShare) grants() ([]any, error) {
	if !strings.EqualFold(r.Kind.Data, "OUTBOUND") {
		return []any{}, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	id := sdk.NewAccountObjectIdentifier(r.Name.Data)
	grants, err := showGrantsRaw(conn, "SHOW GRANTS TO SHARE "+id.FullyQualifiedName())
	if err != nil {
		return nil, err
	}
	return convertGrants(r.MqlRuntime, grants)
}

// grants returns the privileges granted to the database role.
func (r *mqlSnowflakeDatabaseRole) grants() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	id := sdk.NewDatabaseObjectIdentifier(r.DatabaseName.Data, r.Name.Data)
	grants, err := showGrantsRaw(conn, "SHOW GRANTS TO DATABASE ROLE "+id.FullyQualifiedName())
	if err != nil {
		return nil, err
	}
	return convertGrants(r.MqlRuntime, grants)
}

// grantees returns the roles and database roles this database role is granted to.
func (r *mqlSnowflakeDatabaseRole) grantees() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	id := sdk.NewDatabaseObjectIdentifier(r.DatabaseName.Data, r.Name.Data)
	grants, err := showGrantsRaw(conn, "SHOW GRANTS OF DATABASE ROLE "+id.FullyQualifiedName())
	if err != nil {
		return nil, err
	}
	return convertGrants(r.MqlRuntime, grants)
}

func showObjectGrants(runtime *plugin.Runtime, objectType sdk.ObjectType, id sdk.ObjectIdentifier) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	grants, err := showGrantsRaw(conn,
		"SHOW GRANTS ON "+string(objectType)+" "+id.FullyQualifiedName())
	if err != nil {
		return nil, err
	}
	return convertGrants(runtime, grants)
}

// showFutureGrants reads SHOW FUTURE GRANTS IN <scope> <name>, the grants that
// will apply to objects created in that scope later.
func showFutureGrants(runtime *plugin.Runtime, scope sdk.ObjectType, id sdk.ObjectIdentifier) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	grants, err := showGrantsRaw(conn,
		"SHOW FUTURE GRANTS IN "+string(scope)+" "+id.FullyQualifiedName())
	if err != nil {
		return nil, err
	}
	return convertGrants(runtime, grants)
}

func convertGrants(runtime *plugin.Runtime, grants []snowflakeGrant) ([]any, error) {
	list := make([]any, 0, len(grants))
	for i := range grants {
		mqlGrant, err := newMqlSnowflakeGrant(runtime, grants[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlGrant)
	}
	return list, nil
}

// snowflakeGrantID is the stable cache key for a grant: grantee, direction,
// privilege, and the object the privilege is on. Callers that merge grants from
// several statements deduplicate on this so a privilege reached twice through
// the role hierarchy yields one resource.
func snowflakeGrantID(grant snowflakeGrant) string {
	return grant.granteeName + "/" + grant.grantedTo + "/" +
		grant.privilege + "/" + grant.grantedOn + "/" + grant.name
}

func newMqlSnowflakeGrant(runtime *plugin.Runtime, grant snowflakeGrant) (*mqlSnowflakeGrant, error) {
	r, err := CreateResource(runtime, "snowflake.grant", map[string]*llx.RawData{
		"__id":        llx.StringData(snowflakeGrantID(grant)),
		"privilege":   llx.StringData(grant.privilege),
		"grantedOn":   llx.StringData(grant.grantedOn),
		"name":        llx.StringData(grant.name),
		"grantedTo":   llx.StringData(grant.grantedTo),
		"granteeName": llx.StringData(grant.granteeName),
		"grantOption": llx.BoolData(grant.grantOption),
		"createdAt":   grant.createdOn,
	})
	if err != nil {
		return nil, err
	}
	mqlGrant := r.(*mqlSnowflakeGrant)
	mqlGrant.cacheGrantedBy = grant.grantedBy
	return mqlGrant, nil
}
