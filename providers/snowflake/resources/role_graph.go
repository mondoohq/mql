// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// snowflakeGrantCache memoizes the SHOW GRANTS responses the role hierarchy
// walks read. Expanding one role's inherited privileges revisits shared
// ancestors repeatedly (a diamond in the hierarchy is the normal shape, not the
// exception), and every user's expansion re-walks the same roles again, so
// without a cache a single query over an account's roles reissues the same
// statements hundreds of times.
//
// The mutex is held across the Snowflake call rather than only around the map
// write. MQL evaluates blocks in goroutines, so two roles expanding at the same
// time would otherwise both miss on a shared ancestor and issue the statement
// twice. Serializing the fetches trades parallelism for a bounded number of
// round trips, which is the better deal against an API this chatty.
type snowflakeGrantCache struct {
	mu     sync.Mutex
	toRole map[string]grantResult[snowflakeGrant]
	ofRole map[string]grantResult[snowflakeGrant]
	toUser map[string]grantResult[userRoleGrant]
}

// grantResult is the outcome of one SHOW GRANTS statement, successful or not.
//
// Failures are memoized alongside successes. A scanning role that cannot read
// one role in the hierarchy fails on it every time it is reached, and a query
// that walks many roles reaches it repeatedly, so retrying would multiply the
// statements against exactly the account where they are already being refused.
type grantResult[T any] struct {
	grants []T
	err    error
}

// memoGrants returns the memoized outcome for name, running fetch once on the
// first miss. The mutex is held across fetch, which is what makes concurrent
// walks share one statement rather than race to issue their own.
func memoGrants[T any](cache *snowflakeGrantCache, bucket map[string]grantResult[T], name string, fetch func() ([]T, error)) ([]T, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if result, ok := bucket[name]; ok {
		return result.grants, result.err
	}

	grants, err := fetch()
	bucket[name] = grantResult[T]{grants: grants, err: err}
	return grants, err
}

// userRoleGrant is one row of SHOW GRANTS TO USER.
//
// That statement is the odd one out: its result set is created_on, role,
// granted_to, grantee_name, granted_by, with no privilege, granted_on, or name
// column. The SDK scans every SHOW GRANTS variant into one struct that has no
// field for the role column and runs the driver in unsafe mode, so the column
// is silently dropped and the typed rows come back with the role name missing
// entirely. Reading the statement directly is the only way to recover it.
type userRoleGrant struct {
	role      string
	grantedBy string
	createdOn *llx.RawData
}

// snowflakeAccount returns the account resource for the current connection. The
// account is a singleton (its id is the constant "snowflake.account"), so
// CreateResource hands back the instance already in the runtime cache together
// with the grant cache and name indexes hanging off it.
func snowflakeAccount(runtime *plugin.Runtime) (*mqlSnowflakeAccount, error) {
	res, err := CreateResource(runtime, "snowflake.account", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSnowflakeAccount), nil
}

func (r *mqlSnowflakeAccount) grantCache() *snowflakeGrantCache {
	r.grantCacheOnce.Do(func() {
		r.cachedGrants = &snowflakeGrantCache{
			toRole: map[string]grantResult[snowflakeGrant]{},
			ofRole: map[string]grantResult[snowflakeGrant]{},
			toUser: map[string]grantResult[userRoleGrant]{},
		}
	})
	return r.cachedGrants
}

// showGrants runs one memoized SHOW GRANTS statement. The caller picks the
// bucket to memoize into, since the same name means different things in each
// direction.
func (r *mqlSnowflakeAccount) showGrants(bucket map[string]grantResult[snowflakeGrant], name string, statement string) ([]snowflakeGrant, error) {
	return memoGrants(r.grantCache(), bucket, name, func() ([]snowflakeGrant, error) {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		return showGrantsRaw(conn, statement)
	})
}

// grantsToRole returns SHOW GRANTS TO ROLE <name>: the privileges the role holds
// directly, including the roles granted to it.
func (r *mqlSnowflakeAccount) grantsToRole(name string) ([]snowflakeGrant, error) {
	id := sdk.NewAccountObjectIdentifier(name)
	return r.showGrants(r.grantCache().toRole, name,
		"SHOW GRANTS TO ROLE "+id.FullyQualifiedName())
}

// grantsOfRole returns SHOW GRANTS OF ROLE <name>: the users and roles the role
// has been granted to.
func (r *mqlSnowflakeAccount) grantsOfRole(name string) ([]snowflakeGrant, error) {
	id := sdk.NewAccountObjectIdentifier(name)
	return r.showGrants(r.grantCache().ofRole, name,
		"SHOW GRANTS OF ROLE "+id.FullyQualifiedName())
}

// grantsToUser returns SHOW GRANTS TO USER <name>, the roles granted to the
// user. It reads the statement directly rather than through the SDK for the
// reason documented on userRoleGrant.
func (r *mqlSnowflakeAccount) grantsToUser(name string) ([]userRoleGrant, error) {
	cache := r.grantCache()
	return memoGrants(cache, cache.toUser, name, func() ([]userRoleGrant, error) {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		// The identifier is rendered by the SDK, so the name reaches the
		// statement as a properly quoted identifier rather than as raw
		// interpolation.
		id := sdk.NewAccountObjectIdentifier(name)
		rows, err := conn.Client().QueryUnsafe(context.Background(),
			"SHOW GRANTS TO USER "+id.FullyQualifiedName())
		if err != nil {
			return nil, err
		}
		return parseUserRoleGrants(rows), nil
	})
}

// parseUserRoleGrants reads the rows of SHOW GRANTS TO USER. A row with no role
// is dropped rather than recorded as a grant of a role with no name.
func parseUserRoleGrants(rows []map[string]*any) []userRoleGrant {
	grants := make([]userRoleGrant, 0, len(rows))
	for _, row := range rows {
		role := unsafeString(row["role"])
		if role == "" {
			continue
		}
		grants = append(grants, userRoleGrant{
			role:      sdk.NewAccountObjectIdentifier(role).Name(),
			grantedBy: unsafeString(row["granted_by"]),
			createdOn: unsafeTime(row["created_on"]),
		})
	}
	return grants
}

// unsafeTime coerces a QueryUnsafe timestamp cell into time RawData. The driver
// hands back a time.Time for a real timestamp column; a string form is parsed
// through the same layouts the SHOW responses use.
func unsafeTime(v *any) *llx.RawData {
	if v == nil || *v == nil {
		return llx.NilData
	}
	if t, ok := (*v).(time.Time); ok {
		return snowflakeTime(t)
	}
	return parseSnowflakeTime(unsafeString(v))
}

// roleIndex maps account role names to the SHOW ROLES row describing them, so a
// hierarchy walk that produces a list of names can build resources from a single
// account-wide statement instead of one lookup per name.
func (r *mqlSnowflakeAccount) roleIndex() (map[string]sdk.Role, error) {
	r.roleIndexOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		roles, err := conn.Client().Roles.Show(context.Background(), &sdk.ShowRoleRequest{})
		if err != nil {
			r.cachedRoleIndexErr = err
			return
		}
		index := make(map[string]sdk.Role, len(roles))
		for i := range roles {
			index[sdk.NewAccountObjectIdentifier(roles[i].Name).Name()] = roles[i]
		}
		r.cachedRoleIndex = index
	})
	return r.cachedRoleIndex, r.cachedRoleIndexErr
}

// userIndex maps user names to the SHOW USERS row describing them.
func (r *mqlSnowflakeAccount) userIndex() (map[string]sdk.User, error) {
	r.userIndexOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		users, err := conn.Client().Users.Show(context.Background(), &sdk.ShowUserRequest{})
		if err != nil {
			r.cachedUserIndexErr = err
			return
		}
		index := make(map[string]sdk.User, len(users))
		for i := range users {
			index[sdk.NewAccountObjectIdentifier(users[i].Name).Name()] = users[i]
		}
		r.cachedUserIndex = index
	})
	return r.cachedUserIndex, r.cachedUserIndexErr
}

// nameSet accumulates names in first-seen order. The hierarchy walks need both
// membership tests and a stable result order, and the sets involved are small
// enough that a slice plus a map beats anything cleverer.
type nameSet struct {
	seen  map[string]bool
	order []string
}

func newNameSet(initial ...string) *nameSet {
	s := &nameSet{seen: map[string]bool{}}
	for _, name := range initial {
		s.add(name)
	}
	return s
}

// add records the name and reports whether it was new.
func (s *nameSet) add(name string) bool {
	if name == "" || s.seen[name] {
		return false
	}
	s.seen[name] = true
	s.order = append(s.order, name)
	return true
}

// directChildRoles returns the roles granted to roleName, whose privileges
// roleName therefore inherits.
func directChildRoles(account *mqlSnowflakeAccount, roleName string) ([]string, error) {
	grants, err := account.grantsToRole(roleName)
	if err != nil {
		return nil, err
	}
	return grantedRoleNames(grants), nil
}

// grantedRoleNames returns the roles named by grants of a role to something
// else, in the order first seen. A grant on any other object type is not a step
// in the hierarchy, and a role grant with no name cannot be followed.
func grantedRoleNames(grants []snowflakeGrant) []string {
	names := newNameSet()
	for i := range grants {
		if grants[i].grantedOn != string(sdk.ObjectTypeRole) || grants[i].name == "" {
			continue
		}
		names.add(identifierName(grants[i].name))
	}
	return names.order
}

// directParentRoles returns the roles that roleName has been granted to, which
// therefore inherit its privileges.
func directParentRoles(account *mqlSnowflakeAccount, roleName string) ([]string, error) {
	grants, err := account.grantsOfRole(roleName)
	if err != nil {
		return nil, err
	}
	return granteeNames(grants, sdk.ObjectTypeRole), nil
}

// granteeNames returns the grantees of one kind named by a SHOW GRANTS OF
// result, in the order first seen. The same statement reports both the users and
// the roles holding a role, so the kind is what separates them.
func granteeNames(grants []snowflakeGrant, grantedTo sdk.ObjectType) []string {
	names := newNameSet()
	for i := range grants {
		if grants[i].grantedTo != string(grantedTo) {
			continue
		}
		names.add(grants[i].granteeName)
	}
	return names.order
}

// directRoleUsers returns the users roleName has been granted to directly.
func directRoleUsers(account *mqlSnowflakeAccount, roleName string) ([]string, error) {
	grants, err := account.grantsOfRole(roleName)
	if err != nil {
		return nil, err
	}
	return granteeNames(grants, sdk.ObjectTypeUser), nil
}

// directUserRoles returns the roles granted to userName directly.
func directUserRoles(account *mqlSnowflakeAccount, userName string) ([]string, error) {
	grants, err := account.grantsToUser(userName)
	if err != nil {
		return nil, err
	}
	names := newNameSet()
	for i := range grants {
		names.add(grants[i].role)
	}
	return names.order, nil
}

// edgeFunc reports the roles adjacent to a role in one direction of the
// hierarchy. The walks below take the direction as a function so the traversal
// is independent of the statements that supply the edges.
type edgeFunc func(roleName string) ([]string, error)

// walkRoles walks the hierarchy in one direction from the seed roles and
// returns every role reached, excluding the seeds themselves. The visited set
// covers the seeds from the start, so a hierarchy that loops back terminates
// instead of walking forever.
func walkRoles(next edgeFunc, seeds []string) ([]string, error) {
	visited := newNameSet(seeds...)
	result := newNameSet()

	queue := append([]string{}, seeds...)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		adjacent, err := next(current)
		if err != nil {
			return nil, err
		}
		for _, name := range adjacent {
			if visited.add(name) {
				result.add(name)
				queue = append(queue, name)
			}
		}
	}
	return result.order, nil
}

// inheritedRoles walks the hierarchy downward from the seed roles and returns
// every role whose privileges they inherit. Seeds are excluded from the result:
// a role does not inherit from itself, and callers that want the seed's own
// grants add them explicitly.
func inheritedRoles(account *mqlSnowflakeAccount, seeds []string) ([]string, error) {
	return walkRoles(func(name string) ([]string, error) {
		return directChildRoles(account, name)
	}, seeds)
}

// collectRoleHolders walks the hierarchy upward from a role and returns every
// user that ends up holding it, whether granted the role directly or granted a
// role that was itself granted the role.
func collectRoleHolders(parents edgeFunc, holders edgeFunc, roleName string) ([]string, error) {
	reached, err := walkRoles(parents, []string{roleName})
	if err != nil {
		return nil, err
	}

	users := newNameSet()
	// The role itself carries direct assignments too, so it leads the walk.
	for _, name := range append([]string{roleName}, reached...) {
		direct, err := holders(name)
		if err != nil {
			return nil, err
		}
		for _, user := range direct {
			users.add(user)
		}
	}
	return users.order, nil
}

// roleHolders returns every user that holds roleName, directly or through an
// intermediate role.
func roleHolders(account *mqlSnowflakeAccount, roleName string) ([]string, error) {
	return collectRoleHolders(
		func(name string) ([]string, error) { return directParentRoles(account, name) },
		func(name string) ([]string, error) { return directRoleUsers(account, name) },
		roleName,
	)
}

// resolveRoles builds role resources for the given names. A name absent from
// the account's role list is skipped rather than turned into a resource with no
// data behind it: SHOW ROLES omits roles the session cannot see, and an entry
// whose every field is unset reads as a role that exists but has no properties.
func resolveRoles(runtime *plugin.Runtime, account *mqlSnowflakeAccount, names []string) ([]any, error) {
	index, err := account.roleIndex()
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(names))
	for _, name := range names {
		role, ok := index[name]
		if !ok {
			continue
		}
		mqlRole, err := newMqlSnowflakeRole(runtime, role)
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

// resolveUsers builds user resources for the given names, skipping names the
// session cannot list for the same reason resolveRoles does.
func resolveUsers(runtime *plugin.Runtime, account *mqlSnowflakeAccount, names []string) ([]any, error) {
	index, err := account.userIndex()
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(names))
	for _, name := range names {
		user, ok := index[name]
		if !ok {
			continue
		}
		mqlUser, err := newMqlSnowflakeUser(runtime, user)
		if err != nil {
			return nil, err
		}
		list = append(list, mqlUser)
	}
	return list, nil
}

// collectGrants returns the grants held by every named role, deduplicated on the
// same key that identifies a grant resource so a privilege reached through two
// branches of the hierarchy appears once.
func collectGrants(runtime *plugin.Runtime, account *mqlSnowflakeAccount, roleNames []string) ([]any, error) {
	seen := map[string]bool{}
	list := []any{}

	for _, roleName := range roleNames {
		grants, err := account.grantsToRole(roleName)
		if err != nil {
			return nil, err
		}
		for i := range grants {
			id := snowflakeGrantID(grants[i])
			if seen[id] {
				continue
			}
			seen[id] = true

			mqlGrant, err := newMqlSnowflakeGrant(runtime, grants[i])
			if err != nil {
				return nil, err
			}
			list = append(list, mqlGrant)
		}
	}
	return list, nil
}
