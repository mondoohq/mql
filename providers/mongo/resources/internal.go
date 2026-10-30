// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// roleRef is a role grant (role name + the database it is defined in).
type roleRef struct {
	role string
	db   string
}

// mqlMongoUserInternal caches the user's role grants (gathered in the bulk
// usersInfo call) so the roles() accessor builds them without a re-query, plus
// the inheritance-expanded set behind effectiveRoles() and isPrivileged.
type mqlMongoUserInternal struct {
	cacheRoleRefs []roleRef

	cacheEffectiveRefs []roleRef
	effectiveResolved  bool
}
