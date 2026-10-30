// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/weaviate/weaviate-go-client/v5/weaviate/rbac"
)

// mqlWeaviateRoleInternal caches the source role so its permissions resolve
// without re-fetching. The code generator embeds this into mqlWeaviateRole.
type mqlWeaviateRoleInternal struct {
	cacheRole *rbac.Role
}

// mqlWeaviateUserInternal caches the roles returned alongside the user so
// user.roles resolves without a second fetch.
type mqlWeaviateUserInternal struct {
	cacheRoles []*rbac.Role
}
