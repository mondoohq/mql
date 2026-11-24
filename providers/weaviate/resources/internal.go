// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/weaviate/connection"
)

// mqlWeaviateRoleInternal caches the source role so its permissions resolve
// without re-fetching. The code generator embeds this into mqlWeaviateRole.
type mqlWeaviateRoleInternal struct {
	cacheRole *connection.Role
}

// mqlWeaviateUserInternal caches the names of the roles returned alongside the
// user so user.roles resolves without a second fetch.
type mqlWeaviateUserInternal struct {
	cacheRoleNames []string
}
