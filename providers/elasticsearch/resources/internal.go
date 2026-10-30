// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// mqlElasticsearchRoleInternal caches the source role so its index privileges
// resolve without a second fetch. The code generator embeds this into
// mqlElasticsearchRole.
type mqlElasticsearchRoleInternal struct {
	cacheRole *esRole
}
