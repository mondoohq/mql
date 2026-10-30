// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers/mondoo/connection"
)

// assetRoot returns the resource that roots this asset's tree (ADR 031). It is
// what `_` resolves to, and what bounds the query: on an organization
// `_.assets` then fails to compile rather than answering with an unset field.
//
// The connection already knows which it is - determineConnType reads it off the
// MRN, `.../spaces/x` against `.../organizations/y` - so this reads that rather
// than deciding again.
//
// An organization is the fallback, matching what the provider declares
// statically: with no connection to read there is nothing to narrow by, and the
// wider of the two is the honest answer.
func assetRoot(conn *connection.Connection) string {
	if conn != nil && conn.Type == connection.ConnTypeSpace {
		return "mondoo.space"
	}
	return "mondoo.organization"
}
