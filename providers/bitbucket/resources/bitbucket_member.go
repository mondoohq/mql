// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
)

// newMqlBitbucketMember maps a single API user, together with the permission
// level it was read under (empty when the source endpoint doesn't attach
// one, e.g. default reviewers), to its MQL resource.
func newMqlBitbucketMember(runtime *plugin.Runtime, u connection.User, permission string) (plugin.Resource, error) {
	// The same user can appear under different permission levels depending on
	// the context it was read from (workspace admin, default reviewer with no
	// permission, branch-restriction exemption, etc.). Key the cache by both
	// UUID and permission so a later, differently-scoped read does not collide
	// with an earlier one and report a stale permission. The id field stays the
	// bare UUID so the member is still identifiable by account.
	res, err := CreateResource(runtime, "bitbucket.member", map[string]*llx.RawData{
		"__id":        llx.StringData(u.UUID + "/" + permission),
		"id":          llx.StringData(u.UUID),
		"username":    llx.StringData(u.Nickname),
		"displayName": llx.StringData(u.DisplayName),
		"accountType": llx.StringData(u.Type),
		"permission":  llx.StringData(permission),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
