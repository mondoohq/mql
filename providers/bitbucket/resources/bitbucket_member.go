// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// newMqlBitbucketMember maps a single API user, together with the permission
// level it was read under (empty when the source endpoint doesn't attach
// one, e.g. default reviewers), to its MQL resource.
func newMqlBitbucketMember(runtime *plugin.Runtime, u connection.User, permission string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.member", map[string]*llx.RawData{
		"__id":        llx.StringData(u.UUID),
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
