// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// mqlRedisdbInstanceInternal caches the CONFIG GET result fetched during init so
// the config sub-resource resolves without a second round trip. configReadable
// is false when the connecting credential was denied CONFIG GET. The code
// generator embeds this into mqlRedisdbInstance.
type mqlRedisdbInstanceInternal struct {
	configCache    map[string]string
	configReadable bool
}

// mqlRedisdbAclUserInternal caches the selectors parsed alongside the user's
// base rules when the ACL roster was read, so the selectors accessor resolves
// without a second ACL round trip. The code generator embeds this into
// mqlRedisdbAclUser.
type mqlRedisdbAclUserInternal struct {
	selectorCache []aclRules
}
