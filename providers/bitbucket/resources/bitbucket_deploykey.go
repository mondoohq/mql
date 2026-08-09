// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// mqlBitbucketDeployKeyInternal caches the owning repository's full name so
// the repository() accessor can resolve a typed bitbucket.repository
// reference.
type mqlBitbucketDeployKeyInternal struct {
	cacheRepoFullName string
}

// newMqlBitbucketDeployKey maps a single API deploy key to its MQL resource.
// Deploy key ids are not guaranteed unique across repositories, so the cache
// key composes it with the owning repository's full name.
func newMqlBitbucketDeployKey(runtime *plugin.Runtime, repoFullName string, k *connection.DeployKey) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.deployKey", map[string]*llx.RawData{
		"__id":      llx.StringData(fmt.Sprintf("%s/deploy-keys/%d", repoFullName, k.ID)),
		"id":        llx.IntData(k.ID),
		"label":     llx.StringData(k.Label),
		"key":       llx.StringData(k.Key),
		"createdOn": llx.TimeDataPtr(k.CreatedOn),
		"lastUsed":  llx.TimeDataPtr(k.LastUsed),
	})
	if err != nil {
		return nil, err
	}

	mqlKey := res.(*mqlBitbucketDeployKey)
	mqlKey.cacheRepoFullName = repoFullName
	return res, nil
}

// repository resolves the repository this deploy key is registered on.
func (k *mqlBitbucketDeployKey) repository() (*mqlBitbucketRepository, error) {
	res, err := NewResource(k.MqlRuntime, "bitbucket.repository", map[string]*llx.RawData{
		"fullName": llx.StringData(k.cacheRepoFullName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketRepository), nil
}
