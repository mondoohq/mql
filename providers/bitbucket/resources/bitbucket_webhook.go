// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
	"go.mondoo.com/mql/types"
)

// mqlBitbucketRepositoryWebhookInternal caches the owning repository's full
// name so the repository() accessor can resolve a typed bitbucket.repository
// reference.
type mqlBitbucketRepositoryWebhookInternal struct {
	cacheRepoFullName string
}

// newMqlBitbucketRepositoryWebhook maps a single API webhook to its MQL
// resource. Webhook UUIDs are unique within a repository, so the cache key
// composes the UUID with the owning repository's full name.
func newMqlBitbucketRepositoryWebhook(runtime *plugin.Runtime, repoFullName string, h *connection.Webhook) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.repository.webhook", map[string]*llx.RawData{
		"__id":                 llx.StringData(repoFullName + "/hooks/" + h.UUID),
		"id":                   llx.StringData(h.UUID),
		"url":                  llx.StringData(h.URL),
		"description":          llx.StringData(h.Description),
		"active":               llx.BoolDataPtr(h.Active),
		"events":               llx.ArrayData(strList(h.Events), types.String),
		"skipCertVerification": llx.BoolDataPtr(h.SkipCertVerification),
		"secretSet":            llx.BoolDataPtr(h.SecretSet),
		"createdOn":            llx.TimeDataPtr(h.CreatedAt),
	})
	if err != nil {
		return nil, err
	}

	mqlHook := res.(*mqlBitbucketRepositoryWebhook)
	mqlHook.cacheRepoFullName = repoFullName
	return res, nil
}

// repository resolves the repository this webhook is registered on.
func (h *mqlBitbucketRepositoryWebhook) repository() (*mqlBitbucketRepository, error) {
	res, err := NewResource(h.MqlRuntime, "bitbucket.repository", map[string]*llx.RawData{
		"fullName": llx.StringData(h.cacheRepoFullName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketRepository), nil
}

// mqlBitbucketWorkspaceWebhookInternal caches the owning workspace slug so the
// workspace() accessor can resolve a typed bitbucket.workspace reference.
type mqlBitbucketWorkspaceWebhookInternal struct {
	cacheWorkspaceSlug string
}

// newMqlBitbucketWorkspaceWebhook maps a single API webhook to its MQL
// resource. Webhook UUIDs are unique within a workspace, so the cache key
// composes the UUID with the owning workspace slug.
func newMqlBitbucketWorkspaceWebhook(runtime *plugin.Runtime, workspaceSlug string, h *connection.Webhook) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.workspace.webhook", map[string]*llx.RawData{
		"__id":                 llx.StringData(workspaceSlug + "/hooks/" + h.UUID),
		"id":                   llx.StringData(h.UUID),
		"url":                  llx.StringData(h.URL),
		"description":          llx.StringData(h.Description),
		"active":               llx.BoolDataPtr(h.Active),
		"events":               llx.ArrayData(strList(h.Events), types.String),
		"skipCertVerification": llx.BoolDataPtr(h.SkipCertVerification),
		"secretSet":            llx.BoolDataPtr(h.SecretSet),
		"createdOn":            llx.TimeDataPtr(h.CreatedAt),
	})
	if err != nil {
		return nil, err
	}

	mqlHook := res.(*mqlBitbucketWorkspaceWebhook)
	mqlHook.cacheWorkspaceSlug = workspaceSlug
	return res, nil
}

// workspace resolves the workspace this webhook is registered on.
func (h *mqlBitbucketWorkspaceWebhook) workspace() (*mqlBitbucketWorkspace, error) {
	res, err := NewResource(h.MqlRuntime, "bitbucket.workspace", map[string]*llx.RawData{
		"slug": llx.StringData(h.cacheWorkspaceSlug),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketWorkspace), nil
}
