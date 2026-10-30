// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlMongodbatlasAiModelApiKeyInternal carries the project the key was scoped
// to, resolved through the organization's project listing rather than fetched
// per key.
type mqlMongodbatlasAiModelApiKeyInternal struct {
	cacheGroupID string
}

// aiModelApiKeys lists the credentials the organization holds for embedding and
// reranking services. The create response carries the key secret in plaintext
// and the list response does not, so nothing here reads it: status and
// lastUsedAt are what a stale or unattended credential is found by.
func (r *mqlMongodbatlas) aiModelApiKeys() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.AIModelAPIKeysAPI.
			ListOrgModelKeys(ctx, oid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// A project-scoped credential has no organization privilege, and
			// the feature is not enabled everywhere. Neither says the
			// organization holds no keys.
			if isAccessDenied(httpResp) {
				r.AiModelApiKeys.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			k := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.aiModelApiKey", map[string]*llx.RawData{
				// A key id is unique within its organization, and a credential
				// with access to several walks each in turn.
				"__id":       llx.StringData("mongodbatlas.aiModelApiKey/" + oid + "/" + k.GetApiKeyId()),
				"id":         llx.StringData(k.GetApiKeyId()),
				"name":       llx.StringDataPtr(k.Name),
				"status":     llx.StringDataPtr(k.Status),
				"cloud":      llx.StringDataPtr(k.Cloud),
				"geography":  llx.StringDataPtr(k.Geography),
				"endpoint":   llx.StringDataPtr(k.Endpoint),
				"createdBy":  llx.StringDataPtr(k.CreatedBy),
				"createdAt":  llx.TimeDataPtr(parseAtlasTime(k.CreatedAt)),
				"lastUsedAt": llx.TimeDataPtr(parseAtlasTime(k.LastUsedAt)),
			})
			if err != nil {
				return 0, err
			}
			key := res.(*mqlMongodbatlasAiModelApiKey)
			key.cacheGroupID = k.GetGroupId()
			out = append(out, key)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// project resolves the project a key is scoped to. An organization-wide key
// names no project, which is null rather than a project that does not exist.
func (r *mqlMongodbatlasAiModelApiKey) project() (*mqlMongodbatlasProject, error) {
	if r.cacheGroupID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveProject(r.MqlRuntime, r.cacheGroupID)
}
