// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"slices"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
)

// openai.externalKey

type mqlOpenaiExternalKeyInternal struct {
	cacheProjectIds []string
}

// externalKeyArgs maps an external key configuration onto resource arguments.
// Each key service fills a different set of location fields and leaves the
// others out of the response, so a field the service does not use reads as
// null rather than as an empty string.
func externalKeyArgs(k openai.ExternalKey) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                          llx.StringData(k.ID),
		"id":                            llx.StringData(k.ID),
		"name":                          llx.StringData(k.Name),
		"provider":                      llx.StringDataPtr(emptyToNil(k.Type)),
		"purpose":                       llx.StringDataPtr(emptyToNil(string(k.Purpose))),
		"workspaceId":                   llx.StringDataPtr(emptyToNil(k.WorkspaceID)),
		"kmsArn":                        llx.StringDataPtr(emptyToNil(k.KmsArn)),
		"roleArn":                       llx.StringDataPtr(emptyToNil(k.RoleArn)),
		"kmsProjectId":                  llx.StringDataPtr(emptyToNil(k.KmsProjectID)),
		"kmsKeyLocation":                llx.StringDataPtr(emptyToNil(k.KmsKeyLocation)),
		"kmsKeyRingName":                llx.StringDataPtr(emptyToNil(k.KmsKeyRingName)),
		"kmsKeyName":                    llx.StringDataPtr(emptyToNil(k.KmsKeyName)),
		"kmsKeyVersion":                 llx.StringDataPtr(emptyToNil(k.KmsKeyVersion)),
		"audience":                      llx.StringDataPtr(emptyToNil(k.Audience)),
		"workloadIdentityProjectNumber": llx.StringDataPtr(emptyToNil(k.WorkloadIdentityProjectNumber)),
		"workloadIdentityPoolId":        llx.StringDataPtr(emptyToNil(k.WorkloadIdentityPoolID)),
		"workloadIdentityProviderId":    llx.StringDataPtr(emptyToNil(k.WorkloadIdentityProviderID)),
		"vaultUri":                      llx.StringDataPtr(emptyToNil(k.VaultUri)),
		"keyName":                       llx.StringDataPtr(emptyToNil(k.KeyName)),
		"keyVersion":                    llx.StringDataPtr(emptyToNil(k.KeyVersion)),
		"tenantId":                      llx.StringDataPtr(emptyToNil(k.TenantID)),
		"createdAt":                     llx.TimeDataPtr(unixToNullableTime(k.CreatedAt)),
	}
}

func (r *mqlOpenai) externalKeys() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.externalKeys")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	res := []any{}
	err = walkPages(
		client.Admin.Organization.ExternalKeys.ListAutoPaging(ctx, openai.AdminOrganizationExternalKeyListParams{}),
		func(k openai.ExternalKey) string { return k.ID },
		func(k openai.ExternalKey) error {
			mqlKey, err := CreateResource(r.MqlRuntime, "openai.externalKey", externalKeyArgs(k))
			if err != nil {
				return err
			}
			mqlKey.(*mqlOpenaiExternalKey).cacheProjectIds = k.APIProjectIDs
			res = append(res, mqlKey)
			return nil
		})
	if err != nil {
		return nil, classifyReportError(err, "external key list")
	}
	return res, nil
}

// projects resolves the bound project ids through the organization project
// list, so the reference costs no call per key.
func (r *mqlOpenaiExternalKey) projects() ([]any, error) {
	if len(r.cacheProjectIds) == 0 {
		return []any{}, nil
	}
	all, err := openaiProjectList(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return projectsWithIds(all, r.cacheProjectIds), nil
}

// projectsWithIds picks the projects named by ids out of the organization
// project list. An id with no matching project, such as a project deleted
// after it was bound, is left out rather than reported as an empty project.
func projectsWithIds(all []any, ids []string) []any {
	res := []any{}
	for _, item := range all {
		p, ok := item.(*mqlOpenaiProject)
		if ok && slices.Contains(ids, p.Id.Data) {
			res = append(res, p)
		}
	}
	return res
}

func (r *mqlOpenaiProject) externalKeys() ([]any, error) {
	obj, err := CreateResource(r.MqlRuntime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	keys := obj.(*mqlOpenai).GetExternalKeys()
	if keys.Error != nil {
		return nil, keys.Error
	}
	return externalKeysBoundTo(keys.Data, r.Id.Data), nil
}

// externalKeysBoundTo picks the external keys that list projectID among their
// bound projects.
func externalKeysBoundTo(keys []any, projectID string) []any {
	res := []any{}
	if projectID == "" {
		return res
	}
	for _, item := range keys {
		k, ok := item.(*mqlOpenaiExternalKey)
		if ok && slices.Contains(k.cacheProjectIds, projectID) {
			res = append(res, k)
		}
	}
	return res
}
