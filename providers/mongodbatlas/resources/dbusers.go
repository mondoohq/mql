// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

type mqlMongodbatlasDatabaseUserInternal struct {
	cacheScopeClusterNames []string
}

func (r *mqlMongodbatlas) databaseUsers() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.DatabaseUsersAPI.ListDatabaseUsers(ctx, pid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			u := results[i]

			roles := []any{}
			for _, role := range u.GetRoles() {
				roles = append(roles, map[string]any{
					"roleName":       role.GetRoleName(),
					"databaseName":   role.GetDatabaseName(),
					"collectionName": role.GetCollectionName(),
				})
			}
			scopes := []any{}
			clusterScopeNames := []string{}
			for _, sc := range u.GetScopes() {
				scopes = append(scopes, map[string]any{
					"name": sc.GetName(),
					"type": sc.GetType(),
				})
				if sc.GetType() == "CLUSTER" && sc.GetName() != "" {
					clusterScopeNames = append(clusterScopeNames, sc.GetName())
				}
			}

			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.databaseUser", map[string]*llx.RawData{
				"__id":            llx.StringData("mongodbatlas.databaseUser/" + pid + "/" + u.GetDatabaseName() + "/" + u.GetUsername()),
				"id":              llx.StringData(u.GetDatabaseName() + "/" + u.GetUsername()),
				"username":        llx.StringData(u.GetUsername()),
				"databaseName":    llx.StringData(u.GetDatabaseName()),
				"description":     llx.StringData(u.GetDescription()),
				"awsIAMType":      llx.StringData(u.GetAwsIAMType()),
				"x509Type":        llx.StringData(u.GetX509Type()),
				"ldapAuthType":    llx.StringData(u.GetLdapAuthType()),
				"oidcAuthType":    llx.StringData(u.GetOidcAuthType()),
				"roles":           llx.ArrayData(roles, types.Dict),
				"scopes":          llx.ArrayData(scopes, types.Dict),
				"labels":          llx.MapData(labelMap(u.GetLabels()), types.String),
				"deleteAfterDate": llx.TimeDataPtr(timePtr(u.GetDeleteAfterDate())),
			})
			if err != nil {
				return nil, err
			}
			dbUser := res.(*mqlMongodbatlasDatabaseUser)
			dbUser.cacheScopeClusterNames = clusterScopeNames
			out = append(out, dbUser)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// scopedClusters resolves the clusters a database user is confined to. An empty
// result means the user may access all clusters in the project.
func (r *mqlMongodbatlasDatabaseUser) scopedClusters() ([]any, error) {
	root, err := rootMongodbatlas(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	clustersByName, err := root.projectClustersByName()
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, name := range r.cacheScopeClusterNames {
		cl, ok := clustersByName[name]
		if !ok {
			continue
		}
		out = append(out, cl)
	}
	return out, nil
}
