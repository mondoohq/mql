// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlDatabricks) globalInitScripts() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	scripts, err := ws.GlobalInitScripts.ListAll(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range scripts {
		s := scripts[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.globalInitScript", map[string]*llx.RawData{
			"__id":      llx.StringData("databricks.globalInitScript/" + s.ScriptId),
			"id":        llx.StringData(s.ScriptId),
			"name":      llx.StringData(s.Name),
			"enabled":   llx.BoolData(s.Enabled),
			"position":  llx.IntData(int64(s.Position)),
			"createdAt": llx.TimeDataPtr(epochMsTime(int64(s.CreatedAt))),
			"createdBy": llx.StringData(s.CreatedBy),
			"updatedAt": llx.TimeDataPtr(epochMsTime(int64(s.UpdatedAt))),
			"updatedBy": llx.StringData(s.UpdatedBy),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricks) instanceProfiles() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	profiles, err := ws.InstanceProfiles.ListAll(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range profiles {
		res, err := newMqlDatabricksInstanceProfile(r.MqlRuntime, profiles[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksInstanceProfile maps an instance profile to its resource,
// shared by the list path and by every compute definition that resolves the
// profile it assumes.
func newMqlDatabricksInstanceProfile(runtime *plugin.Runtime, p compute.InstanceProfile) (*mqlDatabricksInstanceProfile, error) {
	res, err := CreateResource(runtime, "databricks.instanceProfile", map[string]*llx.RawData{
		"__id":                  llx.StringData("databricks.instanceProfile/" + p.InstanceProfileArn),
		"instanceProfileArn":    llx.StringData(p.InstanceProfileArn),
		"iamRoleArn":            llx.StringData(p.IamRoleArn),
		"isMetaInstanceProfile": llx.BoolData(p.IsMetaInstanceProfile),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksInstanceProfile), nil
}
