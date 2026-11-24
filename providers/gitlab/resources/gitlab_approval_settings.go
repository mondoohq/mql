// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
)

// This file models the merge request approval settings of a group or project as
// GET /:scope/:id/merge_request_approval_setting reports them: every setting
// carries its value, whether a higher level locked it, and where the lock comes
// from. The legacy gitlab.project.approvalSetting stays as it is; it reads the
// older project approvals endpoint, which has no lock or inheritance.

// approvalSettingJSON is one setting of the response. The pointers keep an
// attribute GitLab did not send apart from false: inherited_from is only sent
// for a locked value.
type approvalSettingJSON struct {
	Value         *bool   `json:"value"`
	Locked        *bool   `json:"locked"`
	InheritedFrom *string `json:"inherited_from"`
}

// approvalSettingFields maps each field of gitlab.mergeRequestApprovalSettings
// to the attribute GitLab reports it under.
var approvalSettingFields = []struct {
	field string
	key   string
}{
	{"allowAuthorApproval", "allow_author_approval"},
	{"allowCommitterApproval", "allow_committer_approval"},
	{"allowOverridesToApproverListPerMergeRequest", "allow_overrides_to_approver_list_per_merge_request"},
	{"retainApprovalsOnPush", "retain_approvals_on_push"},
	{"selectiveCodeOwnerRemovals", "selective_code_owner_removals"},
	{"requirePasswordToApprove", "require_password_to_approve"},
	{"requireReauthenticationToApprove", "require_reauthentication_to_approve"},
}

// decodeApprovalSettings decodes the response into one entry per reported
// setting. A setting the scope does not report (groups have no
// selective_code_owner_removals) or reports without a value is left out, so the
// field reads as null instead of false.
func decodeApprovalSettings(raw json.RawMessage) (map[string]approvalSettingJSON, error) {
	all := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	out := map[string]approvalSettingJSON{}
	for _, f := range approvalSettingFields {
		item, ok := all[f.key]
		if !ok || string(item) == "null" {
			continue
		}
		var setting approvalSettingJSON
		if err := json.Unmarshal(item, &setting); err != nil {
			return nil, err
		}
		if setting.Value == nil {
			continue
		}
		out[f.key] = setting
	}
	return out, nil
}

// newApprovalSettings reads the approval settings at path and builds the
// resource. scope and ownerID key the resource and each of its settings, since
// the same setting exists on every group and project. It returns nil when the
// endpoint does not apply (a tier without the feature) or refuses the token
// without structured errors.
func newApprovalSettings(runtime *plugin.Runtime, path, scope string, ownerID int64) (*mqlGitlabMergeRequestApprovalSettings, error) {
	conn := runtime.Connection.(*connection.GitLabConnection)

	var raw json.RawMessage
	if _, err := getRawJSON(conn.Client(), path, nil, &raw); err != nil {
		return nil, gatedError(err)
	}
	settings, err := decodeApprovalSettings(raw)
	if err != nil {
		return nil, err
	}

	resourceID := scopedID("gitlab.mergeRequestApprovalSettings/"+scope, ownerID)
	args := map[string]*llx.RawData{
		"__id": llx.StringData(resourceID),
	}
	for _, f := range approvalSettingFields {
		setting, ok := settings[f.key]
		if !ok {
			args[f.field] = llx.NilData
			continue
		}
		res, err := CreateResource(runtime, "gitlab.mergeRequestApprovalSettings.setting", map[string]*llx.RawData{
			"__id":          llx.StringData(resourceID + "/" + f.key),
			"value":         llx.BoolDataPtr(setting.Value),
			"locked":        llx.BoolData(setting.Locked != nil && *setting.Locked),
			"inheritedFrom": llx.StringDataPtr(setting.InheritedFrom),
		})
		if err != nil {
			return nil, err
		}
		args[f.field] = llx.ResourceData(res, "gitlab.mergeRequestApprovalSettings.setting")
	}

	res, err := CreateResource(runtime, "gitlab.mergeRequestApprovalSettings", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabMergeRequestApprovalSettings), nil
}

func (g *mqlGitlabGroup) mergeRequestApprovalSettings() (*mqlGitlabMergeRequestApprovalSettings, error) {
	res, err := newApprovalSettings(g.MqlRuntime,
		"groups/"+strconv.FormatInt(g.Id.Data, 10)+"/merge_request_approval_setting", "group", g.Id.Data)
	if err != nil {
		return nil, err
	}
	if res == nil {
		g.MergeRequestApprovalSettings.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (p *mqlGitlabProject) mergeRequestApprovalSettings() (*mqlGitlabMergeRequestApprovalSettings, error) {
	res, err := newApprovalSettings(p.MqlRuntime,
		"projects/"+strconv.FormatInt(p.Id.Data, 10)+"/merge_request_approval_setting", "project", p.Id.Data)
	if err != nil {
		return nil, err
	}
	if res == nil {
		p.MergeRequestApprovalSettings.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}
