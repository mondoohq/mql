// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/connection"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
)

func (g *mqlGoogleworkspace) policies() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	service, err := cloudIdentityService(conn, cloudidentity.CloudIdentityPoliciesReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageToken := ""
	for {
		call := service.Policies.List().PageSize(100)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, err
		}
		for _, p := range resp.Policies {
			r, err := newMqlGoogleWorkspacePolicy(g.MqlRuntime, p)
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return res, nil
}

// policyData is the plain-struct projection of a cloudidentity.Policy used to
// build the resource. Value is nil when the setting carried no value or its
// JSON could not be decoded.
type policyData struct {
	Name        string
	Type        string
	SettingType string
	OrgUnit     string
	Group       string
	Query       string
	Value       map[string]any
}

// policyToData projects a cloudidentity.Policy into the plain fields the
// resource exposes. Setting.Value is a googleapi.RawMessage carrying
// setting-specific JSON; a decode failure means the wire shape drifted, so we
// leave Value nil (surfaces as a null field) rather than failing the listing.
func policyToData(entry *cloudidentity.Policy) policyData {
	d := policyData{
		Name: entry.Name,
		Type: entry.Type,
	}
	if entry.PolicyQuery != nil {
		d.OrgUnit = entry.PolicyQuery.OrgUnit
		d.Group = entry.PolicyQuery.Group
		d.Query = entry.PolicyQuery.Query
	}
	if entry.Setting != nil {
		d.SettingType = entry.Setting.Type
		if len(entry.Setting.Value) > 0 {
			var v map[string]any
			if err := json.Unmarshal(entry.Setting.Value, &v); err == nil {
				d.Value = v
			}
		}
	}
	return d
}

func newMqlGoogleWorkspacePolicy(runtime *plugin.Runtime, entry *cloudidentity.Policy) (any, error) {
	d := policyToData(entry)
	args := map[string]*llx.RawData{
		"name":        llx.StringData(d.Name),
		"type":        llx.StringData(d.Type),
		"settingType": llx.StringData(d.SettingType),
		"orgUnit":     llx.StringData(d.OrgUnit),
		"group":       llx.StringData(d.Group),
		"query":       llx.StringData(d.Query),
	}
	if d.Value != nil {
		args["value"] = llx.DictData(d.Value)
	}

	return CreateResource(runtime, "googleworkspace.policy", args)
}

func (g *mqlGoogleworkspacePolicy) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return "googleworkspace.policy/" + g.Name.Data, nil
}
