// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	git "github.com/stackitcloud/stackit-sdk-go/services/git/v1betaapi"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackitGit) id() (string, error) {
	return "stackit.git/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackit) git() (*mqlStackitGit, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.git")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitGit), nil
}

func (r *mqlStackitGit) instances() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Git()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListInstances(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		// The Git API answers 404 for a project that never enabled the service.
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items := resp.GetInstances()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.git.instance", gitInstanceArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// gitInstanceArgs maps a Git instance onto stackit.git.instance. The feature
// toggles are tri-state: an instance that does not report a toggle reads null
// rather than a false the API never sent.
func gitInstanceArgs(inst *git.Instance) map[string]*llx.RawData {
	var localLogin, commitSignatures *bool
	var emailNotifications *string
	if ft, ok := inst.GetFeatureToggleOk(); ok && ft != nil {
		localLogin = optBool(ft.GetEnableLocalLoginOk())
		commitSignatures = optBool(ft.GetEnableCommitSignaturesOk())
		if v, ok := ft.GetDefaultEmailNotificationsOk(); ok && v != nil {
			s := string(*v)
			emailNotifications = &s
		}
	}
	return map[string]*llx.RawData{
		"id":                        llx.StringData(inst.GetId()),
		"name":                      llx.StringData(inst.GetName()),
		"url":                       llx.StringData(inst.GetUrl()),
		"state":                     llx.StringData(string(inst.GetState())),
		"version":                   llx.StringData(inst.GetVersion()),
		"flavor":                    llx.StringData(inst.GetFlavor()),
		"createdAt":                 llx.TimeDataPtr(timeOrNil(inst.GetCreatedOk())),
		"acl":                       strSliceData(inst.GetAcl()),
		"localLoginEnabled":         llx.BoolDataPtr(localLogin),
		"commitSignaturesEnabled":   llx.BoolDataPtr(commitSignatures),
		"defaultEmailNotifications": llx.StringDataPtr(emailNotifications),
	}
}

func (r *mqlStackitGitInstance) id() (string, error) {
	return "stackit.git.instance/" + r.Id.Data, nil
}

func (r *mqlStackitGitInstance) authentications() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Git()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListAuthentication(bgctx(), c.ProjectID(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetAuthentication()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.git.authentication", gitAuthenticationArgs(r.Id.Data, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// gitAuthenticationArgs maps an identity provider definition onto
// stackit.git.authentication. The listing carries no client secret; only the
// public client id is mapped.
func gitAuthenticationArgs(instanceID string, a *git.Authentication) map[string]*llx.RawData {
	scopes := []any{}
	// The API documents scopes as one string; accept space or comma separators.
	for _, s := range strings.FieldsFunc(a.GetScopes(), func(r rune) bool { return r == ' ' || r == ',' }) {
		scopes = append(scopes, s)
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData(qualifiedId("stackit.git.authentication", instanceID, a.GetId())),
		"id":              llx.StringData(a.GetId()),
		"name":            llx.StringData(a.GetName()),
		"provider":        llx.StringData(a.GetProvider()),
		"autoDiscoverUrl": llx.StringData(a.GetAutoDiscoverUrl()),
		"clientId":        llx.StringData(a.GetClientId()),
		"scopes":          llx.ArrayData(scopes, types.String),
		"status":          llx.StringData(a.GetStatus()),
		"createdAt":       llx.TimeDataPtr(timeOrNil(a.GetCreatedAtOk())),
	}
}
