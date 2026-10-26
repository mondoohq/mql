// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
)

func (r *mqlN8n) users() ([]any, error) {
	users, err := n8nConnection(r.MqlRuntime).Client().Users(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(users))
	for _, u := range users {
		res, err := CreateResource(r.MqlRuntime, ResourceN8nUser, map[string]*llx.RawData{
			"id":         llx.StringData(u.ID),
			"email":      llx.StringData(u.Email),
			"firstName":  optString(u.FirstName),
			"lastName":   optString(u.LastName),
			"role":       optString(u.Role),
			"isPending":  llx.BoolDataPtr(u.IsPending),
			"mfaEnabled": llx.BoolDataPtr(u.MfaEnabled),
			"createdAt":  llx.TimeDataPtr(u.CreatedAt),
			"updatedAt":  llx.TimeDataPtr(u.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlN8nUser) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlN8n) tags() ([]any, error) {
	tags, err := n8nConnection(r.MqlRuntime).Client().Tags(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(tags))
	for _, t := range tags {
		res, err := CreateResource(r.MqlRuntime, ResourceN8nTag, map[string]*llx.RawData{
			"id":        llx.StringData(t.ID),
			"name":      llx.StringData(t.Name),
			"createdAt": llx.TimeDataPtr(t.CreatedAt),
			"updatedAt": llx.TimeDataPtr(t.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlN8nTag) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlN8n) communityPackages() ([]any, error) {
	pkgs, err := n8nConnection(r.MqlRuntime).Client().CommunityPackages(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(pkgs))
	for _, p := range pkgs {
		res, err := CreateResource(r.MqlRuntime, ResourceN8nCommunityPackage, map[string]*llx.RawData{
			"name":             llx.StringData(p.Name),
			"installedVersion": llx.StringData(p.InstalledVersion),
			"updateAvailable":  llx.StringData(p.UpdateAvailable),
			"failedLoading":    llx.BoolData(p.FailedLoading),
			"authorName":       optString(p.AuthorName),
			"authorEmail":      optString(p.AuthorEmail),
			"nodeTypes":        stringArray(p.NodeTypes),
			"createdAt":        llx.TimeData(p.CreatedAt),
			"updatedAt":        llx.TimeData(p.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlN8nCommunityPackage) id() (string, error) {
	return r.Name.Data, nil
}
