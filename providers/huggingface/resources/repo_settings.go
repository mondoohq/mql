// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
	"go.mondoo.com/mql/types"
)

// Trusted publishers and access requests are read per repository, and only
// when the field is queried. Reading either needs write or admin rights on the
// repository; like the provider's other listers, a refused or missing answer
// (401, 403, 404) reads as an empty list.

func (r *mqlHuggingfaceModel) trustedPublishers() ([]any, error) {
	return fetchTrustedPublishers(r.MqlRuntime, hfmodels.RepoTypeModel, r.Id.Data)
}

func (r *mqlHuggingfaceDataset) trustedPublishers() ([]any, error) {
	return fetchTrustedPublishers(r.MqlRuntime, hfmodels.RepoTypeDataset, r.Id.Data)
}

func (r *mqlHuggingfaceSpace) trustedPublishers() ([]any, error) {
	return fetchTrustedPublishers(r.MqlRuntime, hfmodels.RepoTypeSpace, r.Id.Data)
}

func fetchTrustedPublishers(runtime *plugin.Runtime, repoType hfmodels.RepoType, repoID string) ([]any, error) {
	client := hfConn(runtime).Client()
	pubs, err := client.ListTrustedPublishers(context.Background(), repoType, repoID)
	if isAccessDenied(err) || isNotFound(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(pubs))
	for _, p := range pubs {
		pres, err := CreateResource(runtime, "huggingface.trustedPublisher", trustedPublisherArgs(repoType, repoID, p))
		if err != nil {
			return nil, err
		}
		res = append(res, pres)
	}
	return res, nil
}

func trustedPublisherArgs(repoType hfmodels.RepoType, repoID string, p hfmodels.TrustedPublisher) map[string]*llx.RawData {
	var configuredBy *string
	if p.ConfiguredBy != nil && p.ConfiguredBy.Name != "" {
		configuredBy = &p.ConfiguredBy.Name
	}
	var claims *llx.RawData = llx.NilData
	if p.Claims != nil {
		claims = llx.DictData(p.Claims)
	}
	return map[string]*llx.RawData{
		"__id":         llx.StringData("huggingface.trustedPublisher/" + string(repoType) + "/" + repoID + "/" + p.ID),
		"id":           llx.StringData(p.ID),
		"issuerUrl":    llx.StringData(p.IssuerURL),
		"claims":       claims,
		"permissions":  llx.ArrayData(stringsToInterface(p.Permissions), types.String),
		"capabilities": llx.ArrayData(stringsToInterface(p.Capabilities), types.String),
		"configuredBy": llx.StringDataPtr(configuredBy),
		"createdAt":    llx.TimeDataPtr(parseHFTime(p.CreatedAt)),
		"lastUsedAt":   llx.TimeDataPtr(parseHFTime(p.LastUsedAt)),
	}
}

func (r *mqlHuggingfaceModel) accessRequests() ([]any, error) {
	return fetchAccessRequests(r.MqlRuntime, hfmodels.RepoTypeModel, r.Id.Data, r.Gated.Data)
}

func (r *mqlHuggingfaceDataset) accessRequests() ([]any, error) {
	return fetchAccessRequests(r.MqlRuntime, hfmodels.RepoTypeDataset, r.Id.Data, r.Gated.Data)
}

// fetchAccessRequests lists the pending and accepted requests on a gated
// repository. An ungated repository has no requests to review, so it costs no
// request.
func fetchAccessRequests(runtime *plugin.Runtime, repoType hfmodels.RepoType, repoID string, gated bool) ([]any, error) {
	if !gated {
		return []any{}, nil
	}
	client := hfConn(runtime).Client()

	res := []any{}
	for _, status := range []hfmodels.AccessRequestStatus{hfmodels.AccessRequestPending, hfmodels.AccessRequestAccepted} {
		reqs, err := client.ListAccessRequests(context.Background(), repoType, repoID, status)
		if isAccessDenied(err) || isNotFound(err) {
			return []any{}, nil
		}
		if err != nil {
			return nil, err
		}
		for _, req := range reqs {
			rres, err := CreateResource(runtime, "huggingface.accessRequest", accessRequestArgs(repoType, repoID, req))
			if err != nil {
				return nil, err
			}
			res = append(res, rres)
		}
	}
	return res, nil
}

func accessRequestArgs(repoType hfmodels.RepoType, repoID string, req hfmodels.AccessRequest) map[string]*llx.RawData {
	var user, grantedBy *string
	if req.User != nil && req.User.User != "" {
		user = &req.User.User
	}
	if req.GrantedBy != nil && req.GrantedBy.User != "" {
		grantedBy = &req.GrantedBy.User
	}
	return map[string]*llx.RawData{
		"__id":        llx.StringData("huggingface.accessRequest/" + string(repoType) + "/" + repoID + "/" + req.RequestID),
		"id":          llx.StringData(req.RequestID),
		"user":        llx.StringDataPtr(user),
		"status":      llx.StringData(req.Status),
		"grantedBy":   llx.StringDataPtr(grantedBy),
		"requestedAt": llx.TimeDataPtr(parseHFTime(req.Timestamp)),
		"reviewedAt":  llx.TimeDataPtr(parseHFTime(req.ReviewedAt)),
	}
}

func (r *mqlHuggingfaceTrustedPublisher) id() (string, error) {
	return r.__id, nil
}

func (r *mqlHuggingfaceAccessRequest) id() (string, error) {
	return r.__id, nil
}
