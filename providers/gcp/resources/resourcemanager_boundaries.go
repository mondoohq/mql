// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

const boundaryResourceName = "gcp.resourcemanager.boundary"

type mqlGcpResourcemanagerBoundaryInternal struct {
	// cacheManagementProject is the management project of the boundary's
	// capability config (projects/{number}), empty when it has none.
	cacheManagementProject string
}

func (g *mqlGcpResourcemanagerBoundary) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// boundaryTagFilter returns the namespaced tag key and the short tag value
// of a boundary's tag filter, both empty when the boundary has none.
func boundaryTagFilter(b *cloudresourcemanager.Boundary) (key, value string) {
	if b == nil || b.ResourceFilter == nil || b.ResourceFilter.TagFilter == nil {
		return "", ""
	}
	return b.ResourceFilter.TagFilter.TagKey, b.ResourceFilter.TagFilter.TagValue
}

// namespacedTagValueName joins a namespaced tag key (123/env) and a tag
// value short name (production) into the namespaced name of the tag value
// (123/env/production). It is empty when either half is.
func namespacedTagValueName(key, value string) string {
	if key == "" || value == "" {
		return ""
	}
	return key + "/" + value
}

func boundaryArgs(b *cloudresourcemanager.Boundary) map[string]*llx.RawData {
	key, value := boundaryTagFilter(b)
	return map[string]*llx.RawData{
		"name":           llx.StringData(b.Name),
		"displayName":    llx.StringData(b.DisplayName),
		"state":          llx.StringData(b.State),
		"tagFilterKey":   llx.StringData(key),
		"tagFilterValue": llx.StringData(value),
		"createTime":     llx.TimeDataPtr(parseTime(b.CreateTime)),
		"updateTime":     llx.TimeDataPtr(parseTime(b.UpdateTime)),
	}
}

func newMqlBoundary(runtime *plugin.Runtime, b *cloudresourcemanager.Boundary) (*mqlGcpResourcemanagerBoundary, error) {
	res, err := CreateResource(runtime, boundaryResourceName, boundaryArgs(b))
	if err != nil {
		return nil, err
	}
	mqlBoundary := res.(*mqlGcpResourcemanagerBoundary)
	mqlBoundary.cacheManagementProject = b.ManagementProject
	return mqlBoundary, nil
}

func boundariesFromPage(runtime *plugin.Runtime, page *cloudresourcemanager.ListBoundariesResponse, res []any) ([]any, error) {
	for _, b := range page.Boundaries {
		if b == nil {
			continue
		}
		mqlBoundary, err := newMqlBoundary(runtime, b)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBoundary)
	}
	return res, nil
}

func (g *mqlGcpOrganization) boundaries() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	res := []any{}
	err = svc.Organizations.Boundaries.List(organizationResourceName(g.Id.Data)).Pages(context.Background(), func(page *cloudresourcemanager.ListBoundariesResponse) error {
		var perr error
		res, perr = boundariesFromPage(g.MqlRuntime, page, res)
		return perr
	})
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.boundaries.list"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpFolder) boundaries() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	res := []any{}
	err = svc.Folders.Boundaries.List(folderResourceName(g.Id.Data)).Pages(context.Background(), func(page *cloudresourcemanager.ListBoundariesResponse) error {
		var perr error
		res, perr = boundariesFromPage(g.MqlRuntime, page, res)
		return perr
	})
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.boundaries.list"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpResourcemanagerBoundary) tagKey() (*mqlGcpOrganizationTagKey, error) {
	if g.TagFilterKey.Error != nil {
		return nil, g.TagFilterKey.Error
	}
	if g.TagFilterKey.Data == "" {
		g.TagKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	k, err := svc.TagKeys.GetNamespaced().Name(g.TagFilterKey.Data).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagKeys.get"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return newMqlTagKey(g.MqlRuntime, k)
}

func (g *mqlGcpResourcemanagerBoundary) tagValue() (*mqlGcpOrganizationTagValue, error) {
	if g.TagFilterKey.Error != nil {
		return nil, g.TagFilterKey.Error
	}
	if g.TagFilterValue.Error != nil {
		return nil, g.TagFilterValue.Error
	}
	name := namespacedTagValueName(g.TagFilterKey.Data, g.TagFilterValue.Data)
	if name == "" {
		g.TagValue.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	client, err := resourceManagerClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	v, err := svc.TagValues.GetNamespaced().Name(name).Context(context.Background()).Do()
	if err != nil {
		if rerr := classifyRefusal(err, "resourcemanager.tagValues.get"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return newMqlTagValue(g.MqlRuntime, v)
}

func (g *mqlGcpResourcemanagerBoundary) managementProject() (*mqlGcpProject, error) {
	proj, err := projectRefById(g.MqlRuntime, projectFromResourceName(g.cacheManagementProject))
	if err != nil {
		return nil, err
	}
	if proj == nil {
		g.ManagementProject.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return proj, nil
}
