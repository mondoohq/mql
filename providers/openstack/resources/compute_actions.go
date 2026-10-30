// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/instanceactions"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackComputeServerActionInternal struct {
	cacheServer    *mqlOpenstackComputeServer
	cacheUserID    string
	cacheProjectID string
}

// actions reads this server's action log. Nova only exposes it per server, so
// this is one call per server and it stays lazy until the field is asked for.
func (r *mqlOpenstackComputeServer) actions() ([]any, error) {
	client, err := conn(r.MqlRuntime).ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := instanceactions.List(client, r.Id.Data, instanceactions.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := instanceactions.ExtractInstanceActions(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, a := range items {
		res, err := CreateResource(r.MqlRuntime, "openstack.compute.server.action", map[string]*llx.RawData{
			"__id":      llx.StringData("openstack.compute.server.action/" + r.Id.Data + "/" + a.RequestID),
			"action":    llx.StringData(a.Action),
			"message":   llx.StringData(a.Message),
			"requestId": llx.StringData(a.RequestID),
			"startTime": llx.TimeDataPtr(timePtr(a.StartTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlAction := res.(*mqlOpenstackComputeServerAction)
		mqlAction.cacheServer = r
		mqlAction.cacheUserID = a.UserID
		mqlAction.cacheProjectID = a.ProjectID
		out = append(out, mqlAction)
	}
	return out, nil
}

func (r *mqlOpenstackComputeServerAction) server() (*mqlOpenstackComputeServer, error) {
	if r.cacheServer == nil {
		r.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheServer, nil
}

func (r *mqlOpenstackComputeServerAction) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackComputeServerAction) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
