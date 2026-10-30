// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

type mqlPortainerEdgeGroupInternal struct {
	cacheEndpointIds []int64
}

type mqlPortainerEdgeStackInternal struct {
	cacheEdgeGroupIds []int64
}

func newMqlPortainerEdgeGroup(runtime *plugin.Runtime, g *models.EdgegroupsDecoratedEdgeGroup) (*mqlPortainerEdgeGroup, error) {
	res, err := CreateResource(runtime, "portainer.edgeGroup", map[string]*llx.RawData{
		"__id":         llx.StringData("portainer.edgeGroup/" + strconv.FormatInt(g.ID, 10)),
		"id":           llx.IntData(g.ID),
		"name":         llx.StringData(g.Name),
		"dynamic":      llx.BoolData(g.Dynamic),
		"hasEdgeStack": llx.BoolData(g.HasEdgeStack),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := res.(*mqlPortainerEdgeGroup)
	mqlGroup.cacheEndpointIds = g.Endpoints
	return mqlGroup, nil
}

// environments resolves the cached endpoint ids to the environments in the
// group.
func (r *mqlPortainerEdgeGroup) environments() ([]any, error) {
	if len(r.cacheEndpointIds) == 0 {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	endpoints, err := conn.Endpoints()
	if err != nil {
		return nil, err
	}
	want := make(map[int64]struct{}, len(r.cacheEndpointIds))
	for _, id := range r.cacheEndpointIds {
		want[id] = struct{}{}
	}
	res := []any{}
	for _, e := range endpoints {
		if _, ok := want[e.ID]; ok {
			mqlEnv, err := newMqlPortainerEnvironment(r.MqlRuntime, e)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEnv)
		}
	}
	return res, nil
}

func (r *mqlPortainer) edgeGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	groups, err := conn.EdgeGroups()
	if err != nil {
		// Edge Compute can be disabled on the instance, in which case the
		// endpoint errors. Degrade to an empty list rather than failing the
		// whole scan, while still logging genuine failures.
		log.Warn().Err(err).Msg("could not list Portainer edge groups; treating as none (Edge Compute may be disabled)")
		return []any{}, nil
	}

	res := make([]any, 0, len(groups))
	for _, g := range groups {
		mqlGroup, err := newMqlPortainerEdgeGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

func newMqlPortainerEdgeStack(runtime *plugin.Runtime, s *models.PortainereeEdgeStack) (*mqlPortainerEdgeStack, error) {
	res, err := CreateResource(runtime, "portainer.edgeStack", map[string]*llx.RawData{
		"__id":           llx.StringData("portainer.edgeStack/" + strconv.FormatInt(s.ID, 10)),
		"id":             llx.IntData(s.ID),
		"name":           llx.StringData(s.Name),
		"deploymentType": llx.StringData(connection.EdgeStackDeploymentType(s.DeploymentType)),
		"numDeployments": llx.IntData(s.NumDeployments),
		"version":        llx.IntData(s.Version),
		"creationDate":   llx.TimeDataPtr(unixTimePtr(s.CreationDate)),
	})
	if err != nil {
		return nil, err
	}
	mqlStack := res.(*mqlPortainerEdgeStack)
	mqlStack.cacheEdgeGroupIds = s.EdgeGroups
	return mqlStack, nil
}

// edgeGroups resolves the cached edge group ids to the edge groups the stack
// targets.
func (r *mqlPortainerEdgeStack) edgeGroups() ([]any, error) {
	if len(r.cacheEdgeGroupIds) == 0 {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	groups, err := conn.EdgeGroups()
	if err != nil {
		return nil, err
	}
	want := make(map[int64]struct{}, len(r.cacheEdgeGroupIds))
	for _, id := range r.cacheEdgeGroupIds {
		want[id] = struct{}{}
	}
	res := []any{}
	for _, g := range groups {
		if _, ok := want[g.ID]; ok {
			mqlGroup, err := newMqlPortainerEdgeGroup(r.MqlRuntime, g)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func (r *mqlPortainer) edgeStacks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	stacks, err := conn.Client().ListEdgeStacks()
	if err != nil {
		// As with edge groups, the endpoint errors when Edge Compute is
		// disabled; degrade to an empty list instead of failing the scan.
		log.Warn().Err(err).Msg("could not list Portainer edge stacks; treating as none (Edge Compute may be disabled)")
		return []any{}, nil
	}

	res := make([]any, 0, len(stacks))
	for _, s := range stacks {
		mqlStack, err := newMqlPortainerEdgeStack(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlStack)
	}
	return res, nil
}
