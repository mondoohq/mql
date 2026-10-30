// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

type mqlPortainerEdgeJobInternal struct {
	cacheEdgeGroupIds []int64
	cacheEndpointIds  []int64
}

// edgeJobEndpointIDs returns the environment ids an Edge job targets directly,
// in ascending order. The API keys them by environment id rendered as a string;
// an entry whose key is not a number cannot be attributed to an environment and
// is skipped rather than reported against a wrong one.
func edgeJobEndpointIDs(endpoints map[string]models.PortainerEdgeJobEndpointMeta) []int64 {
	ids := make([]int64, 0, len(endpoints))
	for key := range endpoints {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			log.Warn().Str("key", key).Msg("skipping Portainer Edge job target with a non-numeric environment key")
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func newMqlPortainerEdgeJob(runtime *plugin.Runtime, j *models.PortainerEdgeJob) (*mqlPortainerEdgeJob, error) {
	res, err := CreateResource(runtime, "portainer.edgeJob", map[string]*llx.RawData{
		"__id":           llx.StringData("portainer.edgeJob/" + strconv.FormatInt(j.ID, 10)),
		"id":             llx.IntData(j.ID),
		"name":           llx.StringData(j.Name),
		"cronExpression": llx.StringData(j.CronExpression),
		"recurring":      llx.BoolData(j.Recurring),
		"scriptPath":     llx.StringData(j.ScriptPath),
		"version":        llx.IntData(j.Version),
		"created":        llx.TimeDataPtr(unixTimePtr(j.Created)),
	})
	if err != nil {
		return nil, err
	}
	mqlJob := res.(*mqlPortainerEdgeJob)
	mqlJob.cacheEdgeGroupIds = j.EdgeGroups
	mqlJob.cacheEndpointIds = edgeJobEndpointIDs(j.Endpoints)
	return mqlJob, nil
}

func (r *mqlPortainer) edgeJobs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	jobs, err := conn.EdgeJobs()
	if connection.IsForbidden(err) {
		// Listing Edge jobs is administrator-only; a refusal is not evidence
		// that the instance schedules none.
		log.Debug().Msg("not permitted to list Portainer Edge jobs")
		r.EdgeJobs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if connection.IsFeatureDisabled(err) {
		// Edge Compute is switched off, so the instance refuses to answer. That
		// is not the same as "there are no Edge jobs", so the field is reported
		// as null rather than as an empty list an audit would read as a pass.
		log.Debug().Msg("Portainer Edge Compute features are disabled, Edge jobs are unavailable")
		r.EdgeJobs.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(jobs))
	for _, j := range jobs {
		mqlJob, err := newMqlPortainerEdgeJob(r.MqlRuntime, j)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJob)
	}
	return res, nil
}

// edgeGroups resolves the Edge groups the job targets.
func (r *mqlPortainerEdgeJob) edgeGroups() ([]any, error) {
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
		if _, ok := want[g.ID]; !ok {
			continue
		}
		mqlGroup, err := newMqlPortainerEdgeGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// environments resolves the environments the job targets directly, which is the
// set the server expanded from the job's own target list.
func (r *mqlPortainerEdgeJob) environments() ([]any, error) {
	if len(r.cacheEndpointIds) == 0 {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	endpoints, err := conn.Endpoints()
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*models.PortainereeEndpoint, len(endpoints))
	for _, e := range endpoints {
		byID[e.ID] = e
	}
	res := []any{}
	for _, id := range r.cacheEndpointIds {
		e, ok := byID[id]
		if !ok {
			continue
		}
		mqlEnv, err := newMqlPortainerEnvironment(r.MqlRuntime, e)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEnv)
	}
	return res, nil
}
