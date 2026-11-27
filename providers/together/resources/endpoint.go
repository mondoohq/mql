// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlTogetherEndpointInternal keeps the project that owns the endpoint. The
// deployment list is addressed by project and endpoint, and the project
// accessor resolves it against the project list.
type mqlTogetherEndpointInternal struct {
	cacheProjectID    string
	cacheTrafficSplit []together.EndpointTrafficSplitEntry
}

// mqlTogetherEndpointTrafficSplitEntryInternal keeps the endpoint the entry
// belongs to and the deployment it names, which the deployment accessor
// resolves against the endpoint's deployment list.
type mqlTogetherEndpointTrafficSplitEntryInternal struct {
	cacheEndpoint     *mqlTogetherEndpoint
	cacheDeploymentID string
}

// endpointArgs maps an endpoint from the project endpoint list onto
// together.endpoint. model, state and owner have no source in the v2 endpoint
// API: model and state moved onto the deployments, and an endpoint is owned by
// a project rather than a user. They are null rather than empty, so a policy
// comparing them fails instead of matching an empty string.
func endpointArgs(e together.Endpoint) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(e.ID),
		"id":         llx.StringData(e.ID),
		"name":       llx.StringData(e.Name),
		"model":      llx.NilData,
		"state":      llx.NilData,
		"owner":      llx.NilData,
		"type":       llx.StringData(endpointTypeName(string(e.EndpointType))),
		"visibility": llx.StringData(string(e.Visibility)),
		"createdAt":  llx.TimeDataPtr(timeOrNil(e.CreatedAt)),
		"updatedAt":  llx.TimeDataPtr(timeOrNil(e.UpdatedAt)),
	}
}

// endpointTypeName turns the v2 serving class (ENDPOINT_TYPE_DEDICATED) back
// into the lowercase name the type field has always reported (dedicated).
func endpointTypeName(t string) string {
	return strings.ToLower(strings.TrimPrefix(t, "ENDPOINT_TYPE_"))
}

func (r *mqlTogetherEndpoint) project() (*mqlTogetherProject, error) {
	p, err := listedProject(r.MqlRuntime, r.cacheProjectID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

func (r *mqlTogetherEndpoint) trafficSplit() ([]any, error) {
	res := make([]any, 0, len(r.cacheTrafficSplit))
	for _, entry := range r.cacheTrafficSplit {
		obj, err := CreateResource(r.MqlRuntime, "together.endpoint.trafficSplitEntry", map[string]*llx.RawData{
			"__id":   llx.StringData(r.Id.Data + "/trafficSplit/" + entry.DeploymentID),
			"weight": llx.FloatData(entry.Weight),
		})
		if err != nil {
			return nil, err
		}
		split := obj.(*mqlTogetherEndpointTrafficSplitEntry)
		split.cacheEndpoint = r
		split.cacheDeploymentID = entry.DeploymentID
		res = append(res, split)
	}
	return res, nil
}

func (r *mqlTogetherEndpointTrafficSplitEntry) deployment() (*mqlTogetherEndpointDeployment, error) {
	if r.cacheEndpoint != nil && r.cacheDeploymentID != "" {
		deployments := r.cacheEndpoint.GetDeployments()
		if deployments.Error != nil {
			return nil, deployments.Error
		}
		for _, raw := range deployments.Data {
			if d, ok := raw.(*mqlTogetherEndpointDeployment); ok && d.Id.Data == r.cacheDeploymentID {
				return d, nil
			}
		}
	}
	r.Deployment.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlTogetherEndpoint) deployments() ([]any, error) {
	client := togetherConn(r.MqlRuntime).Client()

	deployments, err := collectPages(client.Endpoints.Deployments.List(context.Background(), r.Id.Data, together.EndpointDeploymentListParams{
		ProjectID: together.Opt(r.cacheProjectID),
	}))
	if err != nil {
		return nil, classifyRefusal(err)
	}

	res := make([]any, 0, len(deployments))
	for _, d := range deployments {
		mqlDeployment, err := CreateResource(r.MqlRuntime, "together.endpoint.deployment", endpointDeploymentArgs(d))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDeployment)
	}
	return res, nil
}

func endpointDeploymentArgs(d together.EndpointDeployment) map[string]*llx.RawData {
	placement := deploymentPlacementOf(d.Placement)

	regions := llx.NilData
	if placement.regions != nil {
		regions = llx.ArrayData(placement.regions, types.String)
	}

	return map[string]*llx.RawData{
		"__id":             llx.StringData(d.ID),
		"id":               llx.StringData(d.ID),
		"name":             llx.StringData(d.Name),
		"model":            llx.StringData(d.Model),
		"state":            llx.StringData(string(d.Status.State)),
		"statusMessage":    llx.StringData(d.Status.Message),
		"trafficMode":      llx.StringData(string(d.TrafficMode)),
		"hardware":         llx.StringData(d.Hardware),
		"desiredReplicas":  llx.IntData(d.DesiredReplicas),
		"readyReplicas":    llx.IntData(d.Status.ReadyReplicas),
		"inactiveTimeout":  llx.IntData(d.InactiveTimeout),
		"hipaaRequired":    llx.BoolDataPtr(placement.hipaa),
		"placementProfile": llx.StringDataPtr(placement.profile),
		"placementRegions": regions,
		// The API omits zero values, so an absent bound is a zero bound.
		"autoscalingMinReplicas":          llx.IntData(d.Autoscaling.MinReplicas),
		"autoscalingMaxReplicas":          llx.IntData(d.Autoscaling.MaxReplicas),
		"maxConcurrentRequestsPerReplica": llx.IntDataPtr(parseConcurrencyLimit(d.MaxConcurrentRequestsPerReplica)),
		"speculator":                      llx.StringDataPtr(nonEmpty(d.Speculator)),
		"createdAt":                       llx.TimeDataPtr(timeOrNil(d.CreatedAt)),
		"updatedAt":                       llx.TimeDataPtr(timeOrNil(d.UpdatedAt)),
	}
}

// parseConcurrencyLimit reads the per-replica concurrency limit, which the API
// serializes as a decimal string. An omitted limit is not zero: zero means
// unlimited, while an omitted one leaves the platform default in force, so it
// is nil. An unreadable value is nil as well.
func parseConcurrencyLimit(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// deploymentPlacement is what a deployment's placement reports about where it
// may run.
type deploymentPlacement struct {
	// hipaa is nil when the placement is a saved profile, whose compliance
	// policy is not part of the deployment.
	hipaa *bool
	// profile is nil unless the placement is a saved profile.
	profile *string
	// regions is nil when the placement is a saved profile.
	regions []any
}

// deploymentPlacementOf reads the placement union. The API omits false and
// empty values, so an inline placement without a compliance policy, or a
// deployment without any placement, carries no HIPAA restriction: that is a
// measured false, not an unknown. Only a saved profile leaves the answer out
// of the deployment.
func deploymentPlacementOf(p together.EndpointDeploymentPlacementUnion) deploymentPlacement {
	if p.JSON.Profile.Valid() && p.Profile != "" {
		profile := p.Profile
		return deploymentPlacement{profile: &profile}
	}

	inline := p.Inline
	hipaa := inline.CompliancePolicy.Hipaa
	regions := make([]any, 0, len(inline.Regions))
	for _, region := range inline.Regions {
		regions = append(regions, region)
	}
	return deploymentPlacement{hipaa: &hipaa, regions: regions}
}

func (r *mqlTogetherEndpointDeployment) id() (string, error) {
	return r.Id.Data, nil
}
