// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
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
	cacheProjectID string
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
	if r.cacheProjectID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(r.MqlRuntime, "together", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	projects := obj.(*mqlTogether).GetProjects()
	if projects.Error != nil {
		return nil, projects.Error
	}
	for _, p := range projects.Data {
		if project := p.(*mqlTogetherProject); project.Id.Data == r.cacheProjectID {
			return project, nil
		}
	}

	r.Project.State = plugin.StateIsSet | plugin.StateIsNull
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
		"createdAt":        llx.TimeDataPtr(timeOrNil(d.CreatedAt)),
		"updatedAt":        llx.TimeDataPtr(timeOrNil(d.UpdatedAt)),
	}
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
