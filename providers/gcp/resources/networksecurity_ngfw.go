// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	networksecurity "google.golang.org/api/networksecurity/v1"
	"google.golang.org/api/option"
)

// Cloud NGFW Enterprise firewall endpoints and their associations, and Secure
// Web Proxy gateway security policies.

// wildcardLocationUnsupported reports whether a list call rejected the
// locations/- wildcard. Network Security answers a method that does not
// aggregate across locations with a 400 naming the "aggregated list".
func wildcardLocationUnsupported(err error) bool {
	gerr, ok := googleAPIError(err)
	if !ok || gerr.Code != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(gerr.Error()), "aggregated list")
}

// listAcrossLocations lists a location-scoped collection under scope
// ("projects/{id}" or "organizations/{id}"). It asks once with the
// locations/- wildcard and, when the method rejects the wildcard, once per
// location that locations returns. A location that refuses the call is
// logged and skipped, keeping what the others returned (ADR 046 section 8).
func listAcrossLocations(scope string, locations func() ([]string, error), list func(parent string) error) error {
	err := list(scope + "/locations/-")
	if err == nil || !wildcardLocationUnsupported(err) {
		return err
	}
	locs, err := locations()
	if err != nil {
		return err
	}
	for _, l := range locs {
		if err := list(scope + "/locations/" + l); err != nil {
			if isInapplicable(err) {
				log.Warn().Err(err).Str("location", l).Msg("could not list network security resources in location, skipping")
				continue
			}
			return err
		}
	}
	return nil
}

// zonesOnly keeps the zone ids of a location list (us-central1-a), which is
// where firewall endpoints and their associations live.
func zonesOnly(locations []*networksecurity.Location) []string {
	var res []string
	for _, l := range locations {
		if l == nil || l.LocationId == "" || !zonalLocationSuffix.MatchString(l.LocationId) {
			continue
		}
		res = append(res, l.LocationId)
	}
	return res
}

// networkSecurityHTTPClientFor returns the authenticated HTTP client for the API. Each caller
// constructs its own service from it, inline, so the permission extractor can
// trace the calls made on it.
func networkSecurityHTTPClientFor(runtime *plugin.Runtime) (*http.Client, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Client(networksecurity.CloudPlatformScope)
}

// Firewall endpoints

type mqlGcpOrganizationFirewallEndpointInternal struct {
	cacheAssociations     []*networksecurity.FirewallEndpointAssociationReference
	cacheBillingProjectId string
}

func (g *mqlGcpOrganizationFirewallEndpoint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func newMqlFirewallEndpoint(runtime *plugin.Runtime, e *networksecurity.FirewallEndpoint) (*mqlGcpOrganizationFirewallEndpoint, error) {
	jumboFrames := false
	if e.EndpointSettings != nil {
		jumboFrames = e.EndpointSettings.JumboFramesEnabled
	}
	res, err := CreateResource(runtime, "gcp.organization.firewallEndpoint", map[string]*llx.RawData{
		"name":               llx.StringData(e.Name),
		"zone":               llx.StringData(parseLocationFromPath(e.Name)),
		"description":        llx.StringData(e.Description),
		"state":              llx.StringData(e.State),
		"reconciling":        llx.BoolData(e.Reconciling),
		"jumboFramesEnabled": llx.BoolData(jumboFrames),
		"labels":             llx.MapData(convert.MapToInterfaceMap(e.Labels), types.String),
		"created":            llx.TimeDataPtr(parseTime(e.CreateTime)),
		"updated":            llx.TimeDataPtr(parseTime(e.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlEndpoint := res.(*mqlGcpOrganizationFirewallEndpoint)
	mqlEndpoint.cacheAssociations = e.Associations
	mqlEndpoint.cacheBillingProjectId = e.BillingProjectId
	return mqlEndpoint, nil
}

func (g *mqlGcpOrganization) firewallEndpoints() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	org := organizationResourceName(g.Id.Data)
	httpClient, err := networkSecurityHTTPClientFor(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	nsSvc, err := networksecurity.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	res := []any{}
	zones := func() ([]string, error) {
		var locs []*networksecurity.Location
		err := nsSvc.Organizations.Locations.List(org).Pages(ctx, func(page *networksecurity.ListLocationsResponse) error {
			locs = append(locs, page.Locations...)
			return nil
		})
		return zonesOnly(locs), err
	}
	err = listAcrossLocations(org, zones, func(parent string) error {
		return nsSvc.Organizations.Locations.FirewallEndpoints.List(parent).Pages(ctx, func(page *networksecurity.ListFirewallEndpointsResponse) error {
			for _, u := range page.Unreachable {
				log.Warn().Str("location", u).Msg("could not list firewall endpoints in an unreachable location")
			}
			for _, e := range page.FirewallEndpoints {
				if e == nil {
					continue
				}
				mqlEndpoint, err := newMqlFirewallEndpoint(g.MqlRuntime, e)
				if err != nil {
					return err
				}
				res = append(res, mqlEndpoint)
			}
			return nil
		})
	})
	if err != nil {
		return listRefusal(err, "could not list firewall endpoints", "networksecurity.firewallEndpoints.list")
	}
	return res, nil
}

func (g *mqlGcpOrganizationFirewallEndpoint) associatedNetworks() ([]any, error) {
	res := []any{}
	seen := map[string]bool{}
	for _, a := range g.cacheAssociations {
		if a == nil || a.Network == "" || seen[a.Network] {
			continue
		}
		seen[a.Network] = true
		network, err := getNetworkByUrl(a.Network, g.MqlRuntime)
		if err != nil {
			// A network in a project this scan cannot read establishes nothing
			// about the others the endpoint serves.
			if classifyRefusal(err) != nil {
				log.Warn().Err(err).Str("network", a.Network).Msg("could not resolve firewall endpoint network")
				continue
			}
			return nil, err
		}
		if network != nil {
			res = append(res, network)
		}
	}
	return res, nil
}

func (g *mqlGcpOrganizationFirewallEndpoint) billingProject() (*mqlGcpProject, error) {
	if g.cacheBillingProjectId == "" {
		g.BillingProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(g.cacheBillingProjectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProject), nil
}

// getFirewallEndpointByName reads one firewall endpoint by its full resource
// name. Endpoints are normally organization-scoped, but the API also accepts
// project-scoped ones, so both parents are handled.
func getFirewallEndpointByName(runtime *plugin.Runtime, name string) (*mqlGcpOrganizationFirewallEndpoint, error) {
	httpClient, err := networkSecurityHTTPClientFor(runtime)
	if err != nil {
		return nil, err
	}
	nsSvc, err := networksecurity.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	var e *networksecurity.FirewallEndpoint
	if strings.HasPrefix(name, "projects/") {
		e, err = nsSvc.Projects.Locations.FirewallEndpoints.Get(name).Do()
	} else {
		e, err = nsSvc.Organizations.Locations.FirewallEndpoints.Get(name).Do()
	}
	if err != nil {
		if rerr := classifyRefusal(err, "networksecurity.firewallEndpoints.get"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return newMqlFirewallEndpoint(runtime, e)
}

// Firewall endpoint associations

type mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociationInternal struct {
	cacheNetwork             string
	cacheFirewallEndpoint    string
	cacheTlsInspectionPolicy string
}

func (g *mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociation) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityService) firewallEndpointAssociations() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	project := "projects/" + g.ProjectId.Data
	httpClient, err := networkSecurityHTTPClientFor(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	nsSvc, err := networksecurity.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	res := []any{}
	zones := func() ([]string, error) {
		var locs []*networksecurity.Location
		err := nsSvc.Projects.Locations.List(project).Pages(ctx, func(page *networksecurity.ListLocationsResponse) error {
			locs = append(locs, page.Locations...)
			return nil
		})
		return zonesOnly(locs), err
	}
	err = listAcrossLocations(project, zones, func(parent string) error {
		return nsSvc.Projects.Locations.FirewallEndpointAssociations.List(parent).Pages(ctx, func(page *networksecurity.ListFirewallEndpointAssociationsResponse) error {
			for _, u := range page.Unreachable {
				log.Warn().Str("location", u).Msg("could not list firewall endpoint associations in an unreachable location")
			}
			for _, a := range page.FirewallEndpointAssociations {
				if a == nil {
					continue
				}
				mqlAssoc, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.firewallEndpointAssociation", map[string]*llx.RawData{
					"name":        llx.StringData(a.Name),
					"zone":        llx.StringData(parseLocationFromPath(a.Name)),
					"state":       llx.StringData(a.State),
					"disabled":    llx.BoolData(a.Disabled),
					"reconciling": llx.BoolData(a.Reconciling),
					"labels":      llx.MapData(convert.MapToInterfaceMap(a.Labels), types.String),
					"created":     llx.TimeDataPtr(parseTime(a.CreateTime)),
					"updated":     llx.TimeDataPtr(parseTime(a.UpdateTime)),
				})
				if err != nil {
					return err
				}
				ref := mqlAssoc.(*mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociation)
				ref.cacheNetwork = a.Network
				ref.cacheFirewallEndpoint = a.FirewallEndpoint
				ref.cacheTlsInspectionPolicy = a.TlsInspectionPolicy
				res = append(res, mqlAssoc)
			}
			return nil
		})
	})
	if err != nil {
		return listRefusal(err, "could not list firewall endpoint associations", "networksecurity.firewallEndpointAssociations.list")
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociation) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetwork == "" {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
}

func (g *mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociation) firewallEndpoint() (*mqlGcpOrganizationFirewallEndpoint, error) {
	if g.cacheFirewallEndpoint == "" {
		g.FirewallEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return getFirewallEndpointByName(g.MqlRuntime, g.cacheFirewallEndpoint)
}

func (g *mqlGcpProjectNetworkSecurityServiceFirewallEndpointAssociation) tlsInspectionPolicy() (*mqlGcpProjectNetworkSecurityServiceTlsInspectionPolicy, error) {
	policy, err := tlsInspectionPolicyByName(g.MqlRuntime, g.cacheTlsInspectionPolicy)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		g.TlsInspectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return policy, nil
}

// tlsInspectionPolicyByName resolves a TLS inspection policy from its full
// resource name through the owning project's cached policy list. It returns
// nil for an empty name or a policy the list does not hold.
func tlsInspectionPolicyByName(runtime *plugin.Runtime, name string) (*mqlGcpProjectNetworkSecurityServiceTlsInspectionPolicy, error) {
	if name == "" {
		return nil, nil
	}
	projectId := projectFromResourceName(name)
	if projectId == "" {
		return nil, nil
	}
	obj, err := CreateResource(runtime, "gcp.project.networkSecurityService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	policies := obj.(*mqlGcpProjectNetworkSecurityService).GetTlsInspectionPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, p := range policies.Data {
		policy, ok := p.(*mqlGcpProjectNetworkSecurityServiceTlsInspectionPolicy)
		if ok && policy.Name.Data == name {
			return policy, nil
		}
	}
	return nil, nil
}

// Secure Web Proxy gateway security policies

type mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicyInternal struct {
	cacheTlsInspectionPolicy string
}

func (g *mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicyRule) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityService) gatewaySecurityPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	httpClient, err := networkSecurityHTTPClientFor(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	nsSvc, err := networksecurity.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	res := []any{}
	regions := func() ([]string, error) {
		return listNetworkSecurityLocations(ctx, nsSvc, projectId)
	}
	err = listAcrossLocations("projects/"+projectId, regions, func(parent string) error {
		return nsSvc.Projects.Locations.GatewaySecurityPolicies.List(parent).Pages(ctx, func(page *networksecurity.ListGatewaySecurityPoliciesResponse) error {
			for _, p := range page.GatewaySecurityPolicies {
				if p == nil {
					continue
				}
				mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.gatewaySecurityPolicy", map[string]*llx.RawData{
					"name":        llx.StringData(p.Name),
					"location":    llx.StringData(parseLocationFromPath(p.Name)),
					"description": llx.StringData(p.Description),
					"created":     llx.TimeDataPtr(parseTime(p.CreateTime)),
					"updated":     llx.TimeDataPtr(parseTime(p.UpdateTime)),
				})
				if err != nil {
					return err
				}
				mqlPolicy.(*mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicy).cacheTlsInspectionPolicy = p.TlsInspectionPolicy
				res = append(res, mqlPolicy)
			}
			return nil
		})
	})
	if err != nil {
		return listRefusal(err, "could not list gateway security policies", "networksecurity.gatewaySecurityPolicies.list")
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicy) tlsInspectionPolicy() (*mqlGcpProjectNetworkSecurityServiceTlsInspectionPolicy, error) {
	policy, err := tlsInspectionPolicyByName(g.MqlRuntime, g.cacheTlsInspectionPolicy)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		g.TlsInspectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return policy, nil
}

func (g *mqlGcpProjectNetworkSecurityServiceGatewaySecurityPolicy) rules() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	httpClient, err := networkSecurityHTTPClientFor(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	nsSvc, err := networksecurity.NewService(context.Background(), option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	res := []any{}
	err = nsSvc.Projects.Locations.GatewaySecurityPolicies.Rules.List(g.Name.Data).Pages(ctx, func(page *networksecurity.ListGatewaySecurityPolicyRulesResponse) error {
		for _, r := range page.GatewaySecurityPolicyRules {
			if r == nil {
				continue
			}
			mqlRule, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.gatewaySecurityPolicy.rule", map[string]*llx.RawData{
				"name":                 llx.StringData(r.Name),
				"description":          llx.StringData(r.Description),
				"priority":             llx.IntData(r.Priority),
				"enabled":              llx.BoolData(r.Enabled),
				"basicProfile":         llx.StringData(r.BasicProfile),
				"sessionMatcher":       llx.StringData(r.SessionMatcher),
				"applicationMatcher":   llx.StringData(r.ApplicationMatcher),
				"tlsInspectionEnabled": llx.BoolData(r.TlsInspectionEnabled),
				"created":              llx.TimeDataPtr(parseTime(r.CreateTime)),
				"updated":              llx.TimeDataPtr(parseTime(r.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlRule)
		}
		return nil
	})
	if err != nil {
		return listRefusal(err, "could not list gateway security policy rules", "networksecurity.gatewaySecurityPolicyRules.list")
	}
	return res, nil
}
