// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	networksecurity "google.golang.org/api/networksecurity/v1"
	"google.golang.org/api/option"
)

type mqlGcpProjectNetworkSecurityServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) networkSecurity() (*mqlGcpProjectNetworkSecurityService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	// Check service enablement before creating the resource: a transient error
	// here must not leave a resource cached with serviceEnabled = false, which
	// would make every child accessor silently return nil on later calls.
	serviceEnabled, err := g.isServiceEnabled(service_networksecurity)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectNetworkSecurityService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_networksecurity).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectNetworkSecurityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectNetworkSecurityService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.networkSecurityService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectNetworkSecurityServiceAuthorizationPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceServerTlsPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceClientTlsPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceTlsInspectionPolicy) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceAddressGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkSecurityServiceUrlList) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganizationNetworkSecurityProfile) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpOrganizationNetworkSecurityProfileGroupInternal struct {
	// cacheOrg is the organization the group was listed under, whose profile
	// list resolves the group's profile references.
	cacheOrg                     *mqlGcpOrganization
	cacheWildfireAnalysisProfile string
	cacheUrlFilteringProfile     string
}

func (g *mqlGcpOrganizationNetworkSecurityProfileGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// wildfireAnalysisProfileDict maps a WildFire analysis profile to a dict,
// leaving out the deprecated list form of the inline ML settings. Absent
// profiles yield nil.
func wildfireAnalysisProfileDict(p *networksecurity.WildfireAnalysisProfile) (map[string]any, error) {
	if p == nil {
		return nil, nil
	}
	cp := *p
	cp.WildfireInlineMlSettings = nil
	return convert.JsonToDict(cp)
}

// findNetworkSecurityProfile returns the profile with the given resource name
// from an already-listed set of profiles, or nil when none matches.
func findNetworkSecurityProfile(profiles []any, name string) *mqlGcpOrganizationNetworkSecurityProfile {
	if name == "" {
		return nil
	}
	for _, raw := range profiles {
		p, ok := raw.(*mqlGcpOrganizationNetworkSecurityProfile)
		if !ok || p == nil {
			continue
		}
		if p.Name.Error == nil && p.Name.Data == name {
			return p
		}
	}
	return nil
}

// resolveProfile resolves a profile reference against the organization's
// profile list, so each group costs no extra API call.
func (g *mqlGcpOrganizationNetworkSecurityProfileGroup) resolveProfile(name string) (*mqlGcpOrganizationNetworkSecurityProfile, error) {
	if name == "" || g.cacheOrg == nil {
		return nil, nil
	}
	profiles := g.cacheOrg.GetNetworkSecurityProfiles()
	if profiles.Error != nil {
		return nil, profiles.Error
	}
	return findNetworkSecurityProfile(profiles.Data, name), nil
}

func (g *mqlGcpOrganizationNetworkSecurityProfileGroup) wildfireAnalysisProfile() (*mqlGcpOrganizationNetworkSecurityProfile, error) {
	p, err := g.resolveProfile(g.cacheWildfireAnalysisProfile)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.WildfireAnalysisProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p, nil
}

func (g *mqlGcpOrganizationNetworkSecurityProfileGroup) urlFilteringProfile() (*mqlGcpOrganizationNetworkSecurityProfile, error) {
	p, err := g.resolveProfile(g.cacheUrlFilteringProfile)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.UrlFilteringProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p, nil
}

// networkSecurityHTTPClient resolves an authenticated HTTP client for the
// networksecurity REST API. Each accessor still constructs its own
// networksecurity.Service inline so permission extraction can trace the calls.
func (g *mqlGcpProjectNetworkSecurityService) networkSecurityHTTPClient() (*connection.GcpConnection, string, error) {
	if g.ProjectId.Error != nil {
		return nil, "", g.ProjectId.Error
	}
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, "", errors.New("invalid connection provided, it is not a GCP connection")
	}
	// locations/- aggregates resources across every location
	return conn, fmt.Sprintf("projects/%s/locations/-", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectNetworkSecurityService) authorizationPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, parent, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = nsSvc.Projects.Locations.AuthorizationPolicies.List(parent).Pages(ctx, func(page *networksecurity.ListAuthorizationPoliciesResponse) error {
		for _, p := range page.AuthorizationPolicies {
			rules, err := convert.JsonToDictSlice(p.Rules)
			if err != nil {
				return err
			}
			mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.authorizationPolicy", map[string]*llx.RawData{
				"name":        llx.StringData(p.Name),
				"description": llx.StringData(p.Description),
				"action":      llx.StringData(p.Action),
				"rules":       llx.ArrayData(rules, types.Dict),
				"labels":      llx.MapData(convert.MapToInterfaceMap(p.Labels), types.String),
				"created":     llx.TimeDataPtr(parseTime(p.CreateTime)),
				"updated":     llx.TimeDataPtr(parseTime(p.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPolicy)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list authorization policies")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityService) serverTlsPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, parent, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = nsSvc.Projects.Locations.ServerTlsPolicies.List(parent).Pages(ctx, func(page *networksecurity.ListServerTlsPoliciesResponse) error {
		for _, p := range page.ServerTlsPolicies {
			mtlsPolicy, err := convert.JsonToDict(p.MtlsPolicy)
			if err != nil {
				return err
			}
			serverCertificate, err := convert.JsonToDict(p.ServerCertificate)
			if err != nil {
				return err
			}
			var clientValidationMode string
			if p.MtlsPolicy != nil {
				clientValidationMode = p.MtlsPolicy.ClientValidationMode
			}
			mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.serverTlsPolicy", map[string]*llx.RawData{
				"name":                 llx.StringData(p.Name),
				"description":          llx.StringData(p.Description),
				"allowOpen":            llx.BoolData(p.AllowOpen),
				"mtlsPolicy":           llx.DictData(mtlsPolicy),
				"clientValidationMode": llx.StringData(clientValidationMode),
				"serverCertificate":    llx.DictData(serverCertificate),
				"labels":               llx.MapData(convert.MapToInterfaceMap(p.Labels), types.String),
				"created":              llx.TimeDataPtr(parseTime(p.CreateTime)),
				"updated":              llx.TimeDataPtr(parseTime(p.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPolicy)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list server TLS policies")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// zonalLocationSuffix matches a zone id, which is a region followed by a single
// letter (us-central1-a). The locations endpoint lists zones alongside regions,
// but a zonal parent is rejected as a malformed name, so they are dropped.
//
// The digit is required so the pattern cannot claim a region whose last segment
// happens to be one letter. Every GCP region ends in a number, so a zone always
// reads <region><digit>-<letter>; matching a bare trailing "-x" would drop a
// whole region silently, which is the failure this filter exists to avoid.
var zonalLocationSuffix = regexp.MustCompile(`\d-[a-z]$`)

// listNetworkSecurityLocations returns the non-zonal locations the Network
// Security API reports for the project, which are the parents its regional
// collections can be listed under.
func listNetworkSecurityLocations(ctx context.Context, nsSvc *networksecurity.Service, projectId string) ([]string, error) {
	var locations []string
	err := nsSvc.Projects.Locations.List(fmt.Sprintf("projects/%s", projectId)).
		Pages(ctx, func(page *networksecurity.ListLocationsResponse) error {
			for _, l := range page.Locations {
				if l == nil || l.LocationId == "" || zonalLocationSuffix.MatchString(l.LocationId) {
					continue
				}
				locations = append(locations, l.LocationId)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return locations, nil
}

func (g *mqlGcpProjectNetworkSecurityService) clientTlsPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, _, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// ListClientTlsPolicies is the one method in this API that rejects the
	// locations=- wildcard every other collection here uses, answering
	// "aggregated list (locations=-) is not supported ... for
	// method=ListClientTlsPolicies". So the policies are listed per location,
	// the way Cloud Tasks queues already are for the same reason.
	locations, err := listNetworkSecurityLocations(ctx, nsSvc, g.ProjectId.Data)
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list network security locations")
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	listPage := func(page *networksecurity.ListClientTlsPoliciesResponse) error {
		for _, p := range page.ClientTlsPolicies {
			clientCertificate, err := convert.JsonToDict(p.ClientCertificate)
			if err != nil {
				return err
			}
			serverValidationCa, err := convert.JsonToDictSlice(p.ServerValidationCa)
			if err != nil {
				return err
			}
			mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.clientTlsPolicy", map[string]*llx.RawData{
				"name":               llx.StringData(p.Name),
				"description":        llx.StringData(p.Description),
				"sni":                llx.StringData(p.Sni),
				"clientCertificate":  llx.DictData(clientCertificate),
				"serverValidationCa": llx.ArrayData(serverValidationCa, types.Dict),
				"labels":             llx.MapData(convert.MapToInterfaceMap(p.Labels), types.String),
				"created":            llx.TimeDataPtr(parseTime(p.CreateTime)),
				"updated":            llx.TimeDataPtr(parseTime(p.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPolicy)
		}
		return nil
	}

	for _, location := range locations {
		locParent := fmt.Sprintf("projects/%s/locations/%s", g.ProjectId.Data, location)
		if err := nsSvc.Projects.Locations.ClientTlsPolicies.List(locParent).Pages(ctx, listPage); err != nil {
			// One unreadable location establishes nothing about the others, and
			// the policies already collected are real. Keep them and carry on:
			// abandoning the walk here would report a field that is populated
			// in most regions as empty because one region refused.
			if isSkippable(err) {
				log.Warn().Err(err).Str("location", location).
					Msg("could not list client TLS policies")
				continue
			}
			return nil, err
		}
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityService) tlsInspectionPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, parent, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = nsSvc.Projects.Locations.TlsInspectionPolicies.List(parent).Pages(ctx, func(page *networksecurity.ListTlsInspectionPoliciesResponse) error {
		for _, p := range page.TlsInspectionPolicies {
			customTlsFeatures := make([]any, 0, len(p.CustomTlsFeatures))
			for _, f := range p.CustomTlsFeatures {
				customTlsFeatures = append(customTlsFeatures, f)
			}
			mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.tlsInspectionPolicy", map[string]*llx.RawData{
				"name":                    llx.StringData(p.Name),
				"description":             llx.StringData(p.Description),
				"caPool":                  llx.StringData(p.CaPool),
				"certificateIssuanceMode": llx.StringData(p.CertificateIssuanceMode),
				"minTlsVersion":           llx.StringData(p.MinTlsVersion),
				"tlsFeatureProfile":       llx.StringData(p.TlsFeatureProfile),
				"customTlsFeatures":       llx.ArrayData(customTlsFeatures, types.String),
				"excludePublicCaSet":      llx.BoolData(p.ExcludePublicCaSet),
				"trustConfig":             llx.StringData(p.TrustConfig),
				"created":                 llx.TimeDataPtr(parseTime(p.CreateTime)),
				"updated":                 llx.TimeDataPtr(parseTime(p.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPolicy)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list TLS inspection policies")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityService) addressGroups() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, parent, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = nsSvc.Projects.Locations.AddressGroups.List(parent).Pages(ctx, func(page *networksecurity.ListAddressGroupsResponse) error {
		for _, ag := range page.AddressGroups {
			items := make([]any, 0, len(ag.Items))
			for _, item := range ag.Items {
				items = append(items, item)
			}
			purpose := make([]any, 0, len(ag.Purpose))
			for _, p := range ag.Purpose {
				purpose = append(purpose, p)
			}
			mqlGroup, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.addressGroup", map[string]*llx.RawData{
				"name":        llx.StringData(ag.Name),
				"description": llx.StringData(ag.Description),
				"type":        llx.StringData(ag.Type),
				"items":       llx.ArrayData(items, types.String),
				"capacity":    llx.IntData(ag.Capacity),
				"purpose":     llx.ArrayData(purpose, types.String),
				"labels":      llx.MapData(convert.MapToInterfaceMap(ag.Labels), types.String),
				"created":     llx.TimeDataPtr(parseTime(ag.CreateTime)),
				"updated":     llx.TimeDataPtr(parseTime(ag.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlGroup)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list address groups")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectNetworkSecurityService) urlLists() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	conn, parent, err := g.networkSecurityHTTPClient()
	if err != nil {
		return nil, err
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = nsSvc.Projects.Locations.UrlLists.List(parent).Pages(ctx, func(page *networksecurity.ListUrlListsResponse) error {
		for _, ul := range page.UrlLists {
			values := make([]any, 0, len(ul.Values))
			for _, v := range ul.Values {
				values = append(values, v)
			}
			mqlUrlList, err := CreateResource(g.MqlRuntime, "gcp.project.networkSecurityService.urlList", map[string]*llx.RawData{
				"name":        llx.StringData(ul.Name),
				"description": llx.StringData(ul.Description),
				"values":      llx.ArrayData(values, types.String),
				"created":     llx.TimeDataPtr(parseTime(ul.CreateTime)),
				"updated":     llx.TimeDataPtr(parseTime(ul.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlUrlList)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list URL lists")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// networkSecurityProfiles lists organization-scoped network security profiles.
// Organization-scoped accessors have no serviceusage service-enabled pre-check
// (enablement is per-project); a disabled API surfaces as a 403/404 that
// isSkippable handles below.
func (g *mqlGcpOrganization) networkSecurityProfiles() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("%s/locations/-", g.Id.Data)
	res := []any{}
	err = nsSvc.Organizations.Locations.SecurityProfiles.List(parent).Pages(ctx, func(page *networksecurity.ListSecurityProfilesResponse) error {
		for _, sp := range page.SecurityProfiles {
			threatPreventionProfile, err := convert.JsonToDict(sp.ThreatPreventionProfile)
			if err != nil {
				return err
			}
			urlFilteringProfile, err := convert.JsonToDict(sp.UrlFilteringProfile)
			if err != nil {
				return err
			}
			customMirroringProfile, err := convert.JsonToDict(sp.CustomMirroringProfile)
			if err != nil {
				return err
			}
			customInterceptProfile, err := convert.JsonToDict(sp.CustomInterceptProfile)
			if err != nil {
				return err
			}
			wildfireAnalysisProfile, err := wildfireAnalysisProfileDict(sp.WildfireAnalysisProfile)
			if err != nil {
				return err
			}
			wildfireAnalysisProfileData := llx.NilData
			if wildfireAnalysisProfile != nil {
				wildfireAnalysisProfileData = llx.DictData(wildfireAnalysisProfile)
			}
			mqlProfile, err := CreateResource(g.MqlRuntime, "gcp.organization.networkSecurityProfile", map[string]*llx.RawData{
				"name":                    llx.StringData(sp.Name),
				"description":             llx.StringData(sp.Description),
				"type":                    llx.StringData(sp.Type),
				"threatPreventionProfile": llx.DictData(threatPreventionProfile),
				"urlFilteringProfile":     llx.DictData(urlFilteringProfile),
				"customMirroringProfile":  llx.DictData(customMirroringProfile),
				"customInterceptProfile":  llx.DictData(customInterceptProfile),
				"wildfireAnalysisProfile": wildfireAnalysisProfileData,
				"labels":                  llx.MapData(convert.MapToInterfaceMap(sp.Labels), types.String),
				"etag":                    llx.StringData(sp.Etag),
				"created":                 llx.TimeDataPtr(parseTime(sp.CreateTime)),
				"updated":                 llx.TimeDataPtr(parseTime(sp.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlProfile)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list network security profiles")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// networkSecurityProfileGroups lists organization-scoped network security
// profile groups. See networkSecurityProfiles for why there is no
// service-enabled pre-check.
func (g *mqlGcpOrganization) networkSecurityProfileGroups() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(networksecurity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	nsSvc, err := networksecurity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("%s/locations/-", g.Id.Data)
	res := []any{}
	err = nsSvc.Organizations.Locations.SecurityProfileGroups.List(parent).Pages(ctx, func(page *networksecurity.ListSecurityProfileGroupsResponse) error {
		for _, spg := range page.SecurityProfileGroups {
			mqlGroup, err := CreateResource(g.MqlRuntime, "gcp.organization.networkSecurityProfileGroup", map[string]*llx.RawData{
				"name":                    llx.StringData(spg.Name),
				"description":             llx.StringData(spg.Description),
				"threatPreventionProfile": llx.StringData(spg.ThreatPreventionProfile),
				"customMirroringProfile":  llx.StringData(spg.CustomMirroringProfile),
				"customInterceptProfile":  llx.StringData(spg.CustomInterceptProfile),
				"labels":                  llx.MapData(convert.MapToInterfaceMap(spg.Labels), types.String),
				"etag":                    llx.StringData(spg.Etag),
				"created":                 llx.TimeDataPtr(parseTime(spg.CreateTime)),
				"updated":                 llx.TimeDataPtr(parseTime(spg.UpdateTime)),
			})
			if err != nil {
				return err
			}
			internal := mqlGroup.(*mqlGcpOrganizationNetworkSecurityProfileGroup)
			internal.cacheOrg = g
			internal.cacheWildfireAnalysisProfile = spg.WildfireAnalysisProfile
			internal.cacheUrlFilteringProfile = spg.UrlFilteringProfile
			res = append(res, mqlGroup)
		}
		return nil
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list network security profile groups")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectNetworkSecurityService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_networksecurity)
}
