// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

func initGcpProjectDnsServiceManagedzone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// The managed zone is matched by (name, projectId); without both we can't do
	// the lookup. Return an error rather than dereferencing a nil arg (panic) or
	// falling through to build a husk with unset fields.
	if args["name"] == nil || args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.dnsService.managedzone requires name and projectId")
	}

	// Create the parent DNS service and find the specific managed zone
	obj, err := CreateResource(runtime, "gcp.project.dnsService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	dnsSvc := obj.(*mqlGcpProjectDnsService)
	managedzones := dnsSvc.GetManagedZones()
	if managedzones.Error != nil {
		return nil, nil, managedzones.Error
	}

	// Find the matching managed zone. The asset identifier / lookup key is the
	// zone name (getAssetIdentifier stores it in args["name"]), not the numeric
	// zone id — so match on the name field.
	for _, mz := range managedzones.Data {
		managedzone := mz.(*mqlGcpProjectDnsServiceManagedzone)
		name := managedzone.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := managedzone.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, managedzone, nil
		}
	}

	return nil, nil, errors.New("DNS managed zone not found")
}

type mqlGcpProjectDnsServiceInternal struct {
	serviceGate
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectDnsService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_dns)
}

// managedZoneDnssecNonExistence returns the DNSSEC proof-of-nonexistence mode
// ("nsec" or "nsec3") for a managed zone, or "" when DNSSEC is not configured.
func managedZoneDnssecNonExistence(cfg *dns.ManagedZoneDnsSecConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.NonExistence
}

// managedZoneServiceDirectoryNamespaceUrl returns the Service Directory
// namespace a zone resolves names from, or "" when the zone serves its own
// record sets.
//
// The config and its namespace are independently optional, so both are guarded:
// a config present with no namespace still means "no Service Directory backing".
func managedZoneServiceDirectoryNamespaceUrl(cfg *dns.ManagedZoneServiceDirectoryConfig) string {
	if cfg == nil || cfg.Namespace == nil {
		return ""
	}
	return cfg.Namespace.NamespaceUrl
}

// managedZoneReverseLookupEnabled reports whether a zone performs reverse
// lookups.
//
// The API signals this by the presence of the config block rather than by a
// flag inside it, so there is no field to read: an empty, non-nil block means
// enabled.
func managedZoneReverseLookupEnabled(cfg *dns.ManagedZoneReverseLookupConfig) bool {
	return cfg != nil
}

// dnssecStateEnabled reports whether DNSSEC is enabled for a managed zone.
//
// The API documents three states: "off" (not signed), "on" (signed and fully
// managed) and "transfer" (enabled, in transfer mode -- the zone IS signed,
// which is what a zone mid-KSK-transfer reports). Matching only "on" reported a
// signed zone as unsigned, and because dnsSecAlgorithmWeak() short-circuits on
// this predicate it also reported a transfer-state zone signed with RSASHA1 as
// not weak -- a missed finding, not just a false alarm.
func dnssecStateEnabled(cfg *dns.ManagedZoneDnsSecConfig) bool {
	return cfg != nil && cfg.State != "" && cfg.State != "off"
}

func (g *mqlGcpProjectDnsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	id := g.ProjectId.Data
	return "gcp.project.dnsService/" + id, nil
}

func (g *mqlGcpProject) dns() (*mqlGcpProjectDnsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_dns)
	if err != nil {
		return nil, err
	}

	dnsService := res.(*mqlGcpProjectDnsService)
	dnsService.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_dns).Msg("gcp service is not enabled, skipping")
	}

	return dnsService, nil
}

func initGcpProjectDnsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Only default the project from the connection when the caller did not
	// supply one; NewResource runs this init before the resource-cache lookup,
	// so an unconditional overwrite would redirect a caller-scoped reference at
	// the connection's own project.
	if pid, ok := args["projectId"]; !ok || pid == nil {
		args["projectId"] = llx.StringData(conn.ResourceID())
	}

	return args, nil, nil
}

type mqlGcpProjectDnsServiceManagedzoneInternal struct {
	cacheAuthorizedNetworkUrls []string

	// The zone's live signing keys, fetched once and shared by dnsKeys() and
	// dnsSecAlgorithmWeak(). See dns_dnskeys.go.
	dnsKeysLoaded   atomic.Bool
	dnsKeysLock     sync.Mutex
	dnsKeysData     []*dns.DnsKey
	dnsKeysReadable bool
	dnsKeysErr      error
}

func (g *mqlGcpProjectDnsServiceManagedzone) authorizedNetworks() ([]any, error) {
	res := make([]any, 0, len(g.cacheAuthorizedNetworkUrls))
	for _, url := range g.cacheAuthorizedNetworkUrls {
		n, err := getNetworkByUrl(url, g.MqlRuntime)
		if err != nil {
			return nil, err
		}
		if n != nil {
			res = append(res, n)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectDnsServiceManagedzone) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectDnsServiceManagedzone) peeringNetworkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.PeeringNetwork.Error != nil {
		return nil, g.PeeringNetwork.Error
	}
	n, err := getNetworkByUrl(g.PeeringNetwork.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.PeeringNetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectDnsServiceManagedzone) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.dnsService.managedzone/" + projectId + "/" + id, nil
}

func (g *mqlGcpProjectDnsService) managedZones() ([]any, error) {
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

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := dnsSvc.ManagedZones.List(projectId)
	if err := req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for i := range page.ManagedZones {
			managedZone := page.ManagedZones[i]

			var mqlDnssecCfg map[string]any
			dnssecAlgorithms := []any{}
			dnssecAlgorithmSet := map[string]struct{}{}
			dnssecNonExistence := managedZoneDnssecNonExistence(managedZone.DnssecConfig)
			if managedZone.DnssecConfig != nil {
				keySpecs := make([]any, 0, len(managedZone.DnssecConfig.DefaultKeySpecs))
				for _, keySpec := range managedZone.DnssecConfig.DefaultKeySpecs {
					keySpecs = append(keySpecs, map[string]any{
						"algorithm": keySpec.Algorithm,
						"keyLength": keySpec.KeyLength,
						"keyType":   keySpec.KeyType,
					})
					// The ZSK and KSK key specs commonly share an algorithm; emit each distinct value once.
					if _, ok := dnssecAlgorithmSet[keySpec.Algorithm]; keySpec.Algorithm != "" && !ok {
						dnssecAlgorithmSet[keySpec.Algorithm] = struct{}{}
						dnssecAlgorithms = append(dnssecAlgorithms, keySpec.Algorithm)
					}
				}
				mqlDnssecCfg = map[string]any{
					"defaultKeySpecs": keySpecs,
					"nonExistence":    managedZone.DnssecConfig.NonExistence,
					"state":           managedZone.DnssecConfig.State,
				}
			}

			var mqlPrivateVisibilityCfg map[string]any
			authorizedNetworkUrls := []string{}
			if managedZone.PrivateVisibilityConfig != nil {
				networks := make([]any, 0, len(managedZone.PrivateVisibilityConfig.Networks))
				for _, n := range managedZone.PrivateVisibilityConfig.Networks {
					networks = append(networks, map[string]any{
						"networkUrl": n.NetworkUrl,
					})
					if n.NetworkUrl != "" {
						authorizedNetworkUrls = append(authorizedNetworkUrls, n.NetworkUrl)
					}
				}
				gkeClusters := make([]any, 0, len(managedZone.PrivateVisibilityConfig.GkeClusters))
				for _, c := range managedZone.PrivateVisibilityConfig.GkeClusters {
					gkeClusters = append(gkeClusters, map[string]any{
						"gkeClusterName": c.GkeClusterName,
					})
				}
				mqlPrivateVisibilityCfg = map[string]any{
					"networks":    networks,
					"gkeClusters": gkeClusters,
				}
			}

			forwardingTargets := []any{}
			if managedZone.ForwardingConfig != nil {
				for _, target := range managedZone.ForwardingConfig.TargetNameServers {
					if target.Ipv4Address != "" {
						forwardingTargets = append(forwardingTargets, target.Ipv4Address)
					}
				}
			}

			peeringNetwork := ""
			if managedZone.PeeringConfig != nil && managedZone.PeeringConfig.TargetNetwork != nil {
				peeringNetwork = managedZone.PeeringConfig.TargetNetwork.NetworkUrl
			}

			serviceDirectoryNamespaceUrl := managedZoneServiceDirectoryNamespaceUrl(managedZone.ServiceDirectoryConfig)

			mqlManagedZone, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.managedzone", map[string]*llx.RawData{
				"id":                           llx.StringData(strconv.FormatInt(int64(managedZone.Id), 10)),
				"projectId":                    llx.StringData(projectId),
				"name":                         llx.StringData(managedZone.Name),
				"description":                  llx.StringData(managedZone.Description),
				"dnssecConfig":                 llx.DictData(mqlDnssecCfg),
				"dnsName":                      llx.StringData(managedZone.DnsName),
				"nameServerSet":                llx.StringData(managedZone.NameServerSet),
				"nameServers":                  llx.ArrayData(convert.SliceAnyToInterface(managedZone.NameServers), types.String),
				"visibility":                   llx.StringData(managedZone.Visibility),
				"created":                      llx.TimeDataPtr(parseTime(managedZone.CreationTime)),
				"labels":                       llx.MapData(convert.MapToInterfaceMap(managedZone.Labels), types.String),
				"cloudLoggingEnabled":          llx.BoolData(managedZone.CloudLoggingConfig != nil && managedZone.CloudLoggingConfig.EnableLogging),
				"serviceDirectoryNamespaceUrl": llx.StringData(serviceDirectoryNamespaceUrl),
				// The API signals reverse lookup by the presence of the config
				// block rather than by a flag inside it.
				"reverseLookupEnabled":       llx.BoolData(managedZoneReverseLookupEnabled(managedZone.ReverseLookupConfig)),
				"dnssecEnabled":              llx.BoolData(dnssecStateEnabled(managedZone.DnssecConfig)),
				"dnssecNonExistence":         llx.StringData(dnssecNonExistence),
				"dnssecDefaultKeyAlgorithms": llx.ArrayData(dnssecAlgorithms, types.String),
				"privateVisibilityConfig":    llx.DictData(mqlPrivateVisibilityCfg),
				"forwardingTargets":          llx.ArrayData(forwardingTargets, types.String),
				"peeringNetwork":             llx.StringData(peeringNetwork),
			})
			if err != nil {
				return err
			}
			mqlManagedZone.(*mqlGcpProjectDnsServiceManagedzone).cacheAuthorizedNetworkUrls = authorizedNetworkUrls
			res = append(res, mqlManagedZone)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectDnsServicePolicy) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.dnsService.policy/" + projectId + "/" + id, nil
}

func (g *mqlGcpProjectDnsService) policies() ([]any, error) {
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

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := dnsSvc.Policies.List(projectId)
	if err := req.Pages(ctx, func(page *dns.PoliciesListResponse) error {
		for i := range page.Policies {
			policy := page.Policies[i]

			networkNames := make([]any, 0, len(policy.Networks))
			for _, network := range policy.Networks {
				segments := strings.Split(network.NetworkUrl, "/")
				networkNames = append(networkNames, segments[len(segments)-1])
			}

			altNameServers := []any{}
			if policy.AlternativeNameServerConfig != nil {
				for _, target := range policy.AlternativeNameServerConfig.TargetNameServers {
					if target.Ipv4Address != "" {
						altNameServers = append(altNameServers, target.Ipv4Address)
					}
				}
			}

			mqlDnsPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.policy", map[string]*llx.RawData{
				"projectId":               llx.StringData(projectId),
				"id":                      llx.StringData(strconv.FormatInt(int64(policy.Id), 10)),
				"name":                    llx.StringData(policy.Name),
				"description":             llx.StringData(policy.Description),
				"enableInboundForwarding": llx.BoolData(policy.EnableInboundForwarding),
				"enableLogging":           llx.BoolData(policy.EnableLogging),
				"networkNames":            llx.ArrayData(networkNames, types.String),
				"alternativeNameServers":  llx.ArrayData(altNameServers, types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlDnsPolicy)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectDnsServiceResponsePolicy) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.dnsService.responsePolicy/" + projectId + "/" + id, nil
}

func (g *mqlGcpProjectDnsService) responsePolicies() ([]any, error) {
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

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := dnsSvc.ResponsePolicies.List(projectId)
	if err := req.Pages(ctx, func(page *dns.ResponsePoliciesListResponse) error {
		for i := range page.ResponsePolicies {
			responsePolicy := page.ResponsePolicies[i]

			networkUrls := make([]any, 0, len(responsePolicy.Networks))
			for _, network := range responsePolicy.Networks {
				networkUrls = append(networkUrls, network.NetworkUrl)
			}

			gkeClusters := make([]any, 0, len(responsePolicy.GkeClusters))
			for _, c := range responsePolicy.GkeClusters {
				gkeClusters = append(gkeClusters, c.GkeClusterName)
			}

			mqlResponsePolicy, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.responsePolicy", map[string]*llx.RawData{
				"projectId":          llx.StringData(projectId),
				"id":                 llx.StringData(strconv.FormatInt(responsePolicy.Id, 10)),
				"responsePolicyName": llx.StringData(responsePolicy.ResponsePolicyName),
				"description":        llx.StringData(responsePolicy.Description),
				"networkUrls":        llx.ArrayData(networkUrls, types.String),
				"gkeClusters":        llx.ArrayData(gkeClusters, types.String),
				"labels":             llx.MapData(convert.MapToInterfaceMap(responsePolicy.Labels), types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlResponsePolicy)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectDnsServiceResponsePolicy) networks() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	networkUrls := g.GetNetworkUrls()
	if networkUrls.Error != nil {
		return nil, networkUrls.Error
	}

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	gcpCompute := obj.(*mqlGcpProjectComputeService)
	networks := gcpCompute.GetNetworks()
	if networks.Error != nil {
		return nil, networks.Error
	}

	res := make([]any, 0, len(networkUrls.Data))
	for _, network := range networks.Data {
		mqlNetwork := network.(*mqlGcpProjectComputeServiceNetwork)
		for _, raw := range networkUrls.Data {
			url, ok := raw.(string)
			if !ok || url == "" {
				continue
			}
			segments := strings.Split(url, "/")
			if segments[len(segments)-1] == mqlNetwork.Name.Data {
				res = append(res, network)
				break
			}
		}
	}
	return res, nil
}

func (g *mqlGcpProjectDnsServicePolicy) networks() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	networkNames := g.GetNetworkNames()
	if networkNames.Error != nil {
		return nil, networkNames.Error
	}

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	gcpCompute := obj.(*mqlGcpProjectComputeService)
	networks := gcpCompute.GetNetworks()
	if networks.Error != nil {
		return nil, networks.Error
	}

	res := make([]any, 0, len(networkNames.Data))
	for _, network := range networks.Data {
		networkName := network.(*mqlGcpProjectComputeServiceNetwork).Name.Data
		for _, name := range networkNames.Data {
			if name == networkName {
				res = append(res, network)
				break
			}
		}
	}
	return res, nil
}

func (g *mqlGcpProjectDnsServiceRecordset) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	if g.Type.Error != nil {
		return "", g.Type.Error
	}
	// A managed zone can hold several record sets that share a name but
	// differ by type (e.g. an A and an MX record for the same domain), so
	// the type must be part of the key. The authoritative cache key set at
	// creation also includes the managed zone for cross-zone uniqueness.
	return "gcp.project.dnsService.recordset/" + projectId + "/" + g.Name.Data + "/" + g.Type.Data, nil
}

func (g *mqlGcpProjectDnsServiceManagedzone) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	zoneName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	resourcePath := "projects/" + projectId + "/managedZones/" + zoneName
	policy, err := dnsSvc.ManagedZones.GetIamPolicy(resourcePath, &dns.GoogleIamV1GetIamPolicyRequest{Options: &dns.GoogleIamV1GetPolicyOptions{RequestedPolicyVersion: 3}}).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policy.Bindings))
	for i, b := range policy.Bindings {
		condTitle, condExpr, condDesc := "", "", ""
		if b.Condition != nil {
			condTitle = b.Condition.Title
			condExpr = b.Condition.Expression
			condDesc = b.Condition.Description
		}

		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resourcePath + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(condTitle),
			"conditionExpression":  llx.StringData(condExpr),
			"conditionDescription": llx.StringData(condDesc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectDnsServiceManagedzone) recordSets() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	managedZone := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(dns.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	dnsSvc, err := dns.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := dnsSvc.ResourceRecordSets.List(projectId, managedZone)
	if err := req.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for i := range page.Rrsets {
			rSet := page.Rrsets[i]

			mqlDnsPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.recordset", map[string]*llx.RawData{
				// Record sets are keyed by (zone, name, type); include all
				// three so records that share a name don't alias in the cache.
				"__id":             llx.StringData("gcp.project.dnsService.recordset/" + projectId + "/" + managedZone + "/" + rSet.Name + "/" + rSet.Type),
				"projectId":        llx.StringData(projectId),
				"name":             llx.StringData(rSet.Name),
				"rrdatas":          llx.ArrayData(convert.SliceAnyToInterface(rSet.Rrdatas), types.String),
				"signatureRrdatas": llx.ArrayData(convert.SliceAnyToInterface(rSet.SignatureRrdatas), types.String),
				"ttl":              llx.IntData(rSet.Ttl),
				"type":             llx.StringData(rSet.Type),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlDnsPolicy)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}
