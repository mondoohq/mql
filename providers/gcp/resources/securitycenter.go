// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	sccpb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func (g *mqlGcpSccSource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpSccFinding) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpSccNotificationConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpSccMuteConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpSccBigQueryExport) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func newSCCClient(conn *connection.GcpConnection) (*securitycenter.Client, error) {
	creds, err := conn.Credentials(securitycenter.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	return securitycenter.NewClient(context.Background(), option.WithCredentials(creds), connection.GRPCClientTraceOption())
}

// listSCCSources lists Security Command Center sources for a given parent.
// parent should be "organizations/{id}".
func listSCCSources(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListSources(context.Background(), &sccpb.ListSourcesRequest{
		Parent: parent,
	})

	var res []any
	for {
		source, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlSource, err := CreateResource(runtime, "gcp.scc.source", map[string]*llx.RawData{
			"name":          llx.StringData(source.Name),
			"displayName":   llx.StringData(source.DisplayName),
			"description":   llx.StringData(source.Description),
			"canonicalName": llx.StringData(source.CanonicalName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSource)
	}

	return res, nil
}

// listSCCFindings lists Security Command Center findings for a given parent.
// parent should be "organizations/{id}" or "projects/{id}".
func listSCCFindings(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListFindings(context.Background(), &sccpb.ListFindingsRequest{
		Parent:   parent + "/sources/-",
		Filter:   `state="ACTIVE"`,
		PageSize: 1000,
	})

	var res []any
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		f := result.Finding

		sourceProps, err := sourcePropertiesToDict(f.SourceProperties)
		if err != nil {
			return nil, err
		}

		var marks map[string]any
		if f.SecurityMarks != nil {
			marks = make(map[string]any, len(f.SecurityMarks.Marks))
			for k, v := range f.SecurityMarks.Marks {
				marks[k] = v
			}
		}

		compliances := make([]any, 0, len(f.GetCompliances()))
		for _, c := range f.GetCompliances() {
			d, err := protoToDict(c)
			if err != nil {
				return nil, err
			}
			compliances = append(compliances, d)
		}

		vulnerability, err := protoToDict(f.GetVulnerability())
		if err != nil {
			return nil, err
		}

		access, err := protoToDict(f.GetAccess())
		if err != nil {
			return nil, err
		}

		kubernetes, err := protoToDict(f.GetKubernetes())
		if err != nil {
			return nil, err
		}

		connections := make([]any, 0, len(f.GetConnections()))
		for _, c := range f.GetConnections() {
			d, err := protoToDict(c)
			if err != nil {
				return nil, err
			}
			connections = append(connections, d)
		}

		iamBindings := make([]any, 0, len(f.GetIamBindings()))
		for _, b := range f.GetIamBindings() {
			d, err := protoToDict(b)
			if err != nil {
				return nil, err
			}
			iamBindings = append(iamBindings, d)
		}

		internetExposure, err := newMqlSccInternetExposure(runtime, f.Name, f.ExternalExposure)
		if err != nil {
			return nil, err
		}

		mqlFinding, err := CreateResource(runtime, "gcp.scc.finding", map[string]*llx.RawData{
			"name":             llx.StringData(f.Name),
			"parent":           llx.StringData(f.Parent),
			"category":         llx.StringData(f.Category),
			"externalUri":      llx.StringData(f.ExternalUri),
			"sourceProperties": llx.DictData(sourceProps),
			"securityMarks":    llx.DictData(marks),
			"eventTime":        llx.TimeDataPtr(timestampAsTimePtr(f.EventTime)),
			"createTime":       llx.TimeDataPtr(timestampAsTimePtr(f.CreateTime)),
			"severity":         llx.StringData(f.Severity.String()),
			"mute":             llx.StringData(f.Mute.String()),
			"muteInitiator":    llx.StringData(f.GetMuteInitiator()),
			"muteUpdateTime":   llx.TimeDataPtr(timestampAsTimePtr(f.GetMuteUpdateTime())),
			"compliances":      llx.ArrayData(compliances, types.Dict),
			"vulnerability":    llx.DictData(vulnerability),
			"access":           llx.DictData(access),
			"connections":      llx.ArrayData(connections, types.Dict),
			"kubernetes":       llx.DictData(kubernetes),
			"iamBindings":      llx.ArrayData(iamBindings, types.Dict),
			"findingClass":     llx.StringData(f.FindingClass.String()),
			"state":            llx.StringData(f.State.String()),
			"resourceName":     llx.StringData(f.ResourceName),
			"chokepoint":       llx.DictData(chokepointToDict(f.Chokepoint)),
			"externalExposure": llx.DictData(externalExposureToDict(f.ExternalExposure)),
			"internetExposure": internetExposure,
			"toxicCombination": llx.DictData(toxicCombinationToDict(f.ToxicCombination)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFinding)
	}

	return res, nil
}

// sourcePropertiesToDict converts source properties (map[string]*structpb.Value) to map[string]any.
func sourcePropertiesToDict(props map[string]*structpb.Value) (map[string]any, error) {
	if props == nil {
		return nil, nil
	}
	result := make(map[string]any, len(props))
	for k, v := range props {
		result[k] = v.AsInterface()
	}
	return result, nil
}

// chokepointToDict converts a Chokepoint protobuf to a dict.
func chokepointToDict(cp *sccpb.Chokepoint) map[string]any {
	if cp == nil {
		return nil
	}
	return map[string]any{
		"relatedFindings": convert.SliceAnyToInterface(cp.RelatedFindings),
	}
}

// externalExposureToDict converts an ExternalExposure protobuf to a dict.
func externalExposureToDict(ee *sccpb.ExternalExposure) map[string]any {
	if ee == nil {
		return nil
	}
	return map[string]any{
		"privateIpAddress":           ee.PrivateIpAddress,
		"privatePort":                ee.PrivatePort,
		"exposedService":             ee.ExposedService,
		"publicIpAddress":            ee.PublicIpAddress,
		"publicPort":                 ee.PublicPort,
		"exposedEndpoint":            ee.ExposedEndpoint,
		"loadBalancerFirewallPolicy": ee.LoadBalancerFirewallPolicy,
		"serviceFirewallPolicy":      ee.ServiceFirewallPolicy,
		"forwardingRule":             ee.ForwardingRule,
		"backendService":             ee.BackendService,
		"instanceGroup":              ee.InstanceGroup,
		"networkEndpointGroup":       ee.NetworkEndpointGroup,
	}
}

// newMqlSccInternetExposure promotes a finding's external exposure. Returns
// llx.NilData for a finding with no exposure attached, which is every finding
// class other than the internet-reachability ones.
//
// The Compute Engine resources are reported as full resource names, not
// resolved resources: findings are read organization-wide while
// gcp.project.computeService.* is read per project, so a forwarding rule named
// on a finding often lives outside the connected project and a resolved
// reference would read null on a resource that plainly exists.
func newMqlSccInternetExposure(runtime *plugin.Runtime, findingName string, ee *sccpb.ExternalExposure) (*llx.RawData, error) {
	if ee == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "gcp.scc.finding.internetExposure", map[string]*llx.RawData{
		"__id":                       llx.StringData(findingName + "/internetExposure"),
		"publicIpAddress":            llx.StringData(ee.PublicIpAddress),
		"publicPort":                 llx.StringData(ee.PublicPort),
		"privateIpAddress":           llx.StringData(ee.PrivateIpAddress),
		"privatePort":                llx.StringData(ee.PrivatePort),
		"exposedService":             llx.StringData(ee.ExposedService),
		"exposedEndpoint":            llx.StringData(ee.ExposedEndpoint),
		"loadBalancerFirewallPolicy": llx.StringData(ee.LoadBalancerFirewallPolicy),
		"serviceFirewallPolicy":      llx.StringData(ee.ServiceFirewallPolicy),
		"forwardingRule":             llx.StringData(ee.ForwardingRule),
		"backendService":             llx.StringData(ee.BackendService),
		"instanceGroup":              llx.StringData(ee.InstanceGroup),
		"networkEndpointGroup":       llx.StringData(ee.NetworkEndpointGroup),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.scc.finding.internetExposure"), nil
}

// toxicCombinationToDict converts a ToxicCombination protobuf to a dict.
func toxicCombinationToDict(tc *sccpb.ToxicCombination) map[string]any {
	if tc == nil {
		return nil
	}
	return map[string]any{
		"attackExposureScore": tc.AttackExposureScore,
		"relatedFindings":     convert.SliceAnyToInterface(tc.RelatedFindings),
	}
}

// listSCCNotificationConfigs lists SCC notification configs for a given parent.
func listSCCNotificationConfigs(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListNotificationConfigs(context.Background(), &sccpb.ListNotificationConfigsRequest{
		Parent: parent,
	})

	var res []any
	for {
		nc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		filter := ""
		if sc := nc.GetStreamingConfig(); sc != nil {
			filter = sc.Filter
		}

		mqlNC, err := CreateResource(runtime, "gcp.scc.notificationConfig", map[string]*llx.RawData{
			"name":           llx.StringData(nc.Name),
			"description":    llx.StringData(nc.Description),
			"pubsubTopic":    llx.StringData(nc.PubsubTopic),
			"serviceAccount": llx.StringData(nc.ServiceAccount),
			"filter":         llx.StringData(filter),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNC)
	}

	return res, nil
}

// listSCCMuteConfigs lists SCC mute configs for a given parent.
func listSCCMuteConfigs(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListMuteConfigs(context.Background(), &sccpb.ListMuteConfigsRequest{
		Parent: parent,
	})

	var res []any
	for {
		mc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlMC, err := CreateResource(runtime, "gcp.scc.muteConfig", map[string]*llx.RawData{
			"name":             llx.StringData(mc.Name),
			"displayName":      llx.StringData(mc.DisplayName),
			"description":      llx.StringData(mc.Description),
			"filter":           llx.StringData(mc.Filter),
			"createTime":       llx.TimeDataPtr(timestampAsTimePtr(mc.CreateTime)),
			"updateTime":       llx.TimeDataPtr(timestampAsTimePtr(mc.UpdateTime)),
			"mostRecentEditor": llx.StringData(mc.MostRecentEditor),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMC)
	}

	return res, nil
}

// listSCCBigQueryExports lists SCC BigQuery export configs for a given parent.
func listSCCBigQueryExports(runtime *plugin.Runtime, conn *connection.GcpConnection, parent string) ([]any, error) {
	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBigQueryExports(context.Background(), &sccpb.ListBigQueryExportsRequest{
		Parent: parent,
	})

	var res []any
	for {
		bqe, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlBQE, err := CreateResource(runtime, "gcp.scc.bigQueryExport", map[string]*llx.RawData{
			"name":             llx.StringData(bqe.Name),
			"description":      llx.StringData(bqe.Description),
			"dataset":          llx.StringData(bqe.Dataset),
			"filter":           llx.StringData(bqe.Filter),
			"createTime":       llx.TimeDataPtr(timestampAsTimePtr(bqe.CreateTime)),
			"updateTime":       llx.TimeDataPtr(timestampAsTimePtr(bqe.UpdateTime)),
			"mostRecentEditor": llx.StringData(bqe.MostRecentEditor),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBQE)
	}

	return res, nil
}

// Organization-level methods
// Note: org-level SCC methods do not check isServiceEnabled because the Security
// Command Center API is enabled at the project level, not the organization level.
// Organization-scoped queries work as long as the caller has the appropriate IAM
// permissions on the org.

func (g *mqlGcpOrganization) sccParent() (string, *connection.GcpConnection, error) {
	if g.Id.Error != nil {
		return "", nil, g.Id.Error
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	// gcp.organization carries its id as "organizations/{id}" already;
	// prefixing it again addressed "organizations/organizations/{id}".
	return organizationResourceName(g.Id.Data), conn, nil
}

func (g *mqlGcpOrganization) sccSources() ([]any, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}
	return listSCCSources(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpOrganization) sccFindings() ([]any, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}
	return listSCCFindings(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpOrganization) sccNotificationConfigs() ([]any, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}
	return listSCCNotificationConfigs(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpOrganization) sccMuteConfigs() ([]any, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}
	return listSCCMuteConfigs(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpOrganization) sccBigQueryExports() ([]any, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}
	return listSCCBigQueryExports(g.MqlRuntime, conn, parent)
}

func (g *mqlGcpSccOrganizationSettings) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganization) sccOrganizationSettings() (*mqlGcpSccOrganizationSettings, error) {
	parent, conn, err := g.sccParent()
	if err != nil {
		return nil, err
	}

	client, err := newSCCClient(conn)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	settings, err := client.GetOrganizationSettings(context.Background(), &sccpb.GetOrganizationSettingsRequest{
		Name: parent + "/organizationSettings",
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && (s.Code() == codes.PermissionDenied || s.Code() == codes.NotFound) {
			g.SccOrganizationSettings.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	assetDiscoveryConfig, err := protoToDict(settings.AssetDiscoveryConfig)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.scc.organizationSettings", map[string]*llx.RawData{
		"name":                 llx.StringData(settings.Name),
		"enableAssetDiscovery": llx.BoolData(settings.EnableAssetDiscovery),
		"assetDiscoveryConfig": llx.DictData(assetDiscoveryConfig),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpSccOrganizationSettings), nil
}

// Project-level method

func (g *mqlGcpProject) sccFindings() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_securitycenter)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_securitycenter).Msg("gcp service is not enabled, skipping")
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	return listSCCFindings(g.MqlRuntime, conn, "projects/"+projectId)
}
