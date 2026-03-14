// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"

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

	// Find the matching managed zone
	for _, mz := range managedzones.Data {
		managedzone := mz.(*mqlGcpProjectDnsServiceManagedzone)
		id := managedzone.GetId()
		if id.Error != nil {
			return nil, nil, id.Error
		}
		projectId := managedzone.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if id.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, managedzone, nil
		}
	}

	return nil, nil, errors.New("DNS managed zone not found")
}

type mqlGcpProjectDnsServiceInternal struct {
	serviceEnabled bool
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
	dnsService.serviceEnabled = serviceEnabled

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

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
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
	// when the service is not enabled, we return nil
	if !g.serviceEnabled {
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
			if managedZone.DnssecConfig != nil {
				keySpecs := make([]any, 0, len(managedZone.DnssecConfig.DefaultKeySpecs))
				for _, keySpec := range managedZone.DnssecConfig.DefaultKeySpecs {
					keySpecs = append(keySpecs, map[string]any{
						"algorithm": keySpec.Algorithm,
						"keyLength": keySpec.KeyLength,
						"keyType":   keySpec.KeyType,
					})
				}
				mqlDnssecCfg = map[string]any{
					"defaultKeySpecs": keySpecs,
					"nonExistence":    managedZone.DnssecConfig.NonExistence,
					"state":           managedZone.DnssecConfig.State,
				}
			}

			mqlManagedZone, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.managedzone", map[string]*llx.RawData{
				"id":                  llx.StringData(strconv.FormatInt(int64(managedZone.Id), 10)),
				"projectId":           llx.StringData(projectId),
				"name":                llx.StringData(managedZone.Name),
				"description":         llx.StringData(managedZone.Description),
				"dnssecConfig":        llx.DictData(mqlDnssecCfg),
				"dnsName":             llx.StringData(managedZone.DnsName),
				"nameServerSet":       llx.StringData(managedZone.NameServerSet),
				"nameServers":         llx.ArrayData(convert.SliceAnyToInterface(managedZone.NameServers), types.String),
				"visibility":          llx.StringData(managedZone.Visibility),
				"created":             llx.TimeDataPtr(parseTime(managedZone.CreationTime)),
				"labels":              llx.MapData(convert.MapToInterfaceMap(managedZone.Labels), types.String),
				"cloudLoggingEnabled": llx.BoolData(managedZone.CloudLoggingConfig != nil && managedZone.CloudLoggingConfig.EnableLogging),
				"dnssecEnabled":       llx.BoolData(managedZone.DnssecConfig != nil && managedZone.DnssecConfig.State == "on"),
			})
			if err != nil {
				return err
			}
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
	// when the service is not enabled, we return nil
	if !g.serviceEnabled {
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

			mqlDnsPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.dnsService.policy", map[string]*llx.RawData{
				"projectId":               llx.StringData(projectId),
				"id":                      llx.StringData(strconv.FormatInt(int64(policy.Id), 10)),
				"name":                    llx.StringData(policy.Name),
				"description":             llx.StringData(policy.Description),
				"enableInboundForwarding": llx.BoolData(policy.EnableInboundForwarding),
				"enableLogging":           llx.BoolData(policy.EnableLogging),
				"networkNames":            llx.ArrayData(networkNames, types.String),
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
	id := g.Name.Data
	return "gcp.project.dnsService.recordset/" + projectId + "/" + id, nil
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
