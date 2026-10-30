// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	domains "google.golang.org/api/domains/v1"
	"google.golang.org/api/option"
)

func (g *mqlGcpProjectCloudDomainsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.cloudDomainsService", g.ProjectId.Data), nil
}

func (g *mqlGcpProject) cloudDomains() (*mqlGcpProjectCloudDomainsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_clouddomains)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_clouddomains).Msg("gcp service is not enabled, skipping")
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudDomainsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"enabled":   llx.BoolData(serviceEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudDomainsService), nil
}

// Direct construction (e.g. `gcp.project.cloudDomainsService.registrations`)
// bypasses gcp.project.cloudDomains(), leaving projectId and enabled unset.
// Delegate to the parent project accessor so both are populated.
func initGcpProjectCloudDomainsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).cloudDomains()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectCloudDomainsService) registrations() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	if !g.Enabled.Data {
		return []any{}, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(domains.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	domainsSvc, err := domains.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// The "-" location wildcard lists registrations across every location in
	// a single aggregated call (Cloud Domains registrations live in global).
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	var mqlRegistrations []any
	err = domainsSvc.Projects.Locations.Registrations.List(parent).Pages(ctx, func(resp *domains.ListRegistrationsResponse) error {
		for _, reg := range resp.Registrations {
			contactPrivacy := ""
			if reg.ContactSettings != nil {
				contactPrivacy = reg.ContactSettings.Privacy
			}

			transferLockState := ""
			effectiveTransferLockState := ""
			renewalMethod := ""
			preferredRenewalMethod := ""
			if reg.ManagementSettings != nil {
				transferLockState = reg.ManagementSettings.TransferLockState
				effectiveTransferLockState = reg.ManagementSettings.EffectiveTransferLockState
				renewalMethod = reg.ManagementSettings.RenewalMethod
				preferredRenewalMethod = reg.ManagementSettings.PreferredRenewalMethod
			}

			dnsProvider := ""
			var nameServers []string
			dnssecState := ""
			var dsRecords []*domains.DsRecord
			if reg.DnsSettings != nil {
				switch {
				// googleDomainsDns is a legacy holdover from before Google Domains
				// was sold to Squarespace; new registrations won't use it, but
				// migrated/older registrations still can.
				case reg.DnsSettings.GoogleDomainsDns != nil:
					dnsProvider = "googleDomainsDns"
					nameServers = reg.DnsSettings.GoogleDomainsDns.NameServers
					dnssecState = reg.DnsSettings.GoogleDomainsDns.DsState
					dsRecords = reg.DnsSettings.GoogleDomainsDns.DsRecords
				case reg.DnsSettings.CustomDns != nil:
					dnsProvider = "customDns"
					nameServers = reg.DnsSettings.CustomDns.NameServers
					dsRecords = reg.DnsSettings.CustomDns.DsRecords
				}
			}

			mqlDsRecords, err := convert.JsonToDictSlice(dsRecords)
			if err != nil {
				log.Error().Err(err).Send()
				mqlDsRecords = []any{}
			}

			mqlReg, err := CreateResource(g.MqlRuntime, "gcp.project.cloudDomainsService.registration", map[string]*llx.RawData{
				"__id":                       llx.StringData(reg.Name),
				"id":                         llx.StringData(reg.Name),
				"projectId":                  llx.StringData(projectId),
				"location":                   llx.StringData(cloudDomainsLocation(reg.Name)),
				"domainName":                 llx.StringData(reg.DomainName),
				"state":                      llx.StringData(reg.State),
				"expireTime":                 llx.TimeDataPtr(parseTime(reg.ExpireTime)),
				"created":                    llx.TimeDataPtr(parseTime(reg.CreateTime)),
				"labels":                     llx.MapData(convert.MapToInterfaceMap(reg.Labels), types.String),
				"issues":                     llx.ArrayData(convert.SliceAnyToInterface(reg.Issues), types.String),
				"domainProperties":           llx.ArrayData(convert.SliceAnyToInterface(reg.DomainProperties), types.String),
				"contactPrivacy":             llx.StringData(contactPrivacy),
				"transferLockState":          llx.StringData(transferLockState),
				"effectiveTransferLockState": llx.StringData(effectiveTransferLockState),
				"renewalMethod":              llx.StringData(renewalMethod),
				"preferredRenewalMethod":     llx.StringData(preferredRenewalMethod),
				"dnsProvider":                llx.StringData(dnsProvider),
				"nameServers":                llx.ArrayData(convert.SliceAnyToInterface(nameServers), types.String),
				"dnssecState":                llx.StringData(dnssecState),
				"dsRecords":                  llx.ArrayData(mqlDsRecords, types.Dict),
			})
			if err != nil {
				log.Error().Err(err).Send()
				continue
			}
			mqlRegistrations = append(mqlRegistrations, mqlReg)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mqlRegistrations, nil
}

// cloudDomainsLocation extracts the location segment from a Cloud Domains
// resource name of the form projects/{project}/locations/{location}/registrations/{registration}.
func cloudDomainsLocation(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}
