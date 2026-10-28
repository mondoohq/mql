// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionSearchService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionSearchService) id() (string, error) {
	return "azure.subscription.searchService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionSearchServiceService) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSearchService) services() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armsearch.NewServicesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// NewListBySubscriptionPager takes two optional params: *SearchManagementRequestOptions
	// and *ServicesClientListBySubscriptionOptions. Both are left as default (nil).
	pager := client.NewListBySubscriptionPager(nil, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list search services due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, svc := range page.Value {
			if svc == nil {
				continue
			}
			mqlSvc, err := searchServiceToMql(a.MqlRuntime, svc)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSvc)
		}
	}
	return res, nil
}

func searchServiceToMql(runtime *plugin.Runtime, svc *armsearch.Service) (*mqlAzureSubscriptionSearchServiceService, error) {
	sku, err := convert.JsonToDict(svc.SKU)
	svcSku := orZero(svc.SKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(svc.Identity)
	if err != nil {
		return nil, err
	}

	var publicNetworkAccess, cmkEnforcement, cmkComplianceStatus string
	var hostingMode, endpoint, provisioningState, status string
	var disableLocalAuth bool
	var replicaCount, partitionCount int64
	var authMode string
	var aadAuthFailureMode, computeType, semanticSearch, upgradeAvailable *string
	var serviceUpgradedAt *time.Time
	dataExfiltrationProtections := []any{}
	networkRuleSet := llx.NilData
	ipRules := []string{}

	if p := svc.Properties; p != nil {
		if p.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*p.PublicNetworkAccess)
		}
		if p.DisableLocalAuth != nil {
			disableLocalAuth = *p.DisableLocalAuth
		}
		if cmk := p.EncryptionWithCmk; cmk != nil {
			if cmk.Enforcement != nil {
				cmkEnforcement = string(*cmk.Enforcement)
			}
			if cmk.EncryptionComplianceStatus != nil {
				cmkComplianceStatus = string(*cmk.EncryptionComplianceStatus)
			}
		}
		if p.ReplicaCount != nil {
			replicaCount = int64(*p.ReplicaCount)
		}
		if p.PartitionCount != nil {
			partitionCount = int64(*p.PartitionCount)
		}
		if p.HostingMode != nil {
			hostingMode = string(*p.HostingMode)
		}
		if p.Endpoint != nil {
			endpoint = *p.Endpoint
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.Status != nil {
			status = string(*p.Status)
		}
		// AuthOptions is absent when disableLocalAuth is true, where Entra ID
		// is the only option and there is no mode to report.
		if ao := p.AuthOptions; ao != nil {
			if ao.AADOrAPIKey != nil {
				authMode = "aadOrApiKey"
				aadAuthFailureMode = stringEnumPtr(ao.AADOrAPIKey.AADAuthFailureMode)
			} else if ao.APIKeyOnly != nil {
				authMode = "apiKeyOnly"
			}
		}
		for _, dep := range p.DataExfiltrationProtections {
			if dep != nil {
				dataExfiltrationProtections = append(dataExfiltrationProtections, string(*dep))
			}
		}
		computeType = stringEnumPtr(p.ComputeType)
		semanticSearch = stringEnumPtr(p.SemanticSearch)
		upgradeAvailable = stringEnumPtr(p.UpgradeAvailable)
		serviceUpgradedAt = p.ServiceUpgradedAt
		if p.NetworkRuleSet != nil {
			d, err := convert.JsonToDict(p.NetworkRuleSet)
			if err != nil {
				return nil, err
			}
			networkRuleSet = llx.DictData(d)
			for _, r := range p.NetworkRuleSet.IPRules {
				if r != nil && r.Value != nil {
					ipRules = append(ipRules, *r.Value)
				}
			}
		}
	}

	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(svc.ID),
		"name":                          llx.StringDataPtr(svc.Name),
		"location":                      llx.StringDataPtr(svc.Location),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(svc.Tags), types.String),
		"sku":                           llx.DictData(sku),
		"identity":                      llx.DictData(identity),
		"publicNetworkAccess":           llx.StringData(publicNetworkAccess),
		"disableLocalAuth":              llx.BoolData(disableLocalAuth),
		"cmkEnforcement":                llx.StringData(cmkEnforcement),
		"cmkEncryptionComplianceStatus": llx.StringData(cmkComplianceStatus),
		"replicaCount":                  llx.IntData(replicaCount),
		"partitionCount":                llx.IntData(partitionCount),
		"hostingMode":                   llx.StringData(hostingMode),
		"endpoint":                      llx.StringData(endpoint),
		"provisioningState":             llx.StringData(provisioningState),
		"status":                        llx.StringData(status),
		"networkRuleSet":                networkRuleSet,

		"authMode":                    llx.StringData(authMode),
		"aadAuthFailureMode":          llx.StringDataPtr(aadAuthFailureMode),
		"dataExfiltrationProtections": llx.ArrayData(dataExfiltrationProtections, types.String),
		"computeType":                 llx.StringDataPtr(computeType),
		"semanticSearch":              llx.StringDataPtr(semanticSearch),
		"upgradeAvailable":            llx.StringDataPtr(upgradeAvailable),
		"serviceUpgradedAt":           llx.TimeDataPtr(serviceUpgradedAt),
	}
	if err := setSkuData(runtime, args, skuName(svcSku.Name)); err != nil {
		return nil, err
	}
	svcIdentity := orZero(svc.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(svcIdentity.UserAssignedIdentities),
		identityType(svcIdentity.Type), identityPrincipalId(svcIdentity.PrincipalID), identityTenantId(svcIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.searchService.service", args)
	if err != nil {
		return nil, err
	}
	mqlService := res.(*mqlAzureSubscriptionSearchServiceService)
	sysData, err := convert.JsonToDict(svc.SystemData)
	if err != nil {
		return nil, err
	}
	mqlService.cacheSystemData = sysData
	mqlService.cacheIpRules = ipRules
	return mqlService, nil
}

type mqlAzureSubscriptionSearchServiceServiceInternal struct {
	cacheSystemData any
	cacheIpRules    []string
}

// searchServiceInternetReachable reports whether any internet address can reach
// a search service endpoint. The second result is false when the answer cannot
// be given from the service's own properties.
//
// The IP rules are an allowlist that applies only while public access is
// enabled: with no rules every address is admitted, and with rules only the
// listed ranges are, judged as a set so that rules splitting the address space
// between them count as open. When access is securedByPerimeter a network
// security perimeter decides instead, and its rules are not on the service.
func searchServiceInternetReachable(publicNetworkAccess string, ipRules []string) (bool, bool) {
	if strings.EqualFold(strings.TrimSpace(publicNetworkAccess), string(armsearch.PublicNetworkAccessSecuredByPerimeter)) {
		return false, false
	}
	if !publicNetworkAccessEnabled(publicNetworkAccess) {
		return false, true
	}
	if len(ipRules) == 0 {
		return true, true
	}
	return prefixesCoverInternet(ipRules), true
}

func (a *mqlAzureSubscriptionSearchServiceService) internetReachable() (bool, error) {
	reachable, known := searchServiceInternetReachable(a.PublicNetworkAccess.Data, a.cacheIpRules)
	if !known {
		a.InternetReachable.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return reachable, nil
}

func (a *mqlAzureSubscriptionSearchServiceService) diagnosticSettings() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionSearchServiceService) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "search service")
}

func (a *mqlAzureSubscriptionSearchServiceService) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
