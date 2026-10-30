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
	apim "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionApiManagementServiceServiceInternal struct {
	cachePublicIpAddressId          string
	cacheSystemData                 any
	cacheUserAssignedIdentityIds    []string
	cachePrivateEndpointConnections []*apim.RemotePrivateEndpointConnectionWrapper
}

func (a *mqlAzureSubscriptionApiManagementServiceService) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionApiManagementServiceService) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, a.TenantId.Data, &a.SystemAssignedIdentity)
}

func (a *mqlAzureSubscriptionApiManagementServiceService) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

// API Management encodes its gateway TLS protocol and cipher policy as
// string "True"/"False" values under these custom-property keys.
const (
	apimTLS10Key        = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10"
	apimTLS11Key        = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11"
	apimSSL30Key        = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30"
	apimBackendTLS10Key = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10"
	apimBackendTLS11Key = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11"
	apimBackendSSL30Key = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30"
	apimTripleDesKey    = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168"
	apimHTTP2Key        = "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2"
)

// apimBoolCustomProperty reads a "True"/"False" API Management custom property,
// returning nil when the key is absent so the field surfaces as null rather
// than a misleading false.
func apimBoolCustomProperty(props map[string]*string, key string) *bool {
	v, ok := props[key]
	if !ok || v == nil {
		return nil
	}
	b := strings.EqualFold(*v, "true")
	return &b
}

func (a *mqlAzureSubscriptionApiManagementService) id() (string, error) {
	return "azure.subscription.apiManagement/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceService) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceService) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func initAzureSubscriptionApiManagementService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionApiManagementService) services() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := apim.NewServiceClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list api management services due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, svc := range page.Value {
			if svc == nil {
				continue
			}

			var skuName string
			var skuCapacity *int32
			if svc.SKU != nil {
				if svc.SKU.Name != nil {
					skuName = string(*svc.SKU.Name)
				}
				skuCapacity = svc.SKU.Capacity
			}

			var identityType string
			var identityPrincipalId, identityTenantId *string
			var userAssignedIdentityIds []string
			if svc.Identity != nil {
				if svc.Identity.Type != nil {
					identityType = string(*svc.Identity.Type)
				}
				identityPrincipalId = svc.Identity.PrincipalID
				identityTenantId = svc.Identity.TenantID
				userAssignedIdentityIds = sortedUserAssignedIdentityIDs(svc.Identity.UserAssignedIdentities)
			}

			var (
				provisioningState         string
				targetProvisioningState   string
				publisherEmail            string
				publisherName             string
				notificationSenderEmail   string
				gatewayUrl                string
				gatewayRegionalUrl        string
				managementApiUrl          string
				portalUrl                 string
				developerPortalUrl        string
				scmUrl                    string
				virtualNetworkType        string
				publicNetworkAccess       string
				natGatewayState           string
				disableGateway            *bool
				enableClientCertificate   *bool
				developerPortalStatus     string
				legacyPortalStatus        string
				platformVersion           string
				customProperties          = map[string]any{}
				tls10Enabled              *bool
				tls11Enabled              *bool
				ssl30Enabled              *bool
				backendTls10Enabled       *bool
				backendTls11Enabled       *bool
				backendSsl30Enabled       *bool
				tripleDesEnabled          *bool
				http2Enabled              *bool
				publicIpAddresses         = []any{}
				privateIpAddresses        = []any{}
				outboundPublicIpAddresses = []any{}
				publicIpAddressId         string
				createdAt                 *time.Time
			)
			if p := svc.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = *p.ProvisioningState
				}
				if p.TargetProvisioningState != nil {
					targetProvisioningState = *p.TargetProvisioningState
				}
				if p.PublisherEmail != nil {
					publisherEmail = *p.PublisherEmail
				}
				if p.PublisherName != nil {
					publisherName = *p.PublisherName
				}
				if p.NotificationSenderEmail != nil {
					notificationSenderEmail = *p.NotificationSenderEmail
				}
				if p.GatewayURL != nil {
					gatewayUrl = *p.GatewayURL
				}
				if p.GatewayRegionalURL != nil {
					gatewayRegionalUrl = *p.GatewayRegionalURL
				}
				if p.ManagementAPIURL != nil {
					managementApiUrl = *p.ManagementAPIURL
				}
				if p.PortalURL != nil {
					portalUrl = *p.PortalURL
				}
				if p.DeveloperPortalURL != nil {
					developerPortalUrl = *p.DeveloperPortalURL
				}
				if p.ScmURL != nil {
					scmUrl = *p.ScmURL
				}
				if p.VirtualNetworkType != nil {
					virtualNetworkType = string(*p.VirtualNetworkType)
				}
				if p.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*p.PublicNetworkAccess)
				}
				if p.NatGatewayState != nil {
					natGatewayState = string(*p.NatGatewayState)
				}
				disableGateway = p.DisableGateway
				enableClientCertificate = p.EnableClientCertificate
				if p.DeveloperPortalStatus != nil {
					developerPortalStatus = string(*p.DeveloperPortalStatus)
				}
				if p.LegacyPortalStatus != nil {
					legacyPortalStatus = string(*p.LegacyPortalStatus)
				}
				if p.PlatformVersion != nil {
					platformVersion = string(*p.PlatformVersion)
				}
				for k, v := range p.CustomProperties {
					if v != nil {
						customProperties[k] = *v
					}
				}
				tls10Enabled = apimBoolCustomProperty(p.CustomProperties, apimTLS10Key)
				tls11Enabled = apimBoolCustomProperty(p.CustomProperties, apimTLS11Key)
				ssl30Enabled = apimBoolCustomProperty(p.CustomProperties, apimSSL30Key)
				backendTls10Enabled = apimBoolCustomProperty(p.CustomProperties, apimBackendTLS10Key)
				backendTls11Enabled = apimBoolCustomProperty(p.CustomProperties, apimBackendTLS11Key)
				backendSsl30Enabled = apimBoolCustomProperty(p.CustomProperties, apimBackendSSL30Key)
				tripleDesEnabled = apimBoolCustomProperty(p.CustomProperties, apimTripleDesKey)
				http2Enabled = apimBoolCustomProperty(p.CustomProperties, apimHTTP2Key)
				for _, ip := range p.PublicIPAddresses {
					if ip != nil {
						publicIpAddresses = append(publicIpAddresses, *ip)
					}
				}
				for _, ip := range p.PrivateIPAddresses {
					if ip != nil {
						privateIpAddresses = append(privateIpAddresses, *ip)
					}
				}
				for _, ip := range p.OutboundPublicIPAddresses {
					if ip != nil {
						outboundPublicIpAddresses = append(outboundPublicIpAddresses, *ip)
					}
				}
				if p.PublicIPAddressID != nil {
					publicIpAddressId = *p.PublicIPAddressID
				}
				createdAt = p.CreatedAtUTC
			}

			zones := []any{}
			for _, z := range svc.Zones {
				if z != nil {
					zones = append(zones, *z)
				}
			}

			mqlSvc, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService.service",
				map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(svc.ID),
					"name":                      llx.StringDataPtr(svc.Name),
					"location":                  llx.StringDataPtr(svc.Location),
					"tags":                      llx.MapData(convert.PtrMapStrToInterface(svc.Tags), types.String),
					"skuName":                   llx.StringData(skuName),
					"skuCapacity":               llx.IntDataPtr(skuCapacity),
					"provisioningState":         llx.StringData(provisioningState),
					"targetProvisioningState":   llx.StringData(targetProvisioningState),
					"publisherEmail":            llx.StringData(publisherEmail),
					"publisherName":             llx.StringData(publisherName),
					"notificationSenderEmail":   llx.StringData(notificationSenderEmail),
					"gatewayUrl":                llx.StringData(gatewayUrl),
					"gatewayRegionalUrl":        llx.StringData(gatewayRegionalUrl),
					"managementApiUrl":          llx.StringData(managementApiUrl),
					"portalUrl":                 llx.StringData(portalUrl),
					"developerPortalUrl":        llx.StringData(developerPortalUrl),
					"scmUrl":                    llx.StringData(scmUrl),
					"virtualNetworkType":        llx.StringData(virtualNetworkType),
					"publicNetworkAccess":       llx.StringData(publicNetworkAccess),
					"natGatewayState":           llx.StringData(natGatewayState),
					"disableGateway":            llx.BoolDataPtr(disableGateway),
					"enableClientCertificate":   llx.BoolDataPtr(enableClientCertificate),
					"developerPortalStatus":     llx.StringData(developerPortalStatus),
					"legacyPortalStatus":        llx.StringData(legacyPortalStatus),
					"platformVersion":           llx.StringData(platformVersion),
					"customProperties":          llx.MapData(customProperties, types.String),
					"tls10Enabled":              llx.BoolDataPtr(tls10Enabled),
					"tls11Enabled":              llx.BoolDataPtr(tls11Enabled),
					"ssl30Enabled":              llx.BoolDataPtr(ssl30Enabled),
					"backendTls10Enabled":       llx.BoolDataPtr(backendTls10Enabled),
					"backendTls11Enabled":       llx.BoolDataPtr(backendTls11Enabled),
					"backendSsl30Enabled":       llx.BoolDataPtr(backendSsl30Enabled),
					"tripleDesEnabled":          llx.BoolDataPtr(tripleDesEnabled),
					"http2Enabled":              llx.BoolDataPtr(http2Enabled),
					"identityType":              llx.StringData(identityType),
					"principalId":               llx.StringDataPtr(identityPrincipalId),
					"tenantId":                  llx.StringDataPtr(identityTenantId),
					"publicIpAddresses":         llx.ArrayData(publicIpAddresses, types.String),
					"privateIpAddresses":        llx.ArrayData(privateIpAddresses, types.String),
					"outboundPublicIpAddresses": llx.ArrayData(outboundPublicIpAddresses, types.String),
					"zones":                     llx.ArrayData(zones, types.String),
					"createdAt":                 llx.TimeDataPtr(createdAt),
				})
			if err != nil {
				return nil, err
			}
			svcRes := mqlSvc.(*mqlAzureSubscriptionApiManagementServiceService)
			svcRes.cachePublicIpAddressId = publicIpAddressId
			svcRes.cacheUserAssignedIdentityIds = userAssignedIdentityIds
			if p := svc.Properties; p != nil {
				svcRes.cachePrivateEndpointConnections = p.PrivateEndpointConnections
			}
			sysData, err := convert.JsonToDict(svc.SystemData)
			if err != nil {
				return nil, err
			}
			svcRes.cacheSystemData = sysData
			res = append(res, mqlSvc)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceService) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	if a.cachePublicIpAddressId == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceIpAddress,
		map[string]*llx.RawData{"id": llx.StringData(a.cachePublicIpAddressId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}
