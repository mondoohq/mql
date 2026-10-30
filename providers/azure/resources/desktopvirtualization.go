// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization/v2"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionDesktopVirtualizationService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionDesktopVirtualizationService) id() (string, error) {
	return "azure.subscription.desktopVirtualizationService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionDesktopVirtualizationServiceHostPool) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDesktopVirtualizationService) hostPools() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	client, err := armdesktopvirtualization.NewHostPoolsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
				log.Warn().Err(err).Msg("could not list Azure Virtual Desktop host pools due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, hp := range page.Value {
			if hp == nil {
				continue
			}
			mqlHp, err := hostPoolToMql(a.MqlRuntime, hp)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHp)
		}
	}
	return res, nil
}

func hostPoolToMql(runtime *plugin.Runtime, hp *armdesktopvirtualization.HostPool) (*mqlAzureSubscriptionDesktopVirtualizationServiceHostPool, error) {
	identity, err := convert.JsonToDict(hp.Identity)
	if err != nil {
		return nil, err
	}

	var hostPoolType, loadBalancerType, preferredAppGroupType, customRdpProperty string
	var personalDesktopAssignmentType, ssoadfsAuthority, publicNetworkAccess, ssoSecretType string
	var startVMOnConnect, validationEnvironment bool
	var maxSessionLimit, ring *int64
	var description, friendlyName, vmTemplate *string
	var registrationTokenExpirationTime *time.Time
	var registrationTokenOperation *string
	var registrationTokenActive *bool
	var agentUpdateType, agentUpdateMaintenanceWindowTimeZone *string
	var agentUpdateUseSessionHostLocalTime *bool
	agentUpdateMaintenanceWindows := []any{}
	privateEndpointConnectionCount := int64(0)
	if p := hp.Properties; p != nil {
		hostPoolType = string(convert.ToValue(p.HostPoolType))
		loadBalancerType = string(convert.ToValue(p.LoadBalancerType))
		preferredAppGroupType = string(convert.ToValue(p.PreferredAppGroupType))
		customRdpProperty = convert.ToValue(p.CustomRdpProperty)
		personalDesktopAssignmentType = string(convert.ToValue(p.PersonalDesktopAssignmentType))
		ssoadfsAuthority = convert.ToValue(p.SsoadfsAuthority)
		startVMOnConnect = convert.ToValue(p.StartVMOnConnect)
		validationEnvironment = convert.ToValue(p.ValidationEnvironment)
		publicNetworkAccess = string(convert.ToValue(p.PublicNetworkAccess))
		ssoSecretType = string(convert.ToValue(p.SsoSecretType))
		privateEndpointConnectionCount = int64(len(p.PrivateEndpointConnections))
		if p.MaxSessionLimit != nil {
			v := int64(*p.MaxSessionLimit)
			maxSessionLimit = &v
		}
		if p.Ring != nil {
			v := int64(*p.Ring)
			ring = &v
		}
		description = p.Description
		friendlyName = p.FriendlyName
		vmTemplate = p.VMTemplate
		// The token value itself is deliberately not surfaced. What an audit
		// needs is whether one is outstanding and when it lapses.
		if ri := p.RegistrationInfo; ri != nil {
			registrationTokenExpirationTime = ri.ExpirationTime
			registrationTokenOperation = stringEnumPtr(ri.RegistrationTokenOperation)
			active := ri.Token != nil && *ri.Token != ""
			registrationTokenActive = &active
		}
		if au := p.AgentUpdate; au != nil {
			agentUpdateType = stringEnumPtr(au.Type)
			agentUpdateUseSessionHostLocalTime = au.UseSessionHostLocalTime
			agentUpdateMaintenanceWindowTimeZone = au.MaintenanceWindowTimeZone
			for _, w := range au.MaintenanceWindows {
				if w == nil {
					continue
				}
				d, err := convert.JsonToDict(w)
				if err != nil {
					return nil, err
				}
				agentUpdateMaintenanceWindows = append(agentUpdateMaintenanceWindows, d)
			}
		}
	}

	hpArgs := map[string]*llx.RawData{
		"id":                             llx.StringDataPtr(hp.ID),
		"name":                           llx.StringDataPtr(hp.Name),
		"location":                       llx.StringDataPtr(hp.Location),
		"tags":                           llx.MapData(convert.PtrMapStrToInterface(hp.Tags), types.String),
		"identity":                       llx.DictData(identity),
		"hostPoolType":                   llx.StringData(hostPoolType),
		"loadBalancerType":               llx.StringData(loadBalancerType),
		"preferredAppGroupType":          llx.StringData(preferredAppGroupType),
		"customRdpProperty":              llx.StringData(customRdpProperty),
		"maxSessionLimit":                llx.IntDataPtr(maxSessionLimit),
		"personalDesktopAssignmentType":  llx.StringData(personalDesktopAssignmentType),
		"startVMOnConnect":               llx.BoolData(startVMOnConnect),
		"validationEnvironment":          llx.BoolData(validationEnvironment),
		"ssoadfsAuthority":               llx.StringData(ssoadfsAuthority),
		"ring":                           llx.IntDataPtr(ring),
		"publicNetworkAccess":            llx.StringData(publicNetworkAccess),
		"ssoSecretType":                  llx.StringData(ssoSecretType),
		"privateEndpointConnectionCount": llx.IntData(privateEndpointConnectionCount),

		"registrationTokenActive":              llx.BoolDataPtr(registrationTokenActive),
		"registrationTokenExpirationTime":      llx.TimeDataPtr(registrationTokenExpirationTime),
		"registrationTokenOperation":           llx.StringDataPtr(registrationTokenOperation),
		"agentUpdateType":                      llx.StringDataPtr(agentUpdateType),
		"agentUpdateUseSessionHostLocalTime":   llx.BoolDataPtr(agentUpdateUseSessionHostLocalTime),
		"agentUpdateMaintenanceWindowTimeZone": llx.StringDataPtr(agentUpdateMaintenanceWindowTimeZone),
		"agentUpdateMaintenanceWindows":        llx.ArrayData(agentUpdateMaintenanceWindows, types.Dict),
		"description":                          llx.StringDataPtr(description),
		"friendlyName":                         llx.StringDataPtr(friendlyName),
		"vmTemplate":                           llx.StringDataPtr(vmTemplate),
	}
	// armdesktopvirtualization models a host pool identity without
	// UserAssignedIdentities, so the host pool publishes only the three
	// members the SDK reports.
	hpIdentity := orZero(hp.Identity)
	if err := setResourceIdentity(runtime, hpArgs, nil,
		identityType(hpIdentity.Type), identityPrincipalId(hpIdentity.PrincipalID), identityTenantId(hpIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.desktopVirtualizationService.hostPool", hpArgs)
	if err != nil {
		return nil, err
	}
	mqlHostPool := res.(*mqlAzureSubscriptionDesktopVirtualizationServiceHostPool)
	sysData, err := convert.JsonToDict(hp.SystemData)
	if err != nil {
		return nil, err
	}
	mqlHostPool.cacheSystemData = sysData
	return mqlHostPool, nil
}

type mqlAzureSubscriptionDesktopVirtualizationServiceHostPoolInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDesktopVirtualizationServiceHostPool) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
