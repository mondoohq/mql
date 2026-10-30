// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// ExpressRoute link aggregation groups (LAGs)
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceExpressRouteLagInternal struct {
	cacheUserAssignedIdentityIds []string
	cacheCircuitIds              []string
	cacheLinks                   []*network.ExpressRouteLagLink
	// cacheAuthorizations holds the authorizations the list call returned
	// inline. nil means the list response carried no authorizations key at
	// all, so authorizations() asks the authorizations endpoint instead;
	// an empty non-nil slice means the LAG has none.
	cacheAuthorizations []*network.ExpressRouteLagAuthorization
}

func (a *mqlAzureSubscriptionNetworkService) expressRouteLags() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewExpressRouteLagsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.ExpressRouteLagsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lag := range page.Value {
			if lag == nil {
				continue
			}
			mqlLag, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExpressRouteLag, expressRouteLagArgs(lag))
			if err != nil {
				return nil, err
			}
			r := mqlLag.(*mqlAzureSubscriptionNetworkServiceExpressRouteLag)
			if lag.Identity != nil {
				r.cacheUserAssignedIdentityIds = sortedUserAssignedIdentityIDs(lag.Identity.UserAssignedIdentities)
			}
			if p := lag.Properties; p != nil {
				r.cacheCircuitIds = azureNetworkSubResourceIDs(p.Circuits)
				r.cacheLinks = p.Links
				r.cacheAuthorizations = p.Authorizations
			}
			res = append(res, r)
		}
	}
	return res, nil
}

// expressRouteLagArgs maps an ExpressRoute LAG onto its MQL fields. Values the
// API leaves out stay null rather than reading as zero.
func expressRouteLagArgs(lag *network.ExpressRouteLag) map[string]*llx.RawData {
	var provisioningState, encapsulation, billingType, lacpTimer *string
	var peeringLocation, mtu, etherType, resourceGuid, allocationDate *string
	var bandwidthInGbps, numberOfPorts, minimumActivePorts *int32
	var provisionedBandwidth *float64
	if p := lag.Properties; p != nil {
		provisioningState = (*string)(p.ProvisioningState)
		encapsulation = (*string)(p.Encapsulation)
		billingType = (*string)(p.BillingType)
		lacpTimer = (*string)(p.LacpTimer)
		peeringLocation = p.PeeringLocation
		mtu = p.Mtu
		etherType = p.EtherType
		resourceGuid = p.ResourceGUID
		allocationDate = p.AllocationDate
		bandwidthInGbps = p.BandwidthInGbps
		numberOfPorts = p.NumberOfPorts
		minimumActivePorts = p.MinimumActivePortsRequired
		provisionedBandwidth = p.ProvisionedBandwidthInGbps
	}
	var identityType, principalId *string
	if lag.Identity != nil {
		identityType = (*string)(lag.Identity.Type)
		principalId = lag.Identity.PrincipalID
	}
	return map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(lag.ID),
		"name":                       llx.StringDataPtr(lag.Name),
		"location":                   llx.StringDataPtr(lag.Location),
		"tags":                       llx.MapData(convert.PtrMapStrToInterface(lag.Tags), types.String),
		"type":                       llx.StringDataPtr(lag.Type),
		"etag":                       llx.StringDataPtr(lag.Etag),
		"provisioningState":          llx.StringDataPtr(provisioningState),
		"bandwidthInGbps":            llx.IntDataPtr(bandwidthInGbps),
		"provisionedBandwidthInGbps": llx.FloatDataPtr(provisionedBandwidth),
		"numberOfPorts":              llx.IntDataPtr(numberOfPorts),
		"minimumActivePortsRequired": llx.IntDataPtr(minimumActivePorts),
		"encapsulation":              llx.StringDataPtr(encapsulation),
		"billingType":                llx.StringDataPtr(billingType),
		"lacpTimer":                  llx.StringDataPtr(lacpTimer),
		"peeringLocation":            llx.StringDataPtr(peeringLocation),
		"mtu":                        llx.StringDataPtr(mtu),
		"etherType":                  llx.StringDataPtr(etherType),
		"resourceGuid":               llx.StringDataPtr(resourceGuid),
		"allocationDate":             llx.StringDataPtr(allocationDate),
		"identityType":               llx.StringDataPtr(identityType),
		"principalId":                llx.StringDataPtr(principalId),
	}
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) circuits() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExpressRouteCircuit, a.cacheCircuitIds)
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) links() ([]any, error) {
	res := []any{}
	for _, link := range a.cacheLinks {
		if link == nil {
			continue
		}
		args, cakId, cknId, err := expressRouteLagLinkArgs(link)
		if err != nil {
			return nil, err
		}
		mqlLink, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExpressRouteLagLink, args)
		if err != nil {
			return nil, err
		}
		l := mqlLink.(*mqlAzureSubscriptionNetworkServiceExpressRouteLagLink)
		l.cacheCakSecretId = cakId
		l.cacheCknSecretId = cknId
		res = append(res, l)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) authorizations() ([]any, error) {
	auths := a.cacheAuthorizations
	if auths == nil {
		fetched, err := a.fetchAuthorizations()
		if err != nil {
			return nil, err
		}
		auths = fetched
	}
	res := []any{}
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		args, circuitId := expressRouteLagAuthorizationArgs(auth)
		mqlAuth, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExpressRouteLagAuthorization, args)
		if err != nil {
			return nil, err
		}
		r := mqlAuth.(*mqlAzureSubscriptionNetworkServiceExpressRouteLagAuthorization)
		r.cacheCircuitId = circuitId
		res = append(res, r)
	}
	return res, nil
}

// fetchAuthorizations lists the LAG's authorizations from their own endpoint,
// for a list response that did not carry them inline.
func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLag) fetchAuthorizations() ([]*network.ExpressRouteLagAuthorization, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	lagName, err := azureId.Component("expressRouteLags")
	if err != nil {
		return nil, err
	}
	client, err := network.NewExpressRouteLagAuthorizationsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []*network.ExpressRouteLagAuthorization{}
	pager := client.NewListPager(azureId.ResourceGroup, lagName, nil)
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		res = append(res, page.Value...)
	}
	return res, nil
}

// -----------------------------------------------------------------------------
// ExpressRoute LAG links
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceExpressRouteLagLinkInternal struct {
	cacheCakSecretId string
	cacheCknSecretId string
}

// expressRouteLagLinkArgs maps a LAG link onto its MQL fields and returns the
// Key Vault secret identifiers of its MACsec CAK and CKN, empty when unset.
func expressRouteLagLinkArgs(link *network.ExpressRouteLagLink) (map[string]*llx.RawData, string, string, error) {
	var adminState, provisioningState, routerName, interfaceName *string
	var cipher, sciState *string
	var cakId, cknId string
	members := []any{}
	if p := link.Properties; p != nil {
		adminState = (*string)(p.AdminState)
		provisioningState = (*string)(p.ProvisioningState)
		routerName = p.RouterName
		interfaceName = p.InterfaceName
		if m := p.MacSecConfig; m != nil {
			cipher = (*string)(m.Cipher)
			sciState = (*string)(m.SciState)
			cakId = convert.ToValue(m.CakSecretIdentifier)
			cknId = convert.ToValue(m.CknSecretIdentifier)
		}
		if len(p.Members) > 0 {
			dicts, err := convert.JsonToDictSlice(p.Members)
			if err != nil {
				return nil, "", "", err
			}
			members = dicts
		}
	}
	return map[string]*llx.RawData{
		"id":                llx.StringDataPtr(link.ID),
		"name":              llx.StringDataPtr(link.Name),
		"type":              llx.StringDataPtr(link.Type),
		"etag":              llx.StringDataPtr(link.Etag),
		"adminState":        llx.StringDataPtr(adminState),
		"provisioningState": llx.StringDataPtr(provisioningState),
		"routerName":        llx.StringDataPtr(routerName),
		"interfaceName":     llx.StringDataPtr(interfaceName),
		"macSecCipher":      llx.StringDataPtr(cipher),
		"macSecSciState":    llx.StringDataPtr(sciState),
		"members":           llx.ArrayData(members, types.Dict),
	}, cakId, cknId, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLagLink) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLagLink) macSecCakSecret() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if a.cacheCakSecretId == "" {
		a.MacSecCakSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultSecretResource(a.MqlRuntime, a.cacheCakSecretId)
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLagLink) macSecCknSecret() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if a.cacheCknSecretId == "" {
		a.MacSecCknSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultSecretResource(a.MqlRuntime, a.cacheCknSecretId)
}

// -----------------------------------------------------------------------------
// ExpressRoute LAG authorizations
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceExpressRouteLagAuthorizationInternal struct {
	cacheCircuitId string
}

// expressRouteLagAuthorizationArgs maps a LAG authorization onto its MQL fields
// and returns the ARM ID of the circuit that redeemed it, empty when unused.
// The authorization key is never read.
func expressRouteLagAuthorizationArgs(auth *network.ExpressRouteLagAuthorization) (map[string]*llx.RawData, string) {
	var useStatus, provisioningState *string
	var circuitId string
	if p := auth.Properties; p != nil {
		useStatus = (*string)(p.AuthorizationUseStatus)
		provisioningState = (*string)(p.ProvisioningState)
		circuitId = convert.ToValue(p.CircuitResourceURI)
	}
	return map[string]*llx.RawData{
		"id":                     llx.StringDataPtr(auth.ID),
		"name":                   llx.StringDataPtr(auth.Name),
		"type":                   llx.StringDataPtr(auth.Type),
		"etag":                   llx.StringDataPtr(auth.Etag),
		"authorizationUseStatus": llx.StringDataPtr(useStatus),
		"provisioningState":      llx.StringDataPtr(provisioningState),
	}, circuitId
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLagAuthorization) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteLagAuthorization) circuit() (*mqlAzureSubscriptionNetworkServiceExpressRouteCircuit, error) {
	if a.cacheCircuitId == "" {
		a.Circuit.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceExpressRouteCircuit, map[string]*llx.RawData{
		"id": llx.StringData(a.cacheCircuitId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceExpressRouteCircuit), nil
}
