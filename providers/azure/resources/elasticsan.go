// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/elasticsan/armelasticsan"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionElasticSanServiceElasticSanInternal struct {
	cacheSystemData          any
	cachePrivateEndpointConn []*armelasticsan.PrivateEndpointConnection
}

type mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroupInternal struct {
	cacheSystemData              any
	cachePrivateEndpointConn     []*armelasticsan.PrivateEndpointConnection
	cacheVirtualNetworkRules     []*armelasticsan.VirtualNetworkRule
	cacheEncryptionIdentityId    string
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionElasticSanService) id() (string, error) {
	return "azure.subscription.elasticSanService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionElasticSanService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionElasticSanServiceElasticSan) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionElasticSanServiceElasticSan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionElasticSanService,
		func(s *mqlAzureSubscriptionElasticSanService) *plugin.TValue[[]any] { return s.GetElasticSans() },
		ResourceAzureSubscriptionElasticSanServiceElasticSan)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSan) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSan) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConn)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConn)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionElasticSanService) elasticSans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armelasticsan.NewElasticSansClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, san := range page.Value {
			if san == nil {
				continue
			}
			mqlSan, err := createElasticSanResource(a.MqlRuntime, san)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSan)
		}
	}
	return res, nil
}

func createElasticSanResource(runtime *plugin.Runtime, san *armelasticsan.ElasticSan) (*mqlAzureSubscriptionElasticSanServiceElasticSan, error) {
	props := san.Properties
	if props == nil {
		props = &armelasticsan.Properties{}
	}

	var skuName, skuTier string
	if props.SKU != nil {
		skuName = enumString(props.SKU.Name)
		skuTier = enumString(props.SKU.Tier)
	}

	// The SDK pointers are carried through rather than dereferenced: a SAN
	// with no auto-scale configured reports none of these, and 0 TiB is a
	// value a configured policy could legitimately hold. Passing nil through
	// llx.IntDataPtr reports them as null, which keeps "not configured"
	// distinct from "configured at zero".
	var scaleEnforcement string
	var scaleUpLimit, scaleIncreaseBy, scaleUnusedSize *int64
	if props.AutoScaleProperties != nil && props.AutoScaleProperties.ScaleUpProperties != nil {
		up := props.AutoScaleProperties.ScaleUpProperties
		scaleEnforcement = enumString(up.AutoScalePolicyEnforcement)
		scaleUpLimit = up.CapacityUnitScaleUpLimitTiB
		scaleIncreaseBy = up.IncreaseCapacityUnitByTiB
		scaleUnusedSize = up.UnusedSizeTiB
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionElasticSanServiceElasticSan,
		map[string]*llx.RawData{
			"id":                                   llx.StringDataPtr(san.ID),
			"name":                                 llx.StringDataPtr(san.Name),
			"location":                             llx.StringDataPtr(san.Location),
			"type":                                 llx.StringDataPtr(san.Type),
			"tags":                                 llx.MapData(convert.PtrMapStrToInterface(san.Tags), types.String),
			"provisioningState":                    llx.StringData(enumString(props.ProvisioningState)),
			"publicNetworkAccess":                  llx.StringData(enumString(props.PublicNetworkAccess)),
			"skuName":                              llx.StringData(skuName),
			"skuTier":                              llx.StringData(skuTier),
			"baseSizeTiB":                          llx.IntDataPtr(props.BaseSizeTiB),
			"extendedCapacitySizeTiB":              llx.IntDataPtr(props.ExtendedCapacitySizeTiB),
			"totalSizeTiB":                         llx.IntDataPtr(props.TotalSizeTiB),
			"totalVolumeSizeGiB":                   llx.IntDataPtr(props.TotalVolumeSizeGiB),
			"totalIops":                            llx.IntDataPtr(props.TotalIops),
			"totalMBps":                            llx.IntDataPtr(props.TotalMBps),
			"volumeGroupCount":                     llx.IntDataPtr(props.VolumeGroupCount),
			"availabilityZones":                    llx.ArrayData(strPtrSliceToAny(props.AvailabilityZones), types.String),
			"autoScalePolicyEnforcement":           llx.StringData(scaleEnforcement),
			"autoScaleCapacityUnitScaleUpLimitTiB": llx.IntDataPtr(scaleUpLimit),
			"autoScaleIncreaseCapacityUnitByTiB":   llx.IntDataPtr(scaleIncreaseBy),
			"autoScaleUnusedSizeTiB":               llx.IntDataPtr(scaleUnusedSize),
		})
	if err != nil {
		return nil, err
	}

	mqlSan := resource.(*mqlAzureSubscriptionElasticSanServiceElasticSan)
	mqlSan.cachePrivateEndpointConn = props.PrivateEndpointConnections

	sysData, err := convert.JsonToDict(san.SystemData)
	if err != nil {
		return nil, err
	}
	mqlSan.cacheSystemData = sysData

	return mqlSan, nil
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSan) volumeGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	sanName, err := parsed.Component("elasticSans")
	if err != nil {
		return nil, err
	}

	client, err := armelasticsan.NewVolumeGroupsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByElasticSanPager(parsed.ResourceGroup, sanName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, group := range page.Value {
			if group == nil {
				continue
			}
			mqlGroup, err := createElasticSanVolumeGroupResource(a.MqlRuntime, group)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func createElasticSanVolumeGroupResource(runtime *plugin.Runtime, group *armelasticsan.VolumeGroup) (*mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup, error) {
	props := group.Properties
	if props == nil {
		props = &armelasticsan.VolumeGroupProperties{}
	}

	identity, err := convert.JsonToDict(group.Identity)
	if err != nil {
		return nil, err
	}

	groupIdentity := orZero(group.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(groupIdentity.UserAssignedIdentities)

	var keyName, keyVaultUri, keyVersion, currentVersionedKeyIdentifier string
	var currentVersionedKeyExpiration, lastKeyRotation *time.Time
	var encryptionIdentityId string
	if props.EncryptionProperties != nil {
		if kv := props.EncryptionProperties.KeyVaultProperties; kv != nil {
			keyName = convert.ToValue(kv.KeyName)
			keyVaultUri = convert.ToValue(kv.KeyVaultURI)
			keyVersion = convert.ToValue(kv.KeyVersion)
			currentVersionedKeyIdentifier = convert.ToValue(kv.CurrentVersionedKeyIdentifier)
			currentVersionedKeyExpiration = kv.CurrentVersionedKeyExpirationTimestamp
			lastKeyRotation = kv.LastKeyRotationTimestamp
		}
		if id := props.EncryptionProperties.EncryptionIdentity; id != nil {
			encryptionIdentityId = convert.ToValue(id.EncryptionUserAssignedIdentity)
		}
	}

	var networkRules []*armelasticsan.VirtualNetworkRule
	if props.NetworkACLs != nil {
		networkRules = props.NetworkACLs.VirtualNetworkRules
	}

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(group.ID), userAssignedIdentityIds,
		identityType(groupIdentity.Type), identityPrincipalId(groupIdentity.PrincipalID), identityTenantId(groupIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionElasticSanServiceElasticSanVolumeGroup,
		map[string]*llx.RawData{
			"id":                                     llx.StringDataPtr(group.ID),
			"name":                                   llx.StringDataPtr(group.Name),
			"type":                                   llx.StringDataPtr(group.Type),
			"provisioningState":                      llx.StringData(enumString(props.ProvisioningState)),
			"encryption":                             llx.StringData(enumString(props.Encryption)),
			"protocolType":                           llx.StringData(enumString(props.ProtocolType)),
			"enforceDataIntegrityCheckForIscsi":      llx.BoolDataPtr(props.EnforceDataIntegrityCheckForIscsi),
			"identity":                               llx.DictData(identity),
			"resourceIdentity":                       resourceIdentity,
			"keyName":                                llx.StringData(keyName),
			"keyVaultUri":                            llx.StringData(keyVaultUri),
			"keyVersion":                             llx.StringData(keyVersion),
			"currentVersionedKeyIdentifier":          llx.StringData(currentVersionedKeyIdentifier),
			"currentVersionedKeyExpirationTimestamp": llx.TimeDataPtr(currentVersionedKeyExpiration),
			"lastKeyRotationTimestamp":               llx.TimeDataPtr(lastKeyRotation),
		})
	if err != nil {
		return nil, err
	}

	mqlGroup := resource.(*mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup)
	mqlGroup.cachePrivateEndpointConn = props.PrivateEndpointConnections
	mqlGroup.cacheVirtualNetworkRules = networkRules
	mqlGroup.cacheEncryptionIdentityId = encryptionIdentityId
	mqlGroup.cacheUserAssignedIdentityIds = userAssignedIdentityIds

	sysData, err := convert.JsonToDict(group.SystemData)
	if err != nil {
		return nil, err
	}
	mqlGroup.cacheSystemData = sysData

	return mqlGroup, nil
}

// elasticSanKeyVaultKeyId builds the Key Vault key identifier from the vault
// URI, key name and key version a volume group reports separately. The version
// is optional: a group that pins one encrypts with that version, and a group
// that does not follows the key, which a versionless identifier resolves to.
func elasticSanKeyVaultKeyId(vaultURI, keyName, keyVersion string) string {
	if vaultURI == "" || keyName == "" {
		return ""
	}
	kid := strings.TrimSuffix(vaultURI, "/") + "/keys/" + keyName
	if keyVersion != "" {
		kid += "/" + keyVersion
	}
	return kid
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) key() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	kid := elasticSanKeyVaultKeyId(a.KeyVaultUri.Data, a.KeyName.Data, a.KeyVersion.Data)
	if kid == "" {
		a.Key.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, kid)
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) encryptionIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheEncryptionIdentityId == "" {
		a.EncryptionIdentity.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheEncryptionIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroup) virtualNetworkRules() ([]any, error) {
	res := []any{}
	for i, rule := range a.cacheVirtualNetworkRules {
		if rule == nil {
			continue
		}

		// The subnet the rule names is what distinguishes it, but a rule set
		// can in principle repeat one, so the position is folded in too --
		// otherwise two entries would share a cache key and the second would
		// read as the first.
		id := a.Id.Data + "/virtualNetworkRules/" + strconv.Itoa(i) + "/" + convert.ToValue(rule.VirtualNetworkResourceID)

		mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionElasticSanServiceElasticSanVolumeGroupVirtualNetworkRule,
			map[string]*llx.RawData{
				"__id":   llx.StringData(id),
				"action": llx.StringData(enumString(rule.Action)),
			})
		if err != nil {
			return nil, err
		}
		mqlRule.(*mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroupVirtualNetworkRule).cacheSubnetId = rule.VirtualNetworkResourceID
		res = append(res, mqlRule)
	}
	return res, nil
}

type mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroupVirtualNetworkRuleInternal struct {
	cacheSubnetId *string
}

// subnet resolves the rule's target. Azure names the field
// virtualNetworkResourceId, but the value is a subnet's resource ID, not a
// virtual network's -- an Elastic SAN rule admits one subnet at a time.
func (a *mqlAzureSubscriptionElasticSanServiceElasticSanVolumeGroupVirtualNetworkRule) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheSubnetId, &a.Subnet)
}
