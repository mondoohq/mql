// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp/v11"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionNetAppServiceAccountInternal struct {
	cacheSystemData              any
	cacheEncryption              *armnetapp.AccountEncryption
	cacheActiveDirectories       []*armnetapp.ActiveDirectory
	cacheLdapConfiguration       *armnetapp.LdapConfiguration
	cacheUserAssignedIdentityIds []string
}

type mqlAzureSubscriptionNetAppServiceAccountCapacityPoolInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolumeInternal struct {
	cacheSystemData        any
	cacheSubnetId          *string
	cacheExportPolicyRules []*armnetapp.ExportPolicyRule
}

func (a *mqlAzureSubscriptionNetAppService) id() (string, error) {
	return "azure.subscription.netAppService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionNetAppService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionNetAppServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionNetAppServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionNetAppService,
		func(s *mqlAzureSubscriptionNetAppService) *plugin.TValue[[]any] { return s.GetAccounts() },
		ResourceAzureSubscriptionNetAppServiceAccount)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPool) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPool) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionNetAppService) accounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armnetapp.NewAccountsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
		for _, account := range page.Value {
			if account == nil {
				continue
			}
			mqlAccount, err := createNetAppAccountResource(a.MqlRuntime, account)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAccount)
		}
	}
	return res, nil
}

func createNetAppAccountResource(runtime *plugin.Runtime, account *armnetapp.Account) (*mqlAzureSubscriptionNetAppServiceAccount, error) {
	props := account.Properties
	if props == nil {
		props = &armnetapp.AccountProperties{}
	}

	identity, err := convert.JsonToDict(account.Identity)
	if err != nil {
		return nil, err
	}

	accountIdentity := orZero(account.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(accountIdentity.UserAssignedIdentities)

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(account.ID), userAssignedIdentityIds,
		identityType(accountIdentity.Type), identityPrincipalId(accountIdentity.PrincipalID), identityTenantId(accountIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionNetAppServiceAccount,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(account.ID),
			"name":              llx.StringDataPtr(account.Name),
			"location":          llx.StringDataPtr(account.Location),
			"type":              llx.StringDataPtr(account.Type),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(account.Tags), types.String),
			"provisioningState": llx.StringDataPtr(props.ProvisioningState),
			"identity":          llx.DictData(identity),
			"resourceIdentity":  resourceIdentity,
			"nfsV4IdDomain":     llx.StringDataPtr(props.NfsV4IDDomain),
			// The API documents null as false here, so the absence is not a
			// missing reading: showmount is on unless it was turned off.
			"disableShowmount": llx.BoolData(convert.ToValue(props.DisableShowmount)),
			"multiAdStatus":    llx.StringData(enumString(props.MultiAdStatus)),
		})
	if err != nil {
		return nil, err
	}

	mqlAccount := resource.(*mqlAzureSubscriptionNetAppServiceAccount)
	mqlAccount.cacheEncryption = props.Encryption
	mqlAccount.cacheActiveDirectories = props.ActiveDirectories
	mqlAccount.cacheLdapConfiguration = props.LdapConfiguration
	mqlAccount.cacheUserAssignedIdentityIds = userAssignedIdentityIds

	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount.cacheSystemData = sysData

	return mqlAccount, nil
}

// netAppKeyVaultKeyId builds the Key Vault key identifier from the vault URI
// and key name NetApp reports separately. The identifier is versionless, which
// resolves to the key's current version — the same version the account
// encrypts with, since NetApp follows the key rather than pinning a version.
func netAppKeyVaultKeyId(vaultURI, keyName *string) string {
	return netAppKeyVaultObjectId(vaultURI, "keys", keyName)
}

// netAppKeyVaultObjectId joins a vault URI, an object collection ("keys" or
// "secrets"), and an object name into a versionless Key Vault identifier.
// Empty when either half is missing.
func netAppKeyVaultObjectId(vaultURI *string, collection string, name *string) string {
	if vaultURI == nil || *vaultURI == "" || name == nil || *name == "" {
		return ""
	}
	return strings.TrimSuffix(*vaultURI, "/") + "/" + collection + "/" + *name
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) encryption() (*mqlAzureSubscriptionNetAppServiceAccountEncryption, error) {
	enc := a.cacheEncryption
	if enc == nil {
		a.Encryption.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var keyName, keyVaultUri, keyVaultResourceId, keyVaultStatus string
	if enc.KeyVaultProperties != nil {
		keyName = convert.ToValue(enc.KeyVaultProperties.KeyName)
		keyVaultUri = convert.ToValue(enc.KeyVaultProperties.KeyVaultURI)
		keyVaultResourceId = convert.ToValue(enc.KeyVaultProperties.KeyVaultResourceID)
		keyVaultStatus = enumString(enc.KeyVaultProperties.Status)
	}

	var identityPrincipalId, userAssignedIdentity, federatedClientId string
	if enc.Identity != nil {
		identityPrincipalId = convert.ToValue(enc.Identity.PrincipalID)
		userAssignedIdentity = convert.ToValue(enc.Identity.UserAssignedIdentity)
		federatedClientId = convert.ToValue(enc.Identity.FederatedClientID)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppServiceAccountEncryption,
		map[string]*llx.RawData{
			"__id":                llx.StringData(a.Id.Data + "/encryption"),
			"keySource":           llx.StringData(enumString(enc.KeySource)),
			"keyName":             llx.StringData(keyName),
			"keyVaultUri":         llx.StringData(keyVaultUri),
			"keyVaultStatus":      llx.StringData(keyVaultStatus),
			"identityPrincipalId": llx.StringData(identityPrincipalId),
			"federatedClientId":   llx.StringData(federatedClientId),
		})
	if err != nil {
		return nil, err
	}

	mqlEnc := res.(*mqlAzureSubscriptionNetAppServiceAccountEncryption)
	mqlEnc.cacheKeyVaultResourceId = keyVaultResourceId
	mqlEnc.cacheUserAssignedIdentity = userAssignedIdentity
	return mqlEnc, nil
}

type mqlAzureSubscriptionNetAppServiceAccountEncryptionInternal struct {
	cacheKeyVaultResourceId   string
	cacheUserAssignedIdentity string
}

func (a *mqlAzureSubscriptionNetAppServiceAccountEncryption) key() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	kid := netAppKeyVaultKeyId(&a.KeyVaultUri.Data, &a.KeyName.Data)
	if kid == "" {
		a.Key.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, kid)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountEncryption) vault() (*mqlAzureSubscriptionKeyVaultServiceVault, error) {
	if a.cacheKeyVaultResourceId == "" {
		a.Vault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultServiceVault,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheKeyVaultResourceId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceVault), nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccountEncryption) identity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheUserAssignedIdentity == "" {
		a.Identity.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheUserAssignedIdentity)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) activeDirectories() ([]any, error) {
	res := []any{}
	for _, ad := range a.cacheActiveDirectories {
		if ad == nil {
			continue
		}

		ldapSearchScope, err := convert.JsonToDict(ad.LdapSearchScope)
		if err != nil {
			return nil, err
		}

		// The connection id is what identifies one connection among an
		// account's several; without it the entries would collide in the
		// resource cache and every row would read as the first one.
		id := a.Id.Data + "/activeDirectories/" + convert.ToValue(ad.ActiveDirectoryID)

		mqlAd, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppServiceAccountActiveDirectory,
			map[string]*llx.RawData{
				"__id":                          llx.StringData(id),
				"activeDirectoryId":             llx.StringDataPtr(ad.ActiveDirectoryID),
				"domain":                        llx.StringDataPtr(ad.Domain),
				"dns":                           llx.StringDataPtr(ad.DNS),
				"smbServerName":                 llx.StringDataPtr(ad.SmbServerName),
				"organizationalUnit":            llx.StringDataPtr(ad.OrganizationalUnit),
				"site":                          llx.StringDataPtr(ad.Site),
				"adName":                        llx.StringDataPtr(ad.AdName),
				"kdcIp":                         llx.StringDataPtr(ad.KdcIP),
				"aesEncryption":                 llx.BoolDataPtr(ad.AesEncryption),
				"encryptDcConnections":          llx.BoolDataPtr(ad.EncryptDCConnections),
				"ldapOverTls":                   llx.BoolDataPtr(ad.LdapOverTLS),
				"ldapSigning":                   llx.BoolDataPtr(ad.LdapSigning),
				"allowLocalNfsUsersWithLdap":    llx.BoolDataPtr(ad.AllowLocalNfsUsersWithLdap),
				"ldapSearchScope":               llx.DictData(ldapSearchScope),
				"preferredServersForLdapClient": llx.StringDataPtr(ad.PreferredServersForLdapClient),
				"administrators":                llx.ArrayData(strPtrSliceToAny(ad.Administrators), types.String),
				"backupOperators":               llx.ArrayData(strPtrSliceToAny(ad.BackupOperators), types.String),
				"securityOperators":             llx.ArrayData(strPtrSliceToAny(ad.SecurityOperators), types.String),
				"status":                        llx.StringData(enumString(ad.Status)),
				"statusDetails":                 llx.StringDataPtr(ad.StatusDetails),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAd)
	}
	return res, nil
}

// netAppKeyVaultSecretId builds the versionless Key Vault secret identifier
// from the vault URI and secret name NetApp reports separately. Versionless
// resolves to the secret's current version, which is the one NetApp reads.
func netAppKeyVaultSecretId(vaultURI, secretName *string) string {
	return netAppKeyVaultObjectId(vaultURI, "secrets", secretName)
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) ldapConfiguration() (*mqlAzureSubscriptionNetAppServiceAccountLdapConfiguration, error) {
	ldap := a.cacheLdapConfiguration
	if ldap == nil {
		a.LdapConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var vaultUri, secretName, userAssignedIdentity *string
	if akv := ldap.BindPasswordAkvConfig; akv != nil {
		vaultUri = akv.AzureKeyVaultURI
		secretName = akv.SecretName
		userAssignedIdentity = akv.UserAssignedIdentity
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppServiceAccountLdapConfiguration,
		map[string]*llx.RawData{
			"__id":                    llx.StringData(a.Id.Data + "/ldapConfiguration"),
			"domain":                  llx.StringDataPtr(ldap.Domain),
			"ldapServers":             llx.ArrayData(strPtrSliceToAny(ldap.LdapServers), types.String),
			"ldapPort":                llx.IntDataPtr(ldap.LdapPort),
			"secureLdapType":          llx.StringDataPtr(enumStringPtr(ldap.SecureLdapType)),
			"bindAuthenticationLevel": llx.StringDataPtr(enumStringPtr(ldap.BindAuthenticationLevel)),
			"bindDn":                  llx.StringDataPtr(ldap.BindDN),
			"userDn":                  llx.StringDataPtr(ldap.UserDN),
			"groupDn":                 llx.StringDataPtr(ldap.GroupDN),
			"netGroupDn":              llx.StringDataPtr(ldap.NetGroupDN),
			"certificateCnHost":       llx.StringDataPtr(ldap.CertificateCNHost),
			"dnsServers":              llx.ArrayData(strPtrSliceToAny(ldap.DNSServers), types.String),
			"bindPasswordVaultUri":    llx.StringDataPtr(vaultUri),
			"bindPasswordSecretName":  llx.StringDataPtr(secretName),
		})
	if err != nil {
		return nil, err
	}

	mqlLdap := res.(*mqlAzureSubscriptionNetAppServiceAccountLdapConfiguration)
	mqlLdap.cacheBindPasswordSecretId = netAppKeyVaultSecretId(vaultUri, secretName)
	mqlLdap.cacheUserAssignedIdentity = convert.ToValue(userAssignedIdentity)
	return mqlLdap, nil
}

type mqlAzureSubscriptionNetAppServiceAccountLdapConfigurationInternal struct {
	cacheBindPasswordSecretId string
	cacheUserAssignedIdentity string
}

func (a *mqlAzureSubscriptionNetAppServiceAccountLdapConfiguration) bindPasswordSecret() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if a.cacheBindPasswordSecretId == "" {
		a.BindPasswordSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultSecretResource(a.MqlRuntime, a.cacheBindPasswordSecretId)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountLdapConfiguration) bindPasswordIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheUserAssignedIdentity == "" {
		a.BindPasswordIdentity.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheUserAssignedIdentity)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccount) capacityPools() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName, err := parsed.Component("netAppAccounts")
	if err != nil {
		return nil, err
	}

	client, err := armnetapp.NewPoolsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(parsed.ResourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pool := range page.Value {
			if pool == nil {
				continue
			}
			props := pool.Properties
			if props == nil {
				props = &armnetapp.PoolProperties{}
			}

			resource, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppServiceAccountCapacityPool,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(pool.ID),
					"name":              llx.StringDataPtr(pool.Name),
					"location":          llx.StringDataPtr(pool.Location),
					"type":              llx.StringDataPtr(pool.Type),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(pool.Tags), types.String),
					"poolId":            llx.StringDataPtr(props.PoolID),
					"provisioningState": llx.StringDataPtr(props.ProvisioningState),
					"serviceLevel":      llx.StringData(enumString(props.ServiceLevel)),
					"sizeBytes":         llx.IntDataPtr(props.Size),
					"qosType":           llx.StringData(enumString(props.QosType)),
					"coolAccess":        llx.BoolDataPtr(props.CoolAccess),
					"encryptionType":    llx.StringData(enumString(props.EncryptionType)),
					// Carried through as pointers: a pool the API reports no
					// throughput figures for is not a pool doing zero MiB/s.
					"totalThroughputMibps":    llx.FloatDataPtr(props.TotalThroughputMibps),
					"utilizedThroughputMibps": llx.FloatDataPtr(props.UtilizedThroughputMibps),
				})
			if err != nil {
				return nil, err
			}

			mqlPool := resource.(*mqlAzureSubscriptionNetAppServiceAccountCapacityPool)
			sysData, err := convert.JsonToDict(pool.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPool.cacheSystemData = sysData
			res = append(res, mqlPool)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPool) volumes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName, err := parsed.Component("netAppAccounts")
	if err != nil {
		return nil, err
	}
	poolName, err := parsed.Component("capacityPools")
	if err != nil {
		return nil, err
	}

	client, err := armnetapp.NewVolumesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(parsed.ResourceGroup, accountName, poolName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, volume := range page.Value {
			if volume == nil {
				continue
			}
			mqlVolume, err := createNetAppVolumeResource(a.MqlRuntime, volume)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVolume)
		}
	}
	return res, nil
}

func createNetAppVolumeResource(runtime *plugin.Runtime, volume *armnetapp.Volume) (*mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume, error) {
	props := volume.Properties
	if props == nil {
		props = &armnetapp.VolumeProperties{}
	}

	// Ransomware protection is reported only for volumes where the feature
	// applies. Nil stays nil so those volumes read null: a "Disabled" we
	// invented would claim protection was considered and turned off.
	var desiredRansomwareProtectionState, actualRansomwareProtectionState *string
	if props.DataProtection != nil && props.DataProtection.RansomwareProtection != nil {
		ransomware := props.DataProtection.RansomwareProtection
		desiredRansomwareProtectionState = enumStringPtr(ransomware.DesiredRansomwareProtectionState)
		actualRansomwareProtectionState = enumStringPtr(ransomware.ActualRansomwareProtectionState)
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionNetAppServiceAccountCapacityPoolVolume,
		map[string]*llx.RawData{
			"id":                               llx.StringDataPtr(volume.ID),
			"name":                             llx.StringDataPtr(volume.Name),
			"location":                         llx.StringDataPtr(volume.Location),
			"type":                             llx.StringDataPtr(volume.Type),
			"tags":                             llx.MapData(convert.PtrMapStrToInterface(volume.Tags), types.String),
			"provisioningState":                llx.StringDataPtr(props.ProvisioningState),
			"creationToken":                    llx.StringDataPtr(props.CreationToken),
			"fileSystemId":                     llx.StringDataPtr(props.FileSystemID),
			"serviceLevel":                     llx.StringData(enumString(props.ServiceLevel)),
			"usageThreshold":                   llx.IntDataPtr(props.UsageThreshold),
			"protocolTypes":                    llx.ArrayData(strPtrSliceToAny(props.ProtocolTypes), types.String),
			"securityStyle":                    llx.StringData(enumString(props.SecurityStyle)),
			"unixPermissions":                  llx.StringDataPtr(props.UnixPermissions),
			"encrypted":                        llx.BoolDataPtr(props.Encrypted),
			"encryptionKeySource":              llx.StringData(enumString(props.EncryptionKeySource)),
			"kerberosEnabled":                  llx.BoolDataPtr(props.KerberosEnabled),
			"ldapEnabled":                      llx.BoolDataPtr(props.LdapEnabled),
			"smbEncryption":                    llx.BoolDataPtr(props.SmbEncryption),
			"smbContinuouslyAvailable":         llx.BoolDataPtr(props.SmbContinuouslyAvailable),
			"smbAccessBasedEnumeration":        llx.StringData(enumString(props.SmbAccessBasedEnumeration)),
			"smbNonBrowsable":                  llx.StringData(enumString(props.SmbNonBrowsable)),
			"snapshotDirectoryVisible":         llx.BoolDataPtr(props.SnapshotDirectoryVisible),
			"coolAccess":                       llx.BoolDataPtr(props.CoolAccess),
			"isLargeVolume":                    llx.BoolDataPtr(props.IsLargeVolume),
			"networkFeatures":                  llx.StringData(enumString(props.NetworkFeatures)),
			"effectiveNetworkFeatures":         llx.StringData(enumString(props.EffectiveNetworkFeatures)),
			"mountTargetIpAddresses":           llx.ArrayData(netAppMountTargetIps(props.MountTargets), types.String),
			"desiredRansomwareProtectionState": llx.StringDataPtr(desiredRansomwareProtectionState),
			"actualRansomwareProtectionState":  llx.StringDataPtr(actualRansomwareProtectionState),
		})
	if err != nil {
		return nil, err
	}

	mqlVolume := resource.(*mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume)
	mqlVolume.cacheSubnetId = props.SubnetID
	if props.ExportPolicy != nil {
		mqlVolume.cacheExportPolicyRules = props.ExportPolicy.Rules
	}

	sysData, err := convert.JsonToDict(volume.SystemData)
	if err != nil {
		return nil, err
	}
	mqlVolume.cacheSystemData = sysData

	return mqlVolume, nil
}

// netAppMountTargetIps lists the addresses a volume answers on. Mount targets
// carry other fields, but the address is the one an exposure review reads, and
// a volume can have several.
func netAppMountTargetIps(targets []*armnetapp.MountTargetProperties) []any {
	res := []any{}
	for _, target := range targets {
		if target == nil || target.IPAddress == nil || *target.IPAddress == "" {
			continue
		}
		res = append(res, *target.IPAddress)
	}
	return res
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheSubnetId, &a.Subnet)
}

// netAppExportPolicyRuleKey returns the volume-local key of an export policy
// rule, used to build its cache id.
//
// The rule index is the natural key and is stable across reads. It is optional
// in the SDK, though, and two rules that both came back without one would share
// a cache entry -- every row would then read as the first one. A rule with no
// index falls back to its position in the list, which is less stable but keeps
// the rows distinct.
func netAppExportPolicyRuleKey(rule *armnetapp.ExportPolicyRule, position int) string {
	if rule != nil && rule.RuleIndex != nil {
		return strconv.FormatInt(int64(*rule.RuleIndex), 10)
	}
	return "position" + strconv.Itoa(position)
}

func (a *mqlAzureSubscriptionNetAppServiceAccountCapacityPoolVolume) exportPolicyRules() ([]any, error) {
	res := []any{}
	for i, rule := range a.cacheExportPolicyRules {
		if rule == nil {
			continue
		}

		id := a.Id.Data + "/exportPolicyRules/" + netAppExportPolicyRuleKey(rule, i)

		mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppServiceAccountCapacityPoolVolumeExportPolicyRule,
			map[string]*llx.RawData{
				"__id":                llx.StringData(id),
				"ruleIndex":           llx.IntDataPtr(rule.RuleIndex),
				"allowedClients":      llx.StringDataPtr(rule.AllowedClients),
				"cifs":                llx.BoolDataPtr(rule.Cifs),
				"nfsv3":               llx.BoolDataPtr(rule.Nfsv3),
				"nfsv41":              llx.BoolDataPtr(rule.Nfsv41),
				"unixReadOnly":        llx.BoolDataPtr(rule.UnixReadOnly),
				"unixReadWrite":       llx.BoolDataPtr(rule.UnixReadWrite),
				"hasRootAccess":       llx.BoolDataPtr(rule.HasRootAccess),
				"chownMode":           llx.StringData(enumString(rule.ChownMode)),
				"kerberos5ReadOnly":   llx.BoolDataPtr(rule.Kerberos5ReadOnly),
				"kerberos5ReadWrite":  llx.BoolDataPtr(rule.Kerberos5ReadWrite),
				"kerberos5iReadOnly":  llx.BoolDataPtr(rule.Kerberos5IReadOnly),
				"kerberos5iReadWrite": llx.BoolDataPtr(rule.Kerberos5IReadWrite),
				"kerberos5pReadOnly":  llx.BoolDataPtr(rule.Kerberos5PReadOnly),
				"kerberos5pReadWrite": llx.BoolDataPtr(rule.Kerberos5PReadWrite),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}
