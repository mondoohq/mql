// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	keyvault "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

var keyvaultidRegex = regexp.MustCompile(`^(https:\/\/([^\/]*)\.(?:vault|managedhsm)\.azure\.net)\/(certificates|secrets|keys)\/([^\/]*)(?:\/([^\/]*)){0,1}$`)

// isKeyRotateAction reports whether a key rotation policy lifetime action is a
// "Rotate" action. Both the action wrapper and its inner Type are nullable
// pointers, so both are guarded to avoid a nil dereference. Per the Key Vault
// SDK the action value is compared case-insensitively.
func isKeyRotateAction(action *azkeys.LifetimeActionType) bool {
	if action == nil || action.Type == nil {
		return false
	}
	return strings.EqualFold(string(*action.Type), string(azkeys.KeyRotationPolicyActionRotate))
}

type keyvaultid struct {
	BaseUrl string
	Vault   string
	Type    string
	Name    string
	Version string
}

func parseKeyVaultId(url string) (*keyvaultid, error) {
	m := keyvaultidRegex.FindStringSubmatch(url)

	if len(m) != 6 {
		return nil, fmt.Errorf("cannot parse azure keyvault id: %s", url)
	}

	return &keyvaultid{
		BaseUrl: m[1],
		Vault:   m[2],
		Type:    m[3],
		Name:    m[4],
		Version: m[5],
	}, nil
}

func (a *mqlAzureSubscriptionKeyVaultService) id() (string, error) {
	return "azure.subscription.keyVault/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionKeyVaultService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionKeyVaultServiceVault) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionKeyVaultServiceVaultInternal struct {
	fetchVaultOnce  sync.Once
	fetchVaultResp  *keyvault.VaultsClientGetResponse
	fetchVaultErr   error
	cacheSystemData any
}

// fetchVault retrieves the full vault from ARM. Cached with sync.Once so that
// properties, privateEndpointConnections, accessPolicies, and networkAcls
// share a single VaultsClient.Get per vault.
func (a *mqlAzureSubscriptionKeyVaultServiceVault) fetchVault() (*keyvault.VaultsClientGetResponse, error) {
	a.fetchVaultOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		resourceID, err := ParseResourceID(a.Id.Data)
		if err != nil {
			a.fetchVaultErr = err
			return
		}
		vaultName, err := resourceID.Component("vaults")
		if err != nil {
			a.fetchVaultErr = err
			return
		}
		client, err := keyvault.NewVaultsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.fetchVaultErr = err
			return
		}
		vault, err := client.Get(context.Background(), resourceID.ResourceGroup, vaultName, &keyvault.VaultsClientGetOptions{})
		if err != nil {
			a.fetchVaultErr = err
			return
		}
		a.fetchVaultResp = &vault
	})
	return a.fetchVaultResp, a.fetchVaultErr
}

// systemDataRaw returns the vault's systemData dict. The vaults() list pager
// does not return systemData on its entries, so when the cached value is empty
// fall back to the per-vault Get (shared via fetchVault), which does include it.
func (a *mqlAzureSubscriptionKeyVaultServiceVault) systemDataRaw() any {
	if m, ok := a.cacheSystemData.(map[string]any); ok && len(m) > 0 {
		return a.cacheSystemData
	}
	resp, err := a.fetchVault()
	if err != nil || resp == nil {
		return a.cacheSystemData
	}
	sysData, err := convert.JsonToDict(resp.SystemData)
	if err != nil {
		return a.cacheSystemData
	}
	a.cacheSystemData = sysData
	return sysData
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) id() (string, error) {
	return a.Kid.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceSecret) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificate) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultService) vaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := keyvault.NewVaultsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	// ListBySubscription rather than List: List goes through the generic ARM
	// resources endpoint and returns a TrackedResource, which carries no
	// Properties, so every vault then needed its own Get to answer properties,
	// networkAcls, accessPolicies or privateEndpointConnections.
	// ListBySubscription returns the full Vault, so one call answers all of
	// them for every vault in the subscription.
	pager := client.NewListBySubscriptionPager(&keyvault.VaultsClientListBySubscriptionOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlVault, err := vaultToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVault)
		}
	}
	return res, nil
}

// vaultToMql builds a vault resource from a full ARM Vault record and primes
// the per-vault fetch with it, so the accessors that would otherwise each pay a
// VaultsClient.Get read it straight from the listing.
func vaultToMql(runtime *plugin.Runtime, entry *keyvault.Vault) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "azure.subscription.keyVaultService.vault",
		map[string]*llx.RawData{
			"id":        llx.StringDataPtr(entry.ID),
			"vaultName": llx.StringDataPtr(entry.Name),
			"location":  llx.StringDataPtr(entry.Location),
			"type":      llx.StringDataPtr(entry.Type),
			"tags":      llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(entry.SystemData)
	if err != nil {
		return nil, err
	}
	mqlVault := res.(*mqlAzureSubscriptionKeyVaultServiceVault)
	mqlVault.cacheSystemData = sysData
	mqlVault.fetchVaultOnce.Do(func() {
		mqlVault.fetchVaultResp = &keyvault.VaultsClientGetResponse{Vault: *entry}
	})
	return mqlVault, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) vaultUri() (string, error) {
	name := a.VaultName.Data
	KVUri := "https://" + name + ".vault.azure.net"
	return KVUri, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) properties() (any, error) {
	vault, err := a.fetchVault()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(vault.Properties)
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) rbacAuthorizationEnabled() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	rbacProp := propsDict["enableRbacAuthorization"]
	if rbacProp == nil {
		return false, errors.New("key vault does not have enableRbacAuthorization property")
	}
	return rbacProp.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) enableSoftDelete() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["enableSoftDelete"]
	if val == nil {
		return true, nil
	}
	return val.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) enablePurgeProtection() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["enablePurgeProtection"]
	if val == nil {
		return false, nil
	}
	return val.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) softDeleteRetentionInDays() (int64, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return 0, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["softDeleteRetentionInDays"]
	if val == nil {
		return 90, nil
	}
	return int64(val.(float64)), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) skuName() (string, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return "", props.Error
	}
	propsDict := props.Data.(map[string]any)
	skuVal := propsDict["sku"]
	if skuVal == nil {
		return "", nil
	}
	skuDict, ok := skuVal.(map[string]any)
	if !ok {
		return "", nil
	}
	name := skuDict["name"]
	if name == nil {
		return "", nil
	}
	return fmt.Sprintf("%v", name), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) publicNetworkAccess() (string, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return "", props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["publicNetworkAccess"]
	if val == nil {
		return "", nil
	}
	return val.(string), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) enabledForDeployment() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["enabledForDeployment"]
	if val == nil {
		return false, nil
	}
	return val.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) enabledForDiskEncryption() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["enabledForDiskEncryption"]
	if val == nil {
		return false, nil
	}
	return val.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) enabledForTemplateDeployment() (bool, error) {
	props := a.GetProperties()
	if props.Error != nil {
		return false, props.Error
	}
	propsDict := props.Data.(map[string]any)
	val := propsDict["enabledForTemplateDeployment"]
	if val == nil {
		return false, nil
	}
	return val.(bool), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) keys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	vaultUri := a.GetVaultUri()
	client, err := azkeys.NewClient(vaultUri.Data, token, &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListKeyPropertiesPager(&azkeys.ListKeyPropertiesOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Keys, res, "azure key vault keys", err)
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azkeys.KeyAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.key",
				map[string]*llx.RawData{
					"kid":           llx.StringDataPtr((*string)(entry.KID)),
					"managed":       llx.BoolDataPtr(entry.Managed),
					"tags":          llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"enabled":       llx.BoolDataPtr(attrs.Enabled),
					"created":       llx.TimeDataPtr(attrs.Created),
					"updated":       llx.TimeDataPtr(attrs.Updated),
					"expires":       llx.TimeDataPtr(attrs.Expires),
					"notBefore":     llx.TimeDataPtr(attrs.NotBefore),
					"recoveryLevel": llx.StringDataPtr((*string)(attrs.RecoveryLevel)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

// id returns the full key identifier, which is the vault URI plus the key name
// and so already unique.
//
// It used to parse the identifier and return the bare key name. That is not a
// cache key: two vaults holding a key of the same name -- the same "cmk" in a
// production and a staging vault, say -- produced one key, and every rotation
// row after the first reported the first vault's answer. A vault with rotation
// switched off inherited "enabled: true" from a vault that had it on.
//
// Parsing also meant an identifier the regex did not recognize failed the whole
// resource rather than one field. Every other Key Vault resource returns its own
// identifier here; this one was the outlier.
func (a *mqlAzureSubscriptionKeyVaultServiceKeyAutorotation) id() (string, error) {
	return a.Kid.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) autorotation() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	vaultUri := a.GetVaultUri()
	client, err := azkeys.NewClient(vaultUri.Data, token, &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListKeyPropertiesPager(&azkeys.ListKeyPropertiesOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// The same data-plane listing keys() walks, so it degrades the
			// same way: a caller holding the vault's control-plane read but
			// not the keys data action gets 403 here, which reports null
			// rather than failing the whole vault list.
			return keyVaultPageFault(&a.Autorotation, res, "azure key vault key rotation policies", err)
		}

		// Resolve auto-rotation status concurrently. Azure Key Vault has no
		// batch endpoint for rotation policies, so we fan out per-key
		// GetKeyRotationPolicy calls within a bounded errgroup.
		enabledByKid := make(map[string]bool, len(page.Value))
		var mu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(10)
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			if entry.KID == nil {
				continue
			}
			kid := string(*entry.KID)
			kvid, err := parseKeyVaultId(kid)
			if err != nil || kvid.Type != "keys" {
				continue
			}
			keyName := kvid.Name
			g.Go(func() error {
				policyResp, err := client.GetKeyRotationPolicy(gctx, keyName, nil)
				if err != nil || policyResp.LifetimeActions == nil {
					return nil
				}
				for _, action := range policyResp.LifetimeActions {
					if isKeyRotateAction(action.Action) {
						mu.Lock()
						enabledByKid[kid] = true
						mu.Unlock()
						return nil
					}
				}
				return nil
			})
		}
		_ = g.Wait()

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			autoRotationEnabled := false
			if entry.KID != nil {
				autoRotationEnabled = enabledByKid[string(*entry.KID)]
			}

			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.key.autorotation",
				map[string]*llx.RawData{
					"kid":     llx.StringDataPtr((*string)(entry.KID)),
					"enabled": llx.BoolData(autoRotationEnabled),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) secrets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	vaultUri := a.GetVaultUri()
	client, err := azsecrets.NewClient(vaultUri.Data, token, &azsecrets.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListSecretPropertiesPager(&azsecrets.ListSecretPropertiesOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Secrets, res, "azure key vault secrets", err)
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azsecrets.SecretAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.secret",
				map[string]*llx.RawData{
					"id":          llx.StringDataPtr((*string)(entry.ID)),
					"tags":        llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"contentType": llx.StringDataPtr(entry.ContentType),
					"managed":     llx.BoolDataPtr(entry.Managed),
					"enabled":     llx.BoolDataPtr(attrs.Enabled),
					"created":     llx.TimeDataPtr(attrs.Created),
					"updated":     llx.TimeDataPtr(attrs.Updated),
					"expires":     llx.TimeDataPtr(attrs.Expires),
					"notBefore":   llx.TimeDataPtr(attrs.NotBefore),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) certificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	vaultUri := a.GetVaultUri()
	client, err := azcertificates.NewClient(vaultUri.Data, token, &azcertificates.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListCertificatePropertiesPager(&azcertificates.ListCertificatePropertiesOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Certificates, res, "azure key vault certificates", err)
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azcertificates.CertificateAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.certificate",
				map[string]*llx.RawData{
					"id":            llx.StringDataPtr((*string)(entry.ID)),
					"tags":          llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"enabled":       llx.BoolDataPtr(attrs.Enabled),
					"created":       llx.TimeDataPtr(attrs.Created),
					"updated":       llx.TimeDataPtr(attrs.Updated),
					"expires":       llx.TimeDataPtr(attrs.Expires),
					"notBefore":     llx.TimeDataPtr(attrs.NotBefore),
					"recoveryLevel": llx.StringDataPtr((*string)(attrs.RecoveryLevel)),
					"x5t":           llx.StringData(hex.EncodeToString(entry.X509Thumbprint)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

// initAzureSubscriptionKeyVaultServiceSecret is the secret counterpart of
// initAzureSubscriptionKeyVaultServiceKey: it resolves a secret known only by
// its URI so contentType, managed, tags and the attributes are real values
// rather than unset fields. See that function for the full reasoning.
func initAzureSubscriptionKeyVaultServiceSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw := args["id"]
	if idRaw == nil {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AzureConnection)
	client, err := azsecrets.NewClient(kvid.BaseUrl, conn.Token(), &azsecrets.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.GetSecret(context.Background(), kvid.Name, kvid.Version, nil)
	if err != nil {
		if isAzureNotConfigured(err) {
			log.Warn().Err(err).Str("id", id).Msg("could not read key vault secret, reporting its attributes as null")
			return keyVaultSecretArgs(id, nil), nil, nil
		}
		return nil, nil, err
	}
	return keyVaultSecretArgs(id, &resp.Secret), nil, nil
}

// keyVaultSecretArgs maps a secret onto the resource's fields. The secret's
// Value is deliberately never read: this resource reports metadata only.
func keyVaultSecretArgs(id string, secret *azsecrets.Secret) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":          llx.StringData(id),
		"tags":        llx.NilData,
		"contentType": llx.NilData,
		"managed":     llx.NilData,
		"enabled":     llx.NilData,
		"created":     llx.NilData,
		"updated":     llx.NilData,
		"expires":     llx.NilData,
		"notBefore":   llx.NilData,
	}
	if secret == nil {
		return args
	}
	args["tags"] = llx.MapData(convert.PtrMapStrToInterface(secret.Tags), types.String)
	args["contentType"] = llx.StringDataPtr(secret.ContentType)
	args["managed"] = llx.BoolDataPtr(secret.Managed)
	if attrs := secret.Attributes; attrs != nil {
		args["enabled"] = llx.BoolDataPtr(attrs.Enabled)
		args["created"] = llx.TimeDataPtr(attrs.Created)
		args["updated"] = llx.TimeDataPtr(attrs.Updated)
		args["expires"] = llx.TimeDataPtr(attrs.Expires)
		args["notBefore"] = llx.TimeDataPtr(attrs.NotBefore)
	}
	return args
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) privateEndpointConnections() ([]any, error) {
	vault, err := a.fetchVault()
	if err != nil {
		return nil, err
	}

	var res []any
	if vault.Properties == nil || vault.Properties.PrivateEndpointConnections == nil {
		return res, nil
	}

	for _, entry := range vault.Properties.PrivateEndpointConnections {
		if entry == nil {
			continue
		}

		// Extract name and type from ID
		var name, resType string
		if entry.ID != nil {
			connResourceID, err := ParseResourceID(*entry.ID)
			if err == nil {
				if nameComp, err := connResourceID.Component("privateEndpointConnections"); err == nil {
					name = nameComp
				}
				// Construct type from provider and path components
				if connResourceID.Provider != "" {
					resType = connResourceID.Provider + "/vaults/privateEndpointConnections"
				}
			}
			// Fallback: extract name from ID if Component fails
			if name == "" && entry.ID != nil {
				parts := strings.Split(*entry.ID, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
		}
		if resType == "" {
			resType = "Microsoft.KeyVault/vaults/privateEndpointConnections"
		}

		var pecPrivateEndpointID string
		privateEndpoint := map[string]*llx.RawData{
			"__id": llx.StringDataPtr(entry.ID),
			"id":   llx.StringDataPtr(entry.ID),
		}
		if name != "" {
			privateEndpoint["name"] = llx.StringData(name)
		}
		privateEndpoint["type"] = llx.StringData(resType)

		if entry.Properties != nil {
			props := entry.Properties
			propsMap, err := convert.JsonToDict(props)
			if err != nil {
				return nil, err
			}

			privateEndpoint["properties"] = llx.DictData(propsMap)

			if props.PrivateEndpoint != nil {
				pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
			}
			if props.PrivateLinkServiceConnectionState != nil {
				stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(entry.ID),
					stringEnumPtr(props.PrivateLinkServiceConnectionState.ActionsRequired),
					props.PrivateLinkServiceConnectionState.Description,
					stringEnumPtr(props.PrivateLinkServiceConnectionState.Status))
				if err != nil {
					return nil, err
				}
				privateEndpoint["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
			}
			if props.ProvisioningState != nil {
				privateEndpoint["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
			}
		}

		mqlRes, err := newAzurePrivateEndpointConnection(a.MqlRuntime, privateEndpoint, pecPrivateEndpointID)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlRes)
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) accessPolicies() ([]any, error) {
	vault, err := a.fetchVault()
	if err != nil {
		return nil, err
	}
	id := a.Id.Data

	var res []any
	if vault.Properties == nil || vault.Properties.AccessPolicies == nil {
		return res, nil
	}

	for _, entry := range vault.Properties.AccessPolicies {
		if entry == nil {
			continue
		}

		objectId := convert.ToValue(entry.ObjectID)
		tenantId := convert.ToValue(entry.TenantID)
		applicationId := convert.ToValue(entry.ApplicationID)

		var keyPerms, secretPerms, certPerms, storagePerms []any
		if entry.Permissions != nil {
			for _, p := range entry.Permissions.Keys {
				if p != nil {
					keyPerms = append(keyPerms, string(*p))
				}
			}
			for _, p := range entry.Permissions.Secrets {
				if p != nil {
					secretPerms = append(secretPerms, string(*p))
				}
			}
			for _, p := range entry.Permissions.Certificates {
				if p != nil {
					certPerms = append(certPerms, string(*p))
				}
			}
			for _, p := range entry.Permissions.Storage {
				if p != nil {
					storagePerms = append(storagePerms, string(*p))
				}
			}
		}

		// Azure keys an access policy on (tenantId, objectId, applicationId), so
		// the object id alone is not unique within a vault, let alone across
		// them. Without an explicit __id the resource has no cache key at all
		// and every policy in the scan aliases to the first one created.
		mqlRes, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.vault.accessPolicy",
			map[string]*llx.RawData{
				"__id":                   llx.StringData(id + "/accessPolicies/" + tenantId + "/" + objectId + "/" + applicationId),
				"id":                     llx.StringData(id + "/accessPolicies/" + objectId),
				"objectId":               llx.StringData(objectId),
				"tenantId":               llx.StringData(tenantId),
				"applicationId":          llx.StringData(applicationId),
				"keyPermissions":         llx.ArrayData(keyPerms, types.String),
				"secretPermissions":      llx.ArrayData(secretPerms, types.String),
				"certificatePermissions": llx.ArrayData(certPerms, types.String),
				"storagePermissions":     llx.ArrayData(storagePerms, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRes)
	}

	return res, nil
}

// roleAssignments returns the effective Microsoft Entra role assignments at the
// vault scope.
//
// This is the half of Key Vault authorization that accessPolicies cannot see. A
// vault with rbacAuthorizationEnabled set stores no access policies at all, so
// accessPolicies comes back empty on Microsoft's recommended access model and
// on its own reads as "no principal can reach the secrets". The grants are role
// assignments instead (Key Vault Secrets User, Key Vault Administrator, and the
// rest), and they are what this reports.
func (a *mqlAzureSubscriptionKeyVaultServiceVault) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "key vault")
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) networkAcls() (*mqlAzureSubscriptionKeyVaultServiceVaultNetworkAcls, error) {
	vault, err := a.fetchVault()
	if err != nil {
		return nil, err
	}
	id := a.Id.Data

	var bypass, defaultAction string
	var ipRules, vnetSubnetIds []any

	if vault.Properties != nil && vault.Properties.NetworkACLs != nil {
		acls := vault.Properties.NetworkACLs
		if acls.Bypass != nil {
			bypass = string(*acls.Bypass)
		}
		if acls.DefaultAction != nil {
			defaultAction = string(*acls.DefaultAction)
		}
		for _, rule := range acls.IPRules {
			if rule != nil && rule.Value != nil {
				ipRules = append(ipRules, *rule.Value)
			}
		}
		for _, rule := range acls.VirtualNetworkRules {
			if rule != nil && rule.ID != nil {
				vnetSubnetIds = append(vnetSubnetIds, *rule.ID)
			}
		}
	}

	res, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.vault.networkAcls",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(id + "/networkAcls"),
			"id":                      llx.StringData(id + "/networkAcls"),
			"bypass":                  llx.StringData(bypass),
			"defaultAction":           llx.StringData(defaultAction),
			"ipRules":                 llx.ArrayData(ipRules, types.String),
			"virtualNetworkSubnetIds": llx.ArrayData(vnetSubnetIds, types.String),
		})
	if err != nil {
		return nil, err
	}

	return res.(*mqlAzureSubscriptionKeyVaultServiceVaultNetworkAcls), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) keyName() (string, error) {
	id := a.Kid.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Name, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) version() (string, error) {
	id := a.Kid.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Version, nil
}

type mqlAzureSubscriptionKeyVaultServiceKeyInternal struct {
	fetchOnce sync.Once
	fetchResp *azkeys.GetKeyResponse
	fetchErr  error
}

// initAzureSubscriptionKeyVaultServiceKey resolves a key that is known only by
// its URI -- the shape every typed encryption-key accessor in this provider
// hands back -- into a key with its real attributes.
//
// Without an init, NewResource went straight to Create with whatever the caller
// passed, which was just the kid. enabled, expires, notBefore, created, updated
// and recoveryLevel were therefore left *unset* rather than null on ~20
// accessors: an unset field crosses the plugin boundary as an empty DataRes and
// surfaces client-side as "primitive with no type information", and under MQL's
// three-valued logic `{ enabled && expires > time.now }` then passes over a key
// that is disabled or already expired. managed and tags were worse -- they were
// passed as invented literals, so a certificate-backed key reported managed:
// false as fact.
func initAzureSubscriptionKeyVaultServiceKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// the collection path supplies every field already
	if len(args) > 1 {
		return args, nil, nil
	}
	kidRaw := args["kid"]
	if kidRaw == nil {
		return args, nil, nil
	}
	kid, ok := kidRaw.Value.(string)
	if !ok || kid == "" {
		return args, nil, nil
	}

	kvid, err := parseKeyVaultId(kid)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AzureConnection)
	client, err := azkeys.NewClient(kvid.BaseUrl, conn.Token(), &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.GetKey(context.Background(), kvid.Name, kvid.Version, nil)
	if err != nil {
		// Reading a vault's metadata and reading a key inside it are separate
		// permissions, so a caller can legitimately hold a reference it cannot
		// resolve. Report the attributes as null -- unknown -- rather than
		// failing the surrounding query or inventing values for them.
		if isAzureNotConfigured(err) {
			log.Warn().Err(err).Str("kid", kid).Msg("could not read key vault key, reporting its attributes as null")
			return keyVaultKeyArgs(kid, nil), nil, nil
		}
		return nil, nil, err
	}
	return keyVaultKeyArgs(kid, &resp.KeyBundle), nil, nil
}

// keyVaultKeyArgs maps a key bundle onto the resource's fields. A nil bundle
// sets every attribute to null, which is what the provider knows when the key
// could not be read -- as distinct from leaving the fields unset.
func keyVaultKeyArgs(kid string, bundle *azkeys.KeyBundle) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"kid":           llx.StringData(kid),
		"managed":       llx.NilData,
		"tags":          llx.NilData,
		"enabled":       llx.NilData,
		"created":       llx.NilData,
		"updated":       llx.NilData,
		"expires":       llx.NilData,
		"notBefore":     llx.NilData,
		"recoveryLevel": llx.NilData,
	}
	if bundle == nil {
		return args
	}
	args["managed"] = llx.BoolDataPtr(bundle.Managed)
	args["tags"] = llx.MapData(convert.PtrMapStrToInterface(bundle.Tags), types.String)
	if attrs := bundle.Attributes; attrs != nil {
		args["enabled"] = llx.BoolDataPtr(attrs.Enabled)
		args["created"] = llx.TimeDataPtr(attrs.Created)
		args["updated"] = llx.TimeDataPtr(attrs.Updated)
		args["expires"] = llx.TimeDataPtr(attrs.Expires)
		args["notBefore"] = llx.TimeDataPtr(attrs.NotBefore)
		args["recoveryLevel"] = llx.StringDataPtr((*string)(attrs.RecoveryLevel))
	}
	return args
}

// fetchKeyDetails fetches the full key from Azure Key Vault. The result is
// cached with sync.Once so that keyType, keySize, curveName, and keyOps can
// all share a single API call per key.
func (a *mqlAzureSubscriptionKeyVaultServiceKey) fetchKeyDetails() (*azkeys.GetKeyResponse, error) {
	a.fetchOnce.Do(func() {
		id := a.Kid.Data
		kvid, err := parseKeyVaultId(id)
		if err != nil {
			log.Warn().Err(err).Str("kid", id).Msg("failed to parse key vault key ID")
			a.fetchErr = err
			return
		}

		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		client, err := azkeys.NewClient(kvid.BaseUrl, conn.Token(), &azkeys.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.fetchErr = err
			return
		}

		ctx := context.Background()
		keyResp, err := client.GetKey(ctx, kvid.Name, kvid.Version, nil)
		if err != nil {
			log.Warn().Err(err).Str("kid", id).Msg("failed to fetch key vault key details")
			a.fetchErr = err
			return
		}

		a.fetchResp = &keyResp
	})
	return a.fetchResp, a.fetchErr
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) keyType() (string, error) {
	keyResp, err := a.fetchKeyDetails()
	if err != nil {
		return "", err
	}
	if keyResp.Key != nil && keyResp.Key.Kty != nil {
		return string(*keyResp.Key.Kty), nil
	}
	return "", nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) keySize() (int64, error) {
	keyResp, err := a.fetchKeyDetails()
	if err != nil {
		return 0, err
	}
	if keyResp.Key == nil {
		return 0, nil
	}

	// RSA keys: derive size from modulus
	if keyResp.Key.N != nil {
		n := new(big.Int).SetBytes(keyResp.Key.N)
		return int64(n.BitLen()), nil
	}

	// EC keys: derive size from curve name
	if keyResp.Key.Crv != nil {
		switch string(*keyResp.Key.Crv) {
		case "P-256":
			return 256, nil
		case "P-256K":
			return 256, nil
		case "P-384":
			return 384, nil
		case "P-521":
			return 521, nil
		}
	}

	return 0, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) curveName() (string, error) {
	keyResp, err := a.fetchKeyDetails()
	if err != nil {
		return "", err
	}
	if keyResp.Key != nil && keyResp.Key.Crv != nil {
		return string(*keyResp.Key.Crv), nil
	}
	return "", nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) keyOps() ([]any, error) {
	keyResp, err := a.fetchKeyDetails()
	if err != nil {
		return nil, err
	}
	ops := []any{}
	if keyResp.Key != nil {
		for _, op := range keyResp.Key.KeyOps {
			if op != nil {
				ops = append(ops, string(*op))
			}
		}
	}
	return ops, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Kid.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("cannot fetch versions for an already versioned azure key")
	}
	if kvid.Type != "keys" {
		return nil, errors.New("only key ids are supported")
	}

	client, err := azkeys.NewClient(kvid.BaseUrl, conn.Token(), &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListKeyPropertiesVersionsPager(kvid.Name, &azkeys.ListKeyPropertiesVersionsOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Versions, res, "azure key vault key versions", err)
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azkeys.KeyAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.key",
				map[string]*llx.RawData{
					"kid":           llx.StringDataPtr((*string)(entry.KID)),
					"managed":       llx.BoolDataPtr(entry.Managed),
					"tags":          llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"enabled":       llx.BoolDataPtr(attrs.Enabled),
					"created":       llx.TimeDataPtr(attrs.Created),
					"updated":       llx.TimeDataPtr(attrs.Updated),
					"expires":       llx.TimeDataPtr(attrs.Expires),
					"notBefore":     llx.TimeDataPtr(attrs.NotBefore),
					"recoveryLevel": llx.StringDataPtr((*string)(attrs.RecoveryLevel)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceKey) rotationPolicy() (*mqlAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Kid.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if kvid.Type != "keys" {
		return nil, errors.New("only key ids are supported")
	}

	client, err := azkeys.NewClient(kvid.BaseUrl, conn.Token(), &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policyResp, err := client.GetKeyRotationPolicy(ctx, kvid.Name, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			// Rotation policy doesn't exist, return a resource with enabled=false
			resource, err := CreateResource(a.MqlRuntime,
				ResourceAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject,
				map[string]*llx.RawData{
					"__id":             llx.StringData(id + "/rotationPolicy"),
					"lifetimeActions":  llx.ArrayData([]any{}, types.Dict),
					"actions":          llx.ArrayData([]any{}, types.Resource("azure.subscription.keyVaultService.key.rotationPolicyObject.action")),
					"attributes":       llx.DictData(map[string]any{}),
					"policyAttributes": llx.NilData,
					"enabled":          llx.BoolData(false),
				},
			)
			if err != nil {
				return nil, err
			}
			return resource.(*mqlAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject), nil
		}
		return nil, err
	}

	lifetimeActions := []any{}
	rotationActions := []any{}
	rotationEnabled := false
	if policyResp.LifetimeActions != nil {
		for _, action := range policyResp.LifetimeActions {
			actionDict, err := convert.JsonToDict(action)
			if err != nil {
				return nil, err
			}
			lifetimeActions = append(lifetimeActions, actionDict)

			if isKeyRotateAction(action.Action) {
				rotationEnabled = true
			}

			trigger := orZero(action.Trigger)
			actionType := orZero(action.Action).Type
			// A lifetime action carries no identifier; a policy holds at most
			// one action of each type, so the type keys it and the position
			// covers an action the service returned without one.
			key := string(convert.ToValue(actionType))
			if key == "" {
				key = strconv.Itoa(len(rotationActions))
			}
			mqlAction, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.key.rotationPolicyObject.action",
				map[string]*llx.RawData{
					"__id":             llx.StringData(subResourceCacheID(nil, id+"/rotationPolicy", "actions", key)),
					"actionType":       llx.StringDataPtr(stringEnumPtr(actionType)),
					"timeAfterCreate":  llx.StringDataPtr(trigger.TimeAfterCreate),
					"timeBeforeExpiry": llx.StringDataPtr(trigger.TimeBeforeExpiry),
				})
			if err != nil {
				return nil, err
			}
			rotationActions = append(rotationActions, mqlAction)
		}
	}

	attributes := map[string]any{}
	if policyResp.Attributes != nil {
		attributesDict, err := convert.JsonToDict(policyResp.Attributes)
		if err != nil {
			return nil, err
		}
		attributes = attributesDict
	}

	policyAttributes := llx.NilData
	if attrs := policyResp.Attributes; attrs != nil {
		const attributesResource = "azure.subscription.keyVaultService.key.rotationPolicyObject.policyAttributes"
		mqlAttrs, err := CreateResource(a.MqlRuntime, attributesResource, map[string]*llx.RawData{
			"__id":       llx.StringData(id + "/rotationPolicy/attributes"),
			"expiryTime": llx.StringDataPtr(attrs.ExpiryTime),
			"created":    llx.TimeDataPtr(attrs.Created),
			"updated":    llx.TimeDataPtr(attrs.Updated),
		})
		if err != nil {
			return nil, err
		}
		policyAttributes = llx.ResourceData(mqlAttrs, attributesResource)
	}

	resource, err := CreateResource(a.MqlRuntime,
		ResourceAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject,
		map[string]*llx.RawData{
			"__id":             llx.StringData(id + "/rotationPolicy"),
			"lifetimeActions":  llx.ArrayData(lifetimeActions, types.Dict),
			"actions":          llx.ArrayData(rotationActions, types.Resource("azure.subscription.keyVaultService.key.rotationPolicyObject.action")),
			"attributes":       llx.DictData(attributes),
			"policyAttributes": policyAttributes,
			"enabled":          llx.BoolData(rotationEnabled),
		},
	)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificate) certName() (string, error) {
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Name, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificate) version() (string, error) {
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Version, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificate) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("cannot fetch versions for an already versioned azure certificate")
	}
	if kvid.Type != "certificates" {
		return nil, errors.New("only certificate ids are supported")
	}

	vaultUrl := kvid.BaseUrl
	name := kvid.Name
	client, err := azcertificates.NewClient(vaultUrl, conn.Token(), &azcertificates.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListCertificatePropertiesVersionsPager(name, &azcertificates.ListCertificatePropertiesVersionsOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Versions, res, "azure key vault certificate versions", err)
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azcertificates.CertificateAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.certificate",
				map[string]*llx.RawData{
					"id":            llx.StringDataPtr((*string)(entry.ID)),
					"tags":          llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"enabled":       llx.BoolDataPtr(attrs.Enabled),
					"created":       llx.TimeDataPtr(attrs.Created),
					"updated":       llx.TimeDataPtr(attrs.Updated),
					"expires":       llx.TimeDataPtr(attrs.Expires),
					"notBefore":     llx.TimeDataPtr(attrs.NotBefore),
					"recoveryLevel": llx.StringDataPtr((*string)(attrs.RecoveryLevel)),
					"x5t":           llx.StringData(hex.EncodeToString(entry.X509Thumbprint)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificate) policy() (*mqlAzureSubscriptionKeyVaultServiceCertificatePolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if kvid.Type != "certificates" {
		return nil, errors.New("only certificate ids are supported")
	}

	client, err := azcertificates.NewClient(kvid.BaseUrl, conn.Token(), &azcertificates.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policyResp, err := client.GetCertificatePolicy(ctx, kvid.Name, nil)
	if err != nil {
		// Only treat 404 (not found) as "policy doesn't exist"
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			// Certificate policy doesn't exist, return empty resource
			x509Props, err := CreateResource(a.MqlRuntime,
				"azure.subscription.keyVaultService.certificate.policy.x509CertificateProperties",
				map[string]*llx.RawData{
					"__id":             llx.StringData(id + "/policy/x509CertificateProperties"),
					"subject":          llx.StringData(""),
					"validityInMonths": llx.IntData(0),
					"keyUsage":         llx.ArrayData([]any{}, types.String),
					"ekus":             llx.ArrayData([]any{}, types.String),
					"sanDnsNames":      llx.ArrayData([]any{}, types.String),
					"sanEmails":        llx.ArrayData([]any{}, types.String),
					"sanUpns":          llx.ArrayData([]any{}, types.String),
					"sanIpAddresses":   llx.ArrayData([]any{}, types.String),
					"sanUris":          llx.ArrayData([]any{}, types.String),
				},
			)
			if err != nil {
				return nil, err
			}

			// Create empty key properties resource
			keyProps, err := CreateResource(a.MqlRuntime,
				"azure.subscription.keyVaultService.certificate.policy.keyProperties",
				map[string]*llx.RawData{
					"__id":       llx.StringData(id + "/policy/keyProperties"),
					"curve":      llx.StringData(""),
					"exportable": llx.BoolData(false),
					"keySize":    llx.IntData(0),
					"keyType":    llx.StringData(""),
					"reuseKey":   llx.BoolData(false),
				},
			)
			if err != nil {
				return nil, err
			}

			// Create empty issuer parameters resource
			issuerParams, err := CreateResource(a.MqlRuntime,
				"azure.subscription.keyVaultService.certificate.policy.issuerParameters",
				map[string]*llx.RawData{
					"__id":                    llx.StringData(id + "/policy/issuerParameters"),
					"certificateTransparency": llx.BoolData(false),
					"certificateType":         llx.StringData(""),
					"name":                    llx.StringData(""),
				},
			)
			if err != nil {
				return nil, err
			}

			resource, err := CreateResource(a.MqlRuntime,
				"azure.subscription.keyVaultService.certificate.policy",
				map[string]*llx.RawData{
					"__id":                      llx.StringData(id + "/policy"),
					"x509CertificateProperties": llx.ResourceData(x509Props, "azure.subscription.keyVaultService.certificate.policy.x509CertificateProperties"),
					"keyProperties":             llx.ResourceData(keyProps, "azure.subscription.keyVaultService.certificate.policy.keyProperties"),
					"issuerParameters":          llx.ResourceData(issuerParams, "azure.subscription.keyVaultService.certificate.policy.issuerParameters"),
				},
			)
			if err != nil {
				return nil, err
			}
			return resource.(*mqlAzureSubscriptionKeyVaultServiceCertificatePolicy), nil
		}
		// Return the actual error for non-404 cases
		return nil, err
	}

	// Extract X.509 properties
	subject := ""
	validityInMonths := int64(0)
	keyUsage := []any{}
	ekus := []any{}
	sanDnsNames := []any{}
	sanEmails := []any{}
	sanUpns := []any{}
	sanIpAddresses := []any{}
	sanUris := []any{}

	if policyResp.X509CertificateProperties != nil {
		if policyResp.X509CertificateProperties.Subject != nil {
			subject = *policyResp.X509CertificateProperties.Subject
		}
		if policyResp.X509CertificateProperties.ValidityInMonths != nil {
			validityInMonths = int64(*policyResp.X509CertificateProperties.ValidityInMonths)
		}
		if policyResp.X509CertificateProperties.KeyUsage != nil {
			for _, ku := range policyResp.X509CertificateProperties.KeyUsage {
				if ku != nil {
					keyUsage = append(keyUsage, string(*ku))
				}
			}
		}
		if policyResp.X509CertificateProperties.EnhancedKeyUsage != nil {
			for _, eku := range policyResp.X509CertificateProperties.EnhancedKeyUsage {
				if eku != nil {
					ekus = append(ekus, *eku)
				}
			}
		}
		if san := policyResp.X509CertificateProperties.SubjectAlternativeNames; san != nil {
			sanDnsNames = strPtrsToAny(san.DNSNames)
			sanEmails = strPtrsToAny(san.Emails)
			sanUpns = strPtrsToAny(san.UserPrincipalNames)
			sanIpAddresses = strPtrsToAny(san.IPAddresses)
			sanUris = strPtrsToAny(san.URIs)
		}
	}

	// Create X.509 properties resource
	x509Props, err := CreateResource(a.MqlRuntime,
		"azure.subscription.keyVaultService.certificate.policy.x509CertificateProperties",
		map[string]*llx.RawData{
			"__id":             llx.StringData(id + "/policy/x509CertificateProperties"),
			"subject":          llx.StringData(subject),
			"validityInMonths": llx.IntData(validityInMonths),
			"keyUsage":         llx.ArrayData(keyUsage, types.String),
			"ekus":             llx.ArrayData(ekus, types.String),
			"sanDnsNames":      llx.ArrayData(sanDnsNames, types.String),
			"sanEmails":        llx.ArrayData(sanEmails, types.String),
			"sanUpns":          llx.ArrayData(sanUpns, types.String),
			"sanIpAddresses":   llx.ArrayData(sanIpAddresses, types.String),
			"sanUris":          llx.ArrayData(sanUris, types.String),
		},
	)
	if err != nil {
		return nil, err
	}

	// Extract key properties
	curve := ""
	exportable := false
	keySize := int64(0)
	keyType := ""
	reuseKey := false

	if policyResp.KeyProperties != nil {
		if policyResp.KeyProperties.Curve != nil {
			curve = string(*policyResp.KeyProperties.Curve)
		}
		if policyResp.KeyProperties.Exportable != nil {
			exportable = *policyResp.KeyProperties.Exportable
		}
		if policyResp.KeyProperties.KeySize != nil {
			keySize = int64(*policyResp.KeyProperties.KeySize)
		}
		if policyResp.KeyProperties.KeyType != nil {
			keyType = string(*policyResp.KeyProperties.KeyType)
		}
		if policyResp.KeyProperties.ReuseKey != nil {
			reuseKey = *policyResp.KeyProperties.ReuseKey
		}
	}

	// Create key properties resource
	keyProps, err := CreateResource(a.MqlRuntime,
		"azure.subscription.keyVaultService.certificate.policy.keyProperties",
		map[string]*llx.RawData{
			"__id":       llx.StringData(id + "/policy/keyProperties"),
			"curve":      llx.StringData(curve),
			"exportable": llx.BoolData(exportable),
			"keySize":    llx.IntData(keySize),
			"keyType":    llx.StringData(keyType),
			"reuseKey":   llx.BoolData(reuseKey),
		},
	)
	if err != nil {
		return nil, err
	}

	// Extract issuer parameters
	certificateTransparency := false
	certificateType := ""
	issuerName := ""

	if policyResp.IssuerParameters != nil {
		if policyResp.IssuerParameters.CertificateTransparency != nil {
			certificateTransparency = *policyResp.IssuerParameters.CertificateTransparency
		}
		if policyResp.IssuerParameters.CertificateType != nil {
			certificateType = *policyResp.IssuerParameters.CertificateType
		}
		if policyResp.IssuerParameters.Name != nil {
			issuerName = *policyResp.IssuerParameters.Name
		}
	}

	// Create issuer parameters resource
	issuerParams, err := CreateResource(a.MqlRuntime,
		"azure.subscription.keyVaultService.certificate.policy.issuerParameters",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(id + "/policy/issuerParameters"),
			"certificateTransparency": llx.BoolData(certificateTransparency),
			"certificateType":         llx.StringData(certificateType),
			"name":                    llx.StringData(issuerName),
		},
	)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(a.MqlRuntime,
		"azure.subscription.keyVaultService.certificate.policy",
		map[string]*llx.RawData{
			"__id":                      llx.StringData(id + "/policy"),
			"x509CertificateProperties": llx.ResourceData(x509Props, "azure.subscription.keyVaultService.certificate.policy.x509CertificateProperties"),
			"keyProperties":             llx.ResourceData(keyProps, "azure.subscription.keyVaultService.certificate.policy.keyProperties"),
			"issuerParameters":          llx.ResourceData(issuerParams, "azure.subscription.keyVaultService.certificate.policy.issuerParameters"),
		},
	)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAzureSubscriptionKeyVaultServiceCertificatePolicy), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicy) x509CertificateProperties() (*mqlAzureSubscriptionKeyVaultServiceCertificatePolicyX509CertificateProperties, error) {
	if !a.X509CertificateProperties.IsSet() {
		a.X509CertificateProperties.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.X509CertificateProperties.Error != nil {
		return nil, a.X509CertificateProperties.Error
	}
	return a.X509CertificateProperties.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicy) keyProperties() (*mqlAzureSubscriptionKeyVaultServiceCertificatePolicyKeyProperties, error) {
	if !a.KeyProperties.IsSet() {
		a.KeyProperties.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.KeyProperties.Error != nil {
		return nil, a.KeyProperties.Error
	}
	return a.KeyProperties.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicy) issuerParameters() (*mqlAzureSubscriptionKeyVaultServiceCertificatePolicyIssuerParameters, error) {
	if !a.IssuerParameters.IsSet() {
		a.IssuerParameters.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.IssuerParameters.Error != nil {
		return nil, a.IssuerParameters.Error
	}
	return a.IssuerParameters.Data, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicy) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicyX509CertificateProperties) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicyKeyProperties) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceCertificatePolicyIssuerParameters) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceSecret) secretName() (string, error) {
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Name, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceSecret) version() (string, error) {
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return "", err
	}

	return kvid.Version, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceSecret) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}

	if len(kvid.Version) > 0 {
		return nil, errors.New("cannot fetch versions for an already versioned azure secret")
	}
	if kvid.Type != "secrets" {
		return nil, errors.New("only certificate ids are supported")
	}

	vaultUrl := kvid.BaseUrl
	name := kvid.Name

	ctx := context.Background()
	client, err := azsecrets.NewClient(vaultUrl, conn.Token(), &azsecrets.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListSecretPropertiesVersionsPager(name, &azsecrets.ListSecretPropertiesVersionsOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Versions, res, "azure key vault secret versions", err)
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Attributes is optional on the data-plane list response. A bare
			// deref panics, and a provider panic is unrecoverable: it kills the
			// whole scan, not just this query.
			attrs := entry.Attributes
			if attrs == nil {
				attrs = &azsecrets.SecretAttributes{}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.secret",
				map[string]*llx.RawData{
					"id":          llx.StringDataPtr((*string)(entry.ID)),
					"tags":        llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"contentType": llx.StringDataPtr(entry.ContentType),
					"managed":     llx.BoolDataPtr(entry.Managed),
					"enabled":     llx.BoolDataPtr(attrs.Enabled),
					"created":     llx.TimeDataPtr(attrs.Created),
					"updated":     llx.TimeDataPtr(attrs.Updated),
					"expires":     llx.TimeDataPtr(attrs.Expires),
					"notBefore":   llx.TimeDataPtr(attrs.NotBefore),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceSecret) previousVersion() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	id := a.Id.Data
	kvid, err := parseKeyVaultId(id)
	if err != nil {
		return nil, err
	}
	if kvid.Type != "secrets" {
		return nil, errors.New("only secret ids are supported")
	}

	client, err := azsecrets.NewClient(kvid.BaseUrl, conn.Token(), &azsecrets.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := client.GetSecret(ctx, kvid.Name, kvid.Version, nil)
	if err != nil {
		return nil, err
	}
	if resp.PreviousVersion == nil || *resp.PreviousVersion == "" {
		a.PreviousVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	prev, err := client.GetSecret(ctx, kvid.Name, *resp.PreviousVersion, nil)
	if err != nil {
		return nil, err
	}

	var attrs azsecrets.SecretAttributes
	if prev.Attributes != nil {
		attrs = *prev.Attributes
	}
	mqlPrev, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.secret",
		map[string]*llx.RawData{
			"id":          llx.StringDataPtr((*string)(prev.ID)),
			"tags":        llx.MapData(convert.PtrMapStrToInterface(prev.Tags), types.String),
			"contentType": llx.StringDataPtr(prev.ContentType),
			"managed":     llx.BoolDataPtr(prev.Managed),
			"enabled":     llx.BoolDataPtr(attrs.Enabled),
			"created":     llx.TimeDataPtr(attrs.Created),
			"updated":     llx.TimeDataPtr(attrs.Updated),
			"expires":     llx.TimeDataPtr(attrs.Expires),
			"notBefore":   llx.TimeDataPtr(attrs.NotBefore),
		})
	if err != nil {
		return nil, err
	}
	return mqlPrev.(*mqlAzureSubscriptionKeyVaultServiceSecret), nil
}

func initAzureSubscriptionKeyVaultServiceVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionKeyVaultService,
		func(s *mqlAzureSubscriptionKeyVaultService) *plugin.TValue[[]any] { return s.GetVaults() },
		ResourceAzureSubscriptionKeyVaultServiceVault)
}

func (a *mqlAzureSubscriptionKeyVaultServiceKeyRotationPolicyObject) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) id() (string, error) {
	return a.Id.Data, nil
}

// initAzureSubscriptionKeyVaultServiceManagedHsm resolves a single managed HSM.
// When called without arguments it falls back to the discovered asset's
// platform id (see getAssetIdentifier), so an azure-keyvault-managedhsm asset
// resolves to its backing HSM instead of an empty husk.
func initAzureSubscriptionKeyVaultServiceManagedHsm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure managed hsm")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	res, err := NewResource(runtime, "azure.subscription.keyVaultService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	kvSvc := res.(*mqlAzureSubscriptionKeyVaultService)
	hsms := kvSvc.GetManagedHsms()
	if hsms.Error != nil {
		return nil, nil, hsms.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range hsms.Data {
		hsm := entry.(*mqlAzureSubscriptionKeyVaultServiceManagedHsm)
		if hsm.Id.Data == id {
			return args, hsm, nil
		}
	}

	return nil, nil, errors.New("azure managed hsm does not exist")
}

type mqlAzureSubscriptionKeyVaultServiceManagedHsmInternal struct {
	cachePrivateEndpointConnections []*keyvault.MHSMPrivateEndpointConnectionItem
	cacheSystemData                 any
	cacheNetworkRuleSet             *keyvault.MHSMNetworkRuleSet
}

// networkRuleSet reports the pool's inbound network rules, or null when the
// pool sets none. An absent rule set is not an empty one: with no rules the
// pool answers every caller its publicNetworkAccess admits, so reporting an
// empty rule list here would read as "locked down with nothing allowed".
func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) networkRuleSet() (*mqlAzureSubscriptionKeyVaultServiceManagedHsmNetworkRuleSet, error) {
	if a.cacheNetworkRuleSet == nil {
		a.NetworkRuleSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	acls := a.cacheNetworkRuleSet

	ipRules := []any{}
	for _, rule := range acls.IPRules {
		if rule != nil && rule.Value != nil {
			ipRules = append(ipRules, *rule.Value)
		}
	}
	vnetSubnetIds := []any{}
	for _, rule := range acls.VirtualNetworkRules {
		if rule != nil && rule.ID != nil {
			vnetSubnetIds = append(vnetSubnetIds, *rule.ID)
		}
	}
	serviceTags := []any{}
	for _, rule := range acls.ServiceTags {
		if rule != nil && rule.Tag != nil {
			serviceTags = append(serviceTags, *rule.Tag)
		}
	}

	res, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.managedHsm.networkRuleSet",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(a.Id.Data + "/networkRuleSet"),
			"bypass":                  llx.StringDataPtr(stringEnumPtr(acls.Bypass)),
			"defaultAction":           llx.StringDataPtr(stringEnumPtr(acls.DefaultAction)),
			"ipRules":                 llx.ArrayData(ipRules, types.String),
			"virtualNetworkSubnetIds": llx.ArrayData(vnetSubnetIds, types.String),
			"serviceTags":             llx.ArrayData(serviceTags, types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceManagedHsmNetworkRuleSet), nil
}

func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// keys enumerates the cryptographic keys held in the Managed HSM pool. Reading
// keys requires data-plane access to the HSM (a Managed HSM local RBAC role),
// which is distinct from the management-plane permission that lists the pool;
// when that access is missing the HSM returns 401/403 and this gracefully
// degrades to the keys resolved so far.
func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) keys() ([]any, error) {
	res := []any{}
	hsmUri := a.GetHsmUri()
	if hsmUri.Error != nil {
		return nil, hsmUri.Error
	}
	if hsmUri.Data == "" {
		return res, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	client, err := azkeys.NewClient(hsmUri.Data, token, &azkeys.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListKeyPropertiesPager(&azkeys.ListKeyPropertiesOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return keyVaultPageFault(&a.Keys, res, "managed HSM keys", err)
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			fields := map[string]*llx.RawData{
				"kid":           llx.StringDataPtr((*string)(entry.KID)),
				"managed":       llx.BoolDataPtr(entry.Managed),
				"tags":          llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
				"enabled":       llx.BoolDataPtr(nil),
				"created":       llx.TimeDataPtr(nil),
				"updated":       llx.TimeDataPtr(nil),
				"expires":       llx.TimeDataPtr(nil),
				"notBefore":     llx.TimeDataPtr(nil),
				"recoveryLevel": llx.StringDataPtr(nil),
			}
			// Attributes is optional on the list response; guard against a
			// nil pointer so a sparse key summary can't panic the scan.
			if attrs := entry.Attributes; attrs != nil {
				fields["enabled"] = llx.BoolDataPtr(attrs.Enabled)
				fields["created"] = llx.TimeDataPtr(attrs.Created)
				fields["updated"] = llx.TimeDataPtr(attrs.Updated)
				fields["expires"] = llx.TimeDataPtr(attrs.Expires)
				fields["notBefore"] = llx.TimeDataPtr(attrs.NotBefore)
				fields["recoveryLevel"] = llx.StringDataPtr((*string)(attrs.RecoveryLevel))
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.keyVaultService.key", fields)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionKeyVaultService) managedHsms() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := keyvault.NewManagedHsmsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list managed HSMs due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, hsm := range page.Value {
			if hsm == nil {
				continue
			}

			var skuName string
			if hsm.SKU != nil && hsm.SKU.Name != nil {
				skuName = string(*hsm.SKU.Name)
			}

			var hsmUri, provisioningState, tenantIdStr string
			var enableSoftDelete, enablePurgeProtection *bool
			var softDeleteRetentionInDays *int32
			var publicNetworkAccess string
			var initialAdminObjectIds []any
			var networkAcls map[string]any
			var privateEndpointConns []*keyvault.MHSMPrivateEndpointConnectionItem
			var scheduledPurgeDate *time.Time
			regions := []any{}

			if hsm.Properties != nil {
				props := hsm.Properties
				if props.HsmURI != nil {
					hsmUri = *props.HsmURI
				}
				if props.ProvisioningState != nil {
					provisioningState = string(*props.ProvisioningState)
				}
				enableSoftDelete = props.EnableSoftDelete
				enablePurgeProtection = props.EnablePurgeProtection
				softDeleteRetentionInDays = props.SoftDeleteRetentionInDays
				if props.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*props.PublicNetworkAccess)
				}
				if props.TenantID != nil {
					tenantIdStr = *props.TenantID
				}
				for _, adminId := range props.InitialAdminObjectIDs {
					if adminId != nil {
						initialAdminObjectIds = append(initialAdminObjectIds, *adminId)
					}
				}
				if props.NetworkACLs != nil {
					networkAcls, err = convert.JsonToDict(props.NetworkACLs)
					if err != nil {
						return nil, err
					}
				}
				privateEndpointConns = props.PrivateEndpointConnections
				scheduledPurgeDate = props.ScheduledPurgeDate
				for _, r := range props.Regions {
					if r == nil {
						continue
					}
					d, err := convert.JsonToDict(r)
					if err != nil {
						return nil, err
					}
					regions = append(regions, d)
				}
			}

			mqlHsm, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultServiceManagedHsm,
				map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(hsm.ID),
					"name":                      llx.StringDataPtr(hsm.Name),
					"location":                  llx.StringDataPtr(hsm.Location),
					"tags":                      llx.MapData(convert.PtrMapStrToInterface(hsm.Tags), types.String),
					"type":                      llx.StringDataPtr(hsm.Type),
					"skuName":                   llx.StringData(skuName),
					"hsmUri":                    llx.StringData(hsmUri),
					"tenantId":                  llx.StringData(tenantIdStr),
					"initialAdminObjectIds":     llx.ArrayData(initialAdminObjectIds, types.String),
					"enableSoftDelete":          llx.BoolDataPtr(enableSoftDelete),
					"enablePurgeProtection":     llx.BoolDataPtr(enablePurgeProtection),
					"softDeleteRetentionInDays": llx.IntDataPtr(softDeleteRetentionInDays),
					"publicNetworkAccess":       llx.StringData(publicNetworkAccess),
					"provisioningState":         llx.StringData(provisioningState),
					"networkAcls":               llx.DictData(networkAcls),
					"scheduledPurgeDate":        llx.TimeDataPtr(scheduledPurgeDate),
					"regions":                   llx.ArrayData(regions, types.Dict),
				})
			if err != nil {
				return nil, err
			}

			// Cache private endpoint connections for lazy loading
			mqlHsmTyped := mqlHsm.(*mqlAzureSubscriptionKeyVaultServiceManagedHsm)
			mqlHsmTyped.cachePrivateEndpointConnections = privateEndpointConns
			if hsm.Properties != nil {
				mqlHsmTyped.cacheNetworkRuleSet = hsm.Properties.NetworkACLs
			}

			sysData, err := convert.JsonToDict(hsm.SystemData)
			if err != nil {
				return nil, err
			}
			mqlHsmTyped.cacheSystemData = sysData

			res = append(res, mqlHsm)
		}
	}

	return res, nil
}

// roleAssignments returns the effective Microsoft Entra role assignments at the
// Managed HSM pool scope. These govern the management plane only. Data-plane
// key access runs on Managed HSM local RBAC, which lives inside the HSM rather
// than in Azure Resource Manager and is not listable here.
func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "managed hsm")
}

func (a *mqlAzureSubscriptionKeyVaultServiceManagedHsm) privateEndpointConnections() ([]any, error) {
	var res []any
	if a.cachePrivateEndpointConnections == nil {
		return res, nil
	}

	for _, entry := range a.cachePrivateEndpointConnections {
		if entry == nil {
			continue
		}

		// Extract name and type from ID
		var name, resType string
		if entry.ID != nil {
			connResourceID, err := ParseResourceID(*entry.ID)
			if err == nil {
				if nameComp, err := connResourceID.Component("privateEndpointConnections"); err == nil {
					name = nameComp
				}
				if connResourceID.Provider != "" {
					resType = connResourceID.Provider + "/managedHSMs/privateEndpointConnections"
				}
			}
			if name == "" {
				parts := strings.Split(*entry.ID, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
		}
		if resType == "" {
			resType = "Microsoft.KeyVault/managedHSMs/privateEndpointConnections"
		}

		var pecPrivateEndpointID string
		privateEndpoint := map[string]*llx.RawData{
			"__id": llx.StringDataPtr(entry.ID),
			"id":   llx.StringDataPtr(entry.ID),
		}
		if name != "" {
			privateEndpoint["name"] = llx.StringData(name)
		}
		privateEndpoint["type"] = llx.StringData(resType)

		if entry.Properties != nil {
			props := entry.Properties
			propsMap, err := convert.JsonToDict(props)
			if err != nil {
				return nil, err
			}

			privateEndpoint["properties"] = llx.DictData(propsMap)

			if props.PrivateEndpoint != nil {
				pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
			}
			if props.PrivateLinkServiceConnectionState != nil {
				stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(entry.ID),
					stringEnumPtr(props.PrivateLinkServiceConnectionState.ActionsRequired),
					props.PrivateLinkServiceConnectionState.Description,
					stringEnumPtr(props.PrivateLinkServiceConnectionState.Status))
				if err != nil {
					return nil, err
				}
				privateEndpoint["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
			}
			if props.ProvisioningState != nil {
				privateEndpoint["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
			}
		}

		mqlRes, err := newAzurePrivateEndpointConnection(a.MqlRuntime, privateEndpoint, pecPrivateEndpointID)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlRes)
	}

	return res, nil
}

// isKeyVaultReadRefused reports whether a Key Vault data-plane call was refused
// for this identity.
//
// Key Vault splits its permissions in two: the control plane lists the vaults,
// the data plane reads what is inside them, and they are granted separately. A
// Reader on the subscription therefore sees every vault and none of its
// contents, which is the most common credential shape there is. Key Vault
// answers 403 when the caller holds no data action for the contents, and 401
// when the token carries no data-plane access at all. Both mean the contents
// were not read.
func isKeyVaultReadRefused(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusUnauthorized || respErr.StatusCode == http.StatusForbidden
}

// keyVaultPageFault decides what a Key Vault data-plane page walk reports when
// a page fails, and is the only place that decision is made.
//
// A refused read reports null rather than an empty collection. The two are not
// the same answer and must not look alike: an empty list is a claim that the
// vault holds nothing, and a policy written as `keys.none(...)` or
// `secrets.all(...)` passes on it. Reported for contents nobody was allowed to
// look at, that is a silent pass on unexamined key material -- which is the
// most dangerous way for a secrets audit to fail, because it fails as success.
//
// A 404, or one of the not-applicable codes, is a real absence and keeps the
// empty list. Anything else -- a throttle, a 5xx, a transport failure -- proves
// nothing about the contents and stays an error.
//
// collected is what the walk had already read. Once any row has been read, a
// fault can only be reported as an error: returning the rows so far would
// present a truncated collection as a complete one, and nothing downstream can
// tell the difference. This mirrors listPaged, which makes the same call for
// the ARM pagers.
func keyVaultPageFault(field *plugin.TValue[[]any], collected []any, what string, err error) ([]any, error) {
	if len(collected) > 0 {
		return nil, errors.New("could not read all " + what + ": " + err.Error())
	}

	if isKeyVaultReadRefused(err) {
		log.Warn().Err(err).Str("collection", what).
			Msg("azure> not permitted to read, reporting null")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	if isAzureFeatureUnavailable(err) {
		log.Debug().Err(err).Str("collection", what).
			Msg("azure> not available, reporting an empty list")
		return []any{}, nil
	}

	return nil, err
}
