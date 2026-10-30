// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

const blobAccessPointReadPermission = "Microsoft.Storage/storageAccounts/blobAccessPointConfigurations/read"

func (a *mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionStorageServiceAccountBlobAccessPointInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint) privateLinkService() (*mqlAzureSubscriptionNetworkServicePrivateLinkService, error) {
	// A Private Link target can be a first-party resource rather than a
	// Private Link service; privateLinkId still names it in that case.
	if _, ok := parsePrivateLinkServiceID(a.PrivateLinkId.Data); !ok {
		a.PrivateLinkService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServicePrivateLinkService,
		map[string]*llx.RawData{"id": llx.StringData(a.PrivateLinkId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateLinkService), nil
}

// isBlobAccessPointUnavailable reports whether ARM answered that blob access
// point configurations cannot exist on this account: the account kind does not
// support them, or the resource type is not offered in the account's region or
// API version. An account that merely has none answers with an empty list.
func isBlobAccessPointUnavailable(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	// The switch covers the codes the shared allowlist does not: the
	// account-level refusal, and the unknown-resource-type answers ARM gives
	// with 404 as well as 400. azureFeatureNotApplicable only matches 400.
	switch strings.ToLower(azureErrorCode(respErr)) {
	case "featurenotsupportedforaccount":
		return true
	case "invalidresourcetype", "noregisteredproviderfound":
		return respErr.StatusCode == http.StatusBadRequest || respErr.StatusCode == http.StatusNotFound
	}
	return azureFeatureNotApplicable(respErr.StatusCode, azureErrorCode(respErr), azureErrorSubcode(respErr))
}

func (a *mqlAzureSubscriptionStorageServiceAccount) blobAccessPoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, accountName, err := storageAccountResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := storage.NewBlobAccessPointConfigurationsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListByStorageAccountPager(rg, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isBlobAccessPointUnavailable(err) {
				if !plugin.StructuredErrors() {
					a.BlobAccessPoints.State = plugin.StateIsSet | plugin.StateIsNull
					return nil, nil
				}
				return nil, llx.NotApplicable(err)
			}
			return nil, classifyAzureRefusal(err, blobAccessPointReadPermission)
		}
		for _, bap := range page.Value {
			if bap == nil {
				continue
			}
			mqlBap, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccountBlobAccessPoint, blobAccessPointArgs(bap))
			if err != nil {
				return nil, err
			}
			if bap.SystemData != nil {
				sysData, err := convert.JsonToDict(bap.SystemData)
				if err != nil {
					return nil, err
				}
				mqlBap.(*mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint).cacheSystemData = sysData
			}
			res = append(res, mqlBap)
		}
	}
	return res, nil
}

// blobAccessPointArgs flattens a blob access point configuration into the
// resource's fields. The source, its connection and its authentication are
// each polymorphic in the API; the parts every variant shares are read
// through a type switch so a check never has to know which variant it got.
func blobAccessPointArgs(bap *storage.BlobAccessPointConfiguration) map[string]*llx.RawData {
	var description, uniqueID, state, provisioningState string
	var lastTestStatus, lastTestError string
	var lastTestTime *llx.RawData = llx.NilData
	var parts blobAccessPointParts

	if props := bap.Properties; props != nil {
		description = convert.ToValue(props.Description)
		uniqueID = convert.ToValue(props.UniqueID)
		if props.State != nil {
			state = string(*props.State)
		}
		if props.ProvisioningState != nil {
			provisioningState = string(*props.ProvisioningState)
		}
		if props.LastConnectionTestStatus != nil {
			lastTestStatus = string(*props.LastConnectionTestStatus)
		}
		lastTestError = stripURLCredentialsInText(convert.ToValue(props.LastConnectionTestErrorMessage))
		if props.LastConnectionTestTimestamp != nil {
			lastTestTime = llx.TimeData(*props.LastConnectionTestTimestamp)
		}
		parts = blobAccessPointSourceParts(props.Source)
	}

	return map[string]*llx.RawData{
		"id":                             llx.StringDataPtr(bap.ID),
		"name":                           llx.StringDataPtr(bap.Name),
		"type":                           llx.StringDataPtr(bap.Type),
		"location":                       llx.StringDataPtr(bap.Location),
		"tags":                           llx.MapData(convert.PtrMapStrToInterface(bap.Tags), types.String),
		"description":                    llx.StringData(description),
		"uniqueId":                       llx.StringData(uniqueID),
		"state":                          llx.StringData(state),
		"provisioningState":              llx.StringData(provisioningState),
		"sourceType":                     llx.StringData(parts.sourceType),
		"connectionType":                 llx.StringData(parts.connectionType),
		"endpoint":                       llx.StringData(parts.endpoint),
		"endpointHost":                   llx.StringData(endpointHostname(parts.endpoint)),
		"tlsVerification":                llx.StringData(parts.tlsVerification),
		"privateLinkId":                  llx.StringData(parts.privateLinkID),
		"privateLinkGroupId":             llx.StringData(parts.privateLinkGroupID),
		"privateLinkLocation":            llx.StringData(parts.privateLinkLocation),
		"privateEndpointName":            llx.StringData(parts.privateEndpointName),
		"authType":                       llx.StringData(parts.authType),
		"accessKeyId":                    llx.StringData(parts.accessKeyID),
		"signingRegion":                  llx.StringData(parts.signingRegion),
		"signingHostOverride":            llx.StringData(parts.signingHostOverride),
		"lastConnectionTestStatus":       llx.StringData(lastTestStatus),
		"lastConnectionTestTime":         lastTestTime,
		"lastConnectionTestErrorMessage": llx.StringData(lastTestError),
	}
}

type blobAccessPointParts struct {
	sourceType          string
	connectionType      string
	endpoint            string
	tlsVerification     string
	privateLinkID       string
	privateLinkGroupID  string
	privateLinkLocation string
	privateEndpointName string
	authType            string
	accessKeyID         string
	signingRegion       string
	signingHostOverride string
}

func blobAccessPointSourceParts(src storage.BlobAccessPointSourcePropertiesClassification) blobAccessPointParts {
	var parts blobAccessPointParts
	if src == nil {
		return parts
	}
	if base := src.GetBlobAccessPointSourceProperties(); base != nil && base.SourceType != nil {
		parts.sourceType = string(*base.SourceType)
	}

	var conn storage.BlobAccessPointConnectionPropertiesClassification
	var auth storage.BlobAccessPointRemoteAuthPropertiesClassification
	switch s := src.(type) {
	case *storage.BlobAccessPointAzureNetAppFilesSourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointCommvaultSourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointDellOneFSSourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointGenericS3SourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointNasuniSourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointNetAppONTAPSourceProperties:
		conn, auth = s.Connection, s.Auth
	case *storage.BlobAccessPointQumuloSourceProperties:
		conn, auth = s.Connection, s.Auth
	}

	if conn != nil {
		if base := conn.GetBlobAccessPointConnectionProperties(); base != nil && base.ConnectionType != nil {
			parts.connectionType = string(*base.ConnectionType)
		}
		switch c := conn.(type) {
		case *storage.BlobAccessPointEndpointConnectionProperties:
			parts.endpoint = redactEndpoint(convert.ToValue(c.Endpoint))
			if c.TLSVerification != nil {
				parts.tlsVerification = string(*c.TLSVerification)
			}
		case *storage.BlobAccessPointPrivateLinkConnectionProperties:
			parts.endpoint = redactEndpoint(convert.ToValue(c.Endpoint))
			if c.TLSVerification != nil {
				parts.tlsVerification = string(*c.TLSVerification)
			}
			parts.privateLinkID = convert.ToValue(c.PrivateLinkID)
			parts.privateLinkGroupID = convert.ToValue(c.PrivateLinkGroupID)
			parts.privateLinkLocation = convert.ToValue(c.PrivateLinkLocation)
			parts.privateEndpointName = convert.ToValue(c.PrivateEndpointName)
		}
	}

	if auth != nil {
		if base := auth.GetBlobAccessPointRemoteAuthProperties(); base != nil && base.AuthType != nil {
			parts.authType = string(*base.AuthType)
		}
		// The secret access key is write-only in the API and is deliberately
		// never read here.
		if k, ok := auth.(*storage.BlobAccessPointAccessKeyAuthProperties); ok {
			parts.accessKeyID = convert.ToValue(k.AccessKeyID)
			parts.signingRegion = convert.ToValue(k.SigningRegion)
			parts.signingHostOverride = convert.ToValue(k.HostOverride)
		}
	}
	return parts
}

// redactEndpoint removes credentials a backing endpoint URL may carry: user
// information, and a query string or fragment where a signed request token
// would live. An endpoint written without a scheme is handled the same way.
func redactEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.Contains(endpoint, "://") {
		clean, _ := stripURLCredentials(endpoint)
		return clean
	}
	endpoint, _, _ = strings.Cut(endpoint, "?")
	endpoint, _, _ = strings.Cut(endpoint, "#")
	authority, path, hasPath := strings.Cut(endpoint, "/")
	if _, after, ok := strings.CutLast(authority, "@"); ok {
		authority = after
	}
	if hasPath {
		return authority + "/" + path
	}
	return authority
}

// endpointHostname returns the host of a backing endpoint URL, without scheme,
// port, path or credentials. An endpoint written without a scheme is read as
// a host, since the API accepts the protocol as optional in practice.
func endpointHostname(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// storageAccountIDFromContainerID returns the ARM id of the storage account a
// blob container belongs to, preserving the casing the container id carries so
// it matches the account id from the account listing.
func storageAccountIDFromContainerID(containerID string) (string, error) {
	idx := strings.Index(strings.ToLower(containerID), "/blobservices/")
	if idx <= 0 {
		return "", fmt.Errorf("%q is not a blob container id", containerID)
	}
	accountID := containerID[:idx]
	if _, _, err := storageAccountResourceGroup(accountID); err != nil {
		return "", err
	}
	return accountID, nil
}

// findBlobAccessPoint returns the configuration a container connection names.
// The unique id wins when the connection carries one: a configuration deleted
// and recreated under the same name gets a new unique id, and is not the one
// the container was connected to.
func findBlobAccessPoint(aps []any, name, uniqueID string) *mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint {
	for _, entry := range aps {
		ap, ok := entry.(*mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint)
		if !ok {
			continue
		}
		if uniqueID != "" {
			if strings.EqualFold(ap.UniqueId.Data, uniqueID) {
				return ap
			}
			continue
		}
		if name != "" && strings.EqualFold(ap.Name.Data, name) {
			return ap
		}
	}
	return nil
}

func (a *mqlAzureSubscriptionStorageServiceAccountContainer) blobAccessPoint() (*mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint, error) {
	if a.cacheBlobAccessPointName == "" && a.cacheBlobAccessPointUniqueID == "" {
		a.BlobAccessPoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	accountID, err := storageAccountIDFromContainerID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccount,
		map[string]*llx.RawData{"id": llx.StringData(accountID)})
	if err != nil {
		return nil, err
	}
	aps := res.(*mqlAzureSubscriptionStorageServiceAccount).GetBlobAccessPoints()
	if aps.Error != nil {
		return nil, aps.Error
	}
	if ap := findBlobAccessPoint(aps.Data, a.cacheBlobAccessPointName, a.cacheBlobAccessPointUniqueID); ap != nil {
		return ap, nil
	}
	a.BlobAccessPoint.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
