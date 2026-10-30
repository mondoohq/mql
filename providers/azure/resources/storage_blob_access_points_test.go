// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func decodeBlobAccessPoint(t *testing.T, body string) map[string]*llx.RawData {
	t.Helper()
	var bap storage.BlobAccessPointConfiguration
	require.NoError(t, json.Unmarshal([]byte(body), &bap))
	return blobAccessPointArgs(&bap)
}

func TestBlobAccessPointArgsEndpointSource(t *testing.T) {
	args := decodeBlobAccessPoint(t, `{
		"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/blobAccessPointConfigurations/ontap",
		"name": "ontap",
		"type": "Microsoft.Storage/storageAccounts/blobAccessPointConfigurations",
		"location": "eastus",
		"tags": {"env": "prod"},
		"properties": {
			"uniqueId": "11111111-2222-3333-4444-555555555555",
			"state": "Inactive",
			"description": "ONTAP source",
			"provisioningState": "Succeeded",
			"lastConnectionTestStatus": "Failed",
			"lastConnectionTestTimestamp": "2026-10-01T12:30:00Z",
			"lastConnectionTestErrorMessage": "certificate signed by unknown authority",
			"source": {
				"sourceType": "NetAppOntap",
				"connection": {
					"connectionType": "Endpoint",
					"endpoint": "https://NetApp.Contoso.com:9000/bucket1",
					"tlsVerification": "Skip"
				},
				"auth": {
					"authType": "AccessKey",
					"accessKeyId": "AKIDEXAMPLE",
					"secretAccessKey": "must-never-surface",
					"signingRegion": "us-west-2",
					"hostOverride": "sign.contoso.com"
				}
			}
		}
	}`)

	assert.Equal(t, "ontap", args["name"].Value)
	assert.Equal(t, "eastus", args["location"].Value)
	assert.Equal(t, map[string]any{"env": "prod"}, args["tags"].Value)
	assert.Equal(t, "ONTAP source", args["description"].Value)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", args["uniqueId"].Value)
	assert.Equal(t, "Inactive", args["state"].Value)
	assert.Equal(t, "Succeeded", args["provisioningState"].Value)
	assert.Equal(t, "NetAppOntap", args["sourceType"].Value)
	assert.Equal(t, "Endpoint", args["connectionType"].Value)
	assert.Equal(t, "https://NetApp.Contoso.com:9000/bucket1", args["endpoint"].Value)
	assert.Equal(t, "netapp.contoso.com", args["endpointHost"].Value)
	assert.Equal(t, "Skip", args["tlsVerification"].Value)
	assert.Equal(t, "AccessKey", args["authType"].Value)
	assert.Equal(t, "AKIDEXAMPLE", args["accessKeyId"].Value)
	assert.Equal(t, "us-west-2", args["signingRegion"].Value)
	assert.Equal(t, "sign.contoso.com", args["signingHostOverride"].Value)
	assert.Equal(t, "Failed", args["lastConnectionTestStatus"].Value)
	assert.Equal(t, time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC), *args["lastConnectionTestTime"].Value.(*time.Time))
	assert.Equal(t, "certificate signed by unknown authority", args["lastConnectionTestErrorMessage"].Value)
	assert.Equal(t, "", args["privateLinkId"].Value)
	assert.Equal(t, "", args["privateEndpointName"].Value)

	// The API documents the secret key as write-only, but if a response ever
	// carried it, it must not reach any field.
	for k, v := range args {
		if str, ok := v.Value.(string); ok {
			assert.NotContains(t, str, "must-never-surface", k)
		}
	}
}

func TestBlobAccessPointArgsPrivateLinkSource(t *testing.T) {
	args := decodeBlobAccessPoint(t, `{
		"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/blobAccessPointConfigurations/anf",
		"name": "anf",
		"properties": {
			"source": {
				"sourceType": "AzureNetAppFiles",
				"connection": {
					"connectionType": "PrivateLink",
					"privateLinkIdType": "ResourceId",
					"privateLinkId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/privateLinkServices/anfpls",
					"privateLinkGroupId": "s3",
					"privateLinkLocation": "eastus",
					"requestMessage": "please approve",
					"privateEndpointName": "anf-pe",
					"endpoint": "https://anf.contoso.com/bucket1"
				},
				"auth": {"authType": "AccessKey", "accessKeyId": "AKID2"}
			}
		}
	}`)

	assert.Equal(t, "AzureNetAppFiles", args["sourceType"].Value)
	assert.Equal(t, "PrivateLink", args["connectionType"].Value)
	assert.Equal(t, "anf.contoso.com", args["endpointHost"].Value)
	assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/privateLinkServices/anfpls", args["privateLinkId"].Value)
	assert.Equal(t, "s3", args["privateLinkGroupId"].Value)
	assert.Equal(t, "eastus", args["privateLinkLocation"].Value)
	assert.Equal(t, "anf-pe", args["privateEndpointName"].Value)
	// Not reported by the service: stays empty rather than claiming the
	// documented "Perform" default.
	assert.Equal(t, "", args["tlsVerification"].Value)
	assert.Equal(t, "AKID2", args["accessKeyId"].Value)
	assert.Equal(t, "", args["signingRegion"].Value)
}

func TestBlobAccessPointArgsEverySourceVariantReachesConnection(t *testing.T) {
	for _, sourceType := range []string{"AzureNetAppFiles", "Commvault", "DellOneFs", "Nasuni", "NetAppOntap", "Qumulo", "S3Compatible"} {
		t.Run(sourceType, func(t *testing.T) {
			args := decodeBlobAccessPoint(t, `{"properties": {"source": {
				"sourceType": "`+sourceType+`",
				"connection": {"connectionType": "Endpoint", "endpoint": "https://src.example.com", "tlsVerification": "Perform"},
				"auth": {"authType": "AccessKey", "accessKeyId": "AKID"}
			}}}`)
			assert.Equal(t, sourceType, args["sourceType"].Value)
			assert.Equal(t, "src.example.com", args["endpointHost"].Value)
			assert.Equal(t, "Perform", args["tlsVerification"].Value)
			assert.Equal(t, "AKID", args["accessKeyId"].Value)
		})
	}
}

func TestBlobAccessPointArgsAbsentProperties(t *testing.T) {
	args := decodeBlobAccessPoint(t, `{"id": "x", "name": "bare"}`)
	assert.Equal(t, llx.NilData, args["lastConnectionTestTime"])
	assert.Equal(t, "", args["sourceType"].Value)
	assert.Equal(t, "", args["endpointHost"].Value)
	assert.Equal(t, "", args["state"].Value)
}

func TestEndpointHostname(t *testing.T) {
	cases := map[string]string{
		"https://s3.example.com/bucket":         "s3.example.com",
		"https://S3.Example.com:9000":           "s3.example.com",
		"http://user:pw@s3.example.com/b":       "s3.example.com",
		"s3.example.com/bucket":                 "s3.example.com",
		"https://[2001:db8::1]:443/bucket":      "2001:db8::1",
		"":                                      "",
		"   ":                                   "",
		"https://%zz":                           "",
		"https://10.0.0.5:9000/bucket?x=y#frag": "10.0.0.5",
	}
	for in, want := range cases {
		assert.Equal(t, want, endpointHostname(in), in)
	}
}

func TestIsBlobAccessPointUnavailable(t *testing.T) {
	assert.True(t, isBlobAccessPointUnavailable(armError(http.StatusBadRequest,
		`{"error":{"code":"FeatureNotSupportedForAccount","message":"Blob access points are not supported for the account."}}`)))
	assert.True(t, isBlobAccessPointUnavailable(armError(http.StatusBadRequest,
		`{"error":{"code":"InvalidResourceType","message":"The resource type could not be found in the namespace 'Microsoft.Storage' for api version '2026-09-01'."}}`)))
	assert.True(t, isBlobAccessPointUnavailable(armError(http.StatusNotFound,
		`{"error":{"code":"NoRegisteredProviderFound","message":"No registered resource provider found for location 'westus'."}}`)))

	// The account itself is missing: an error, not an absence of the feature.
	assert.False(t, isBlobAccessPointUnavailable(armError(http.StatusNotFound,
		`{"error":{"code":"ResourceNotFound","message":"The Resource 'Microsoft.Storage/storageAccounts/acct' was not found."}}`)))
	assert.False(t, isBlobAccessPointUnavailable(armError(http.StatusForbidden,
		`{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)))
	assert.False(t, isBlobAccessPointUnavailable(armError(http.StatusInternalServerError,
		`{"error":{"code":"InternalServerError","message":"boom"}}`)))
	assert.False(t, isBlobAccessPointUnavailable(errors.New("dial tcp: i/o timeout")))
}

func TestStorageAccountIDFromContainerID(t *testing.T) {
	got, err := storageAccountIDFromContainerID("/subscriptions/sub/resourceGroups/MyRG/providers/Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/c1")
	require.NoError(t, err)
	assert.Equal(t, "/subscriptions/sub/resourceGroups/MyRG/providers/Microsoft.Storage/storageAccounts/acct", got)

	_, err = storageAccountIDFromContainerID("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct")
	assert.Error(t, err)
	_, err = storageAccountIDFromContainerID("")
	assert.Error(t, err)
}

func TestFindBlobAccessPoint(t *testing.T) {
	ap := func(name, uniqueID string) *mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint {
		return &mqlAzureSubscriptionStorageServiceAccountBlobAccessPoint{
			Name:     plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
			UniqueId: plugin.TValue[string]{Data: uniqueID, State: plugin.StateIsSet},
		}
	}
	first := ap("ontap", "uid-1")
	second := ap("qumulo", "uid-2")
	aps := []any{first, second}

	assert.Same(t, second, findBlobAccessPoint(aps, "qumulo", "uid-2"))
	assert.Same(t, second, findBlobAccessPoint(aps, "", "UID-2"))
	assert.Same(t, first, findBlobAccessPoint(aps, "ontap", ""))
	// Recreated under the same name: the new configuration is not the one the
	// container was connected to.
	assert.Nil(t, findBlobAccessPoint(aps, "ontap", "uid-old"))
	assert.Nil(t, findBlobAccessPoint(aps, "missing", ""))
	assert.Nil(t, findBlobAccessPoint(nil, "ontap", "uid-1"))
}

func TestRedactEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://s3.example.com:9000/bucket1":                          "https://s3.example.com:9000/bucket1",
		"https://AKID:secret@s3.example.com/bucket1":                   "https://s3.example.com/bucket1",
		"https://s3.example.com/bucket1?X-Amz-Signature=abc&X-Amz-C=d": "https://s3.example.com/bucket1",
		"https://s3.example.com/bucket1#token=abc":                     "https://s3.example.com/bucket1",
		"AKID:secret@s3.example.com/bucket1?sig=abc":                   "s3.example.com/bucket1",
		"s3.example.com": "s3.example.com",
		"":               "",
	}
	for in, want := range cases {
		assert.Equal(t, want, redactEndpoint(in), in)
	}
}

func TestBlobAccessPointArgsRedactsEndpointCredentials(t *testing.T) {
	for _, connection := range []string{
		`{"connectionType": "Endpoint", "endpoint": "https://AKID:topsecret@s3.example.com/b?X-Amz-Signature=topsecret"}`,
		`{"connectionType": "PrivateLink", "privateLinkId": "/x", "endpoint": "https://AKID:topsecret@s3.example.com/b?X-Amz-Signature=topsecret"}`,
	} {
		args := decodeBlobAccessPoint(t, `{"properties": {
			"lastConnectionTestErrorMessage": "GET https://AKID:topsecret@s3.example.com/b?X-Amz-Signature=topsecret failed: 403",
			"source": {"sourceType": "S3Compatible", "connection": `+connection+`, "auth": {"authType": "AccessKey"}}
		}}`)
		assert.Equal(t, "https://s3.example.com/b", args["endpoint"].Value)
		assert.Equal(t, "s3.example.com", args["endpointHost"].Value)
		assert.Equal(t, "GET https://s3.example.com/b failed: 403", args["lastConnectionTestErrorMessage"].Value)
	}
}
