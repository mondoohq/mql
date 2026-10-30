// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The payload below is the properties block of a real Service Fabric cluster
// as Azure Resource Manager returned it (api-version 2021-06-01), with
// identifiers replaced. It is kept verbatim in shape because several of the
// assertions here exist to pin how the SDK decodes it, and a hand-tidied
// fixture would stop reproducing the API.
const serviceFabricLiveProperties = `{
  "addOnFeatures": null,
  "azureActiveDirectory": null,
  "certificate": {
    "thumbprint": "7EF41DE666CD2F29B4E499B27101823E998C66DA",
    "thumbprintSecondary": null,
    "x509StoreName": "My"
  },
  "certificateCommonNames": null,
  "clientCertificateCommonNames": [],
  "clientCertificateThumbprints": [],
  "clusterCodeVersion": "11.7.157.1",
  "clusterId": "b9e5b7e9-22c7-4d1a-b993-cf438b34bbd2",
  "clusterState": "Deploying",
  "diagnosticsStorageAccountConfig": {
    "blobEndpoint": "https://sflogsexample.blob.core.windows.net/",
    "primaryAccessKey": "",
    "protectedAccountKeyName": "StorageAccountKey1",
    "protectedAccountKeyName2": "",
    "queueEndpoint": "https://sflogsexample.queue.core.windows.net/",
    "secondaryAccessKey": "",
    "storageAccountName": "sflogsexample",
    "tableEndpoint": "https://sflogsexample.table.core.windows.net/"
  },
  "eventStoreServiceEnabled": null,
  "fabricSettings": [
    {
      "name": "Security",
      "parameters": [
        { "name": "ClusterProtectionLevel", "value": "EncryptAndSign" }
      ]
    }
  ],
  "managementEndpoint": "https://mqlsfverify.westus2.cloudapp.azure.com:19080",
  "nodeTypes": [
    {
      "applicationPorts": { "endPort": 30000, "startPort": 20000 },
      "clientConnectionEndpointPort": 19000,
      "durabilityLevel": "Bronze",
      "ephemeralPorts": { "endPort": 65534, "startPort": 49152 },
      "httpGatewayEndpointPort": 19080,
      "isPrimary": true,
      "isStateless": false,
      "name": "nt1vm",
      "vmInstanceCount": 3
    }
  ],
  "provisioningState": "Succeeded",
  "reliabilityLevel": "Bronze",
  "reverseProxyCertificate": null,
  "upgradeMode": "Automatic",
  "upgradePauseEndTimestampUtc": null,
  "upgradePauseStartTimestampUtc": null,
  "upgradeWave": "Wave0",
  "vmImage": "Windows",
  "waveUpgradePaused": null
}`

func decodeLiveProperties(t *testing.T) *armservicefabric.ClusterProperties {
	t.Helper()
	var props armservicefabric.ClusterProperties
	require.NoError(t, json.Unmarshal([]byte(serviceFabricLiveProperties), &props))
	return &props
}

// TestServiceFabricPropertiesDecode pins the SDK field mapping for the settings
// an audit reads. A wrong or missing tag on any of these decodes to a zero
// value, which would report a secured cluster as unsecured (or the reverse)
// without ever erroring.
func TestServiceFabricPropertiesDecode(t *testing.T) {
	props := decodeLiveProperties(t)

	require.NotNil(t, props.ManagementEndpoint)
	assert.Equal(t, "https://mqlsfverify.westus2.cloudapp.azure.com:19080", *props.ManagementEndpoint)

	require.NotNil(t, props.ClusterCodeVersion)
	assert.Equal(t, "11.7.157.1", *props.ClusterCodeVersion)

	require.NotNil(t, props.ClusterID)
	assert.Equal(t, "b9e5b7e9-22c7-4d1a-b993-cf438b34bbd2", *props.ClusterID)

	require.NotNil(t, props.UpgradeMode)
	assert.Equal(t, armservicefabric.UpgradeModeAutomatic, *props.UpgradeMode)

	require.NotNil(t, props.UpgradeWave)
	assert.Equal(t, armservicefabric.ClusterUpgradeCadenceWave0, *props.UpgradeWave)

	require.NotNil(t, props.ReliabilityLevel)
	assert.Equal(t, armservicefabric.ReliabilityLevelBronze, *props.ReliabilityLevel)

	require.NotNil(t, props.ClusterState)
	assert.Equal(t, armservicefabric.ClusterStateDeploying, *props.ClusterState)

	require.NotNil(t, props.VMImage)
	assert.Equal(t, "Windows", *props.VMImage)

	// The cluster certificate is pinned by thumbprint and read from the "My"
	// store; the secondary slot is empty during normal operation.
	require.NotNil(t, props.Certificate)
	require.NotNil(t, props.Certificate.Thumbprint)
	assert.Equal(t, "7EF41DE666CD2F29B4E499B27101823E998C66DA", *props.Certificate.Thumbprint)
	assert.Nil(t, props.Certificate.ThumbprintSecondary)
	require.NotNil(t, props.Certificate.X509StoreName)
	assert.Equal(t, armservicefabric.StoreNameMy, *props.Certificate.X509StoreName)
}

// TestServiceFabricAbsentValuesStayNull is the absent case. Azure omits or
// nulls most optional settings, and each one has to survive as nil rather than
// becoming a zero value: a false waveUpgradePaused would claim the cluster
// still receives runtime patches, and a zero-valued azureActiveDirectory would
// claim Entra integration on a cluster that has none.
func TestServiceFabricAbsentValuesStayNull(t *testing.T) {
	props := decodeLiveProperties(t)

	assert.Nil(t, props.AzureActiveDirectory, "absent Entra config must stay null, not an empty struct")
	assert.Nil(t, props.ReverseProxyCertificate)
	assert.Nil(t, props.CertificateCommonNames)
	assert.Nil(t, props.WaveUpgradePaused)
	assert.Nil(t, props.EventStoreServiceEnabled)
	assert.Nil(t, props.InfrastructureServiceManager)
	assert.Nil(t, props.SfZonalUpgradeMode)
	assert.Nil(t, props.AddOnFeatures)

	// An absent pause window must not become the zero time, which would report
	// 1 January year 1 as a real pause.
	assert.Nil(t, props.UpgradePauseStartTimestampUTC)
	assert.Nil(t, props.UpgradePauseEndTimestampUTC)
}

// TestServiceFabricDiagnosticsCarriesNoKeyMaterial guards the reason this
// block is mapped field by field instead of through convert.JsonToDict. Azure
// returns primaryAccessKey and secondaryAccessKey in the wire response (see the
// fixture above); armservicefabric v2.0.0 models neither, and this test fails
// if an SDK bump starts decoding them, which is the moment the hand-built map
// in serviceFabricDiagnosticsToMql would need revisiting.
func TestServiceFabricDiagnosticsCarriesNoKeyMaterial(t *testing.T) {
	props := decodeLiveProperties(t)
	cfg := props.DiagnosticsStorageAccountConfig
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.StorageAccountName)
	assert.Equal(t, "sflogsexample", *cfg.StorageAccountName)
	require.NotNil(t, cfg.ProtectedAccountKeyName)
	assert.Equal(t, "StorageAccountKey1", *cfg.ProtectedAccountKeyName)

	// Re-encoding the decoded struct must not carry the key members through.
	encoded, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "primaryAccessKey")
	assert.NotContains(t, string(encoded), "secondaryAccessKey")
}

// TestServiceFabricNodeTypeDecode pins the published ports. These are the
// values that say which management and application ports the scale set
// exposes, and a dropped tag would silently report port 0.
func TestServiceFabricNodeTypeDecode(t *testing.T) {
	props := decodeLiveProperties(t)
	require.Len(t, props.NodeTypes, 1)
	nt := props.NodeTypes[0]

	require.NotNil(t, nt.Name)
	assert.Equal(t, "nt1vm", *nt.Name)
	require.NotNil(t, nt.IsPrimary)
	assert.True(t, *nt.IsPrimary)
	require.NotNil(t, nt.IsStateless)
	assert.False(t, *nt.IsStateless)
	require.NotNil(t, nt.VMInstanceCount)
	assert.Equal(t, int32(3), *nt.VMInstanceCount)
	require.NotNil(t, nt.ClientConnectionEndpointPort)
	assert.Equal(t, int32(19000), *nt.ClientConnectionEndpointPort)
	require.NotNil(t, nt.HTTPGatewayEndpointPort)
	assert.Equal(t, int32(19080), *nt.HTTPGatewayEndpointPort)
	require.NotNil(t, nt.DurabilityLevel)
	assert.Equal(t, armservicefabric.DurabilityLevelBronze, *nt.DurabilityLevel)

	require.NotNil(t, nt.ApplicationPorts)
	assert.Equal(t, int32(20000), *nt.ApplicationPorts.StartPort)
	assert.Equal(t, int32(30000), *nt.ApplicationPorts.EndPort)
	require.NotNil(t, nt.EphemeralPorts)
	assert.Equal(t, int32(49152), *nt.EphemeralPorts.StartPort)
	assert.Equal(t, int32(65534), *nt.EphemeralPorts.EndPort)

	// No reverse proxy is configured on this node type; the port must stay
	// null rather than reading as port 0.
	assert.Nil(t, nt.ReverseProxyEndpointPort)
}

// TestServiceFabricManagementEndpointHTTPS covers the one value the provider
// derives rather than reports. An unsecured Service Fabric cluster publishes
// its management endpoint over plain HTTP, so this predicate is the difference
// between "administrative API is behind TLS" and "it is not".
func TestServiceFabricManagementEndpointHTTPS(t *testing.T) {
	str := func(s string) *string { return &s }

	tests := []struct {
		name     string
		endpoint *string
		want     *bool
	}{
		{"secured cluster", str("https://c.westus2.cloudapp.azure.com:19080"), new(true)},
		{"unsecured cluster", str("http://c.westus2.cloudapp.azure.com:19080"), new(false)},
		{"scheme casing is ignored", str("HTTPS://c.westus2.cloudapp.azure.com:19080"), new(true)},
		{"leading whitespace is trimmed", str("  https://c:19080"), new(true)},
		{"http host containing the word https", str("http://https.example.com:19080"), new(false)},
		{"empty endpoint is not https", str(""), new(false)},
		{"absent endpoint stays null", nil, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceFabricManagementEndpointHTTPS(tc.endpoint)
			if tc.want == nil {
				assert.Nil(t, got, "an unread endpoint must stay null, not report plaintext")
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, *got)
		})
	}
}

//go:fix inline
func boolPtrFor(b bool) *bool { return new(b) }

// TestServiceFabricSettingParameters covers the fabric-settings flattening,
// including the entries the loop is meant to skip. A nil name would panic on
// deref, and a section is what an audit reaches through to read
// ClusterProtectionLevel.
func TestServiceFabricSettingParameters(t *testing.T) {
	props := decodeLiveProperties(t)
	require.Len(t, props.FabricSettings, 1)
	require.NotNil(t, props.FabricSettings[0].Name)
	assert.Equal(t, "Security", *props.FabricSettings[0].Name)

	params := serviceFabricSettingParameters(props.FabricSettings[0].Parameters)
	assert.Equal(t, map[string]any{"ClusterProtectionLevel": "EncryptAndSign"}, params)

	name := "Present"
	tests := []struct {
		name  string
		input []*armservicefabric.SettingsParameterDescription
		want  map[string]any
	}{
		{"nil slice yields an empty map", nil, map[string]any{}},
		{"nil entries are skipped", []*armservicefabric.SettingsParameterDescription{nil}, map[string]any{}},
		{
			"entries with no name are skipped",
			[]*armservicefabric.SettingsParameterDescription{{Name: nil, Value: &name}},
			map[string]any{},
		},
		{
			"a named parameter with no value reads as empty, not as a missing key",
			[]*armservicefabric.SettingsParameterDescription{{Name: &name, Value: nil}},
			map[string]any{"Present": ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, serviceFabricSettingParameters(tc.input))
		})
	}
}

// TestServiceFabricAddOnFeatures covers the enum flattening. The live cluster
// returns null here, which has to come out as an empty list rather than
// panicking on a nil deref.
func TestServiceFabricAddOnFeatures(t *testing.T) {
	props := decodeLiveProperties(t)
	assert.Equal(t, []any{}, serviceFabricAddOnFeatures(props.AddOnFeatures))

	dns := armservicefabric.AddOnFeaturesDNSService
	backup := armservicefabric.AddOnFeaturesBackupRestoreService

	assert.Equal(t, []any{},
		serviceFabricAddOnFeatures([]*armservicefabric.AddOnFeatures{nil}),
		"a nil entry must be skipped, not dereferenced")

	assert.Equal(t, []any{"DnsService", "BackupRestoreService"},
		serviceFabricAddOnFeatures([]*armservicefabric.AddOnFeatures{&dns, nil, &backup}))
}

// TestServiceFabricEmptyClientCertificateLists distinguishes the two ways Azure
// says "none": this cluster returns null for certificateCommonNames and [] for
// the two client certificate lists, and both must reach MQL as an empty list so
// that clientCertificateThumbprints.none(isAdmin) evaluates rather than failing
// on a null.
func TestServiceFabricEmptyClientCertificateLists(t *testing.T) {
	props := decodeLiveProperties(t)

	assert.NotNil(t, props.ClientCertificateThumbprints, "[] must decode to an empty slice, not nil")
	assert.Empty(t, props.ClientCertificateThumbprints)
	assert.NotNil(t, props.ClientCertificateCommonNames)
	assert.Empty(t, props.ClientCertificateCommonNames)

	// null decodes to nil, which is the case the creator has to normalize.
	assert.Nil(t, props.CertificateCommonNames)
}

// TestServiceFabricAdminClientCertificateDecode pins the flag that separates a
// client certificate holding full administrative rights from a read-only one.
// A dropped isAdmin tag reads false, which would report an admin certificate as
// read-only and let a "no admin client certificates" check pass on a cluster
// that has one.
func TestServiceFabricAdminClientCertificateDecode(t *testing.T) {
	const payload = `{
      "clientCertificateThumbprints": [
        { "certificateThumbprint": "AAAA", "isAdmin": true },
        { "certificateThumbprint": "BBBB", "isAdmin": false }
      ],
      "clientCertificateCommonNames": [
        { "certificateCommonName": "admin.example.com",
          "certificateIssuerThumbprint": "CCCC",
          "isAdmin": true }
      ]
    }`

	var props armservicefabric.ClusterProperties
	require.NoError(t, json.Unmarshal([]byte(payload), &props))

	require.Len(t, props.ClientCertificateThumbprints, 2)
	require.NotNil(t, props.ClientCertificateThumbprints[0].CertificateThumbprint)
	assert.Equal(t, "AAAA", *props.ClientCertificateThumbprints[0].CertificateThumbprint)
	require.NotNil(t, props.ClientCertificateThumbprints[0].IsAdmin)
	assert.True(t, *props.ClientCertificateThumbprints[0].IsAdmin)
	require.NotNil(t, props.ClientCertificateThumbprints[1].IsAdmin)
	assert.False(t, *props.ClientCertificateThumbprints[1].IsAdmin)

	require.Len(t, props.ClientCertificateCommonNames, 1)
	cn := props.ClientCertificateCommonNames[0]
	require.NotNil(t, cn.CertificateCommonName)
	assert.Equal(t, "admin.example.com", *cn.CertificateCommonName)
	require.NotNil(t, cn.CertificateIssuerThumbprint)
	assert.Equal(t, "CCCC", *cn.CertificateIssuerThumbprint)
	require.NotNil(t, cn.IsAdmin)
	assert.True(t, *cn.IsAdmin)
}

// TestServiceFabricAzureActiveDirectoryDecode covers the populated Entra case,
// which the live cluster does not exercise. tenantId and the two application
// registrations are what a policy reads to confirm management access is behind
// Entra rather than certificates alone.
func TestServiceFabricAzureActiveDirectoryDecode(t *testing.T) {
	const payload = `{
      "azureActiveDirectory": {
        "tenantId": "00000000-0000-0000-0000-000000000001",
        "clusterApplication": "00000000-0000-0000-0000-000000000002",
        "clientApplication": "00000000-0000-0000-0000-000000000003"
      }
    }`

	var props armservicefabric.ClusterProperties
	require.NoError(t, json.Unmarshal([]byte(payload), &props))

	require.NotNil(t, props.AzureActiveDirectory)
	require.NotNil(t, props.AzureActiveDirectory.TenantID)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", *props.AzureActiveDirectory.TenantID)
	require.NotNil(t, props.AzureActiveDirectory.ClusterApplication)
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", *props.AzureActiveDirectory.ClusterApplication)
	require.NotNil(t, props.AzureActiveDirectory.ClientApplication)
	assert.Equal(t, "00000000-0000-0000-0000-000000000003", *props.AzureActiveDirectory.ClientApplication)
}
