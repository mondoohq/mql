// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureOperationFromPath(t *testing.T) {
	cases := []struct{ method, path, ns, op string }{
		{"GET", "/subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/Microsoft.Kusto/clusters/{c}/databases", "Microsoft.Kusto", "Microsoft.Kusto/clusters/databases/read"},
		{"GET", "/subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/{settingName}", "Microsoft.Security", "Microsoft.Security/autoProvisioningSettings/read"},
		{"GET", "/subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{a}/tableServices/default/tables", "Microsoft.Storage", "Microsoft.Storage/storageAccounts/tableServices/tables/read"},
		{"POST", "/subscriptions/{s}/providers/Microsoft.PolicyInsights/policyStates/{policyStatesResource}/queryResults", "Microsoft.PolicyInsights", "Microsoft.PolicyInsights/policyStates/queryResults/action"},
		{"GET", "/{resourceUri}/providers/Microsoft.Insights/diagnosticSettings", "Microsoft.Insights", "Microsoft.Insights/diagnosticSettings/read"},
		{"GET", "/subscriptions/{s}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/providers/Microsoft.Insights/metrics", "Microsoft.Insights", "Microsoft.Insights/metrics/read"},
		{"GET", "/subscriptions/{subscriptionId}/resources", "Microsoft.Resources", "Microsoft.Resources/subscriptions/resources/read"},
		{"GET", "/subscriptions/{subscriptionId}/resourcegroups?api-version=x", "Microsoft.Resources", "Microsoft.Resources/subscriptions/resourcegroups/read"},
		{"GET", "/subscriptions", "Microsoft.Resources", "Microsoft.Resources/subscriptions/read"},
		{"GET", "/providers/Microsoft.Management/managementGroups", "Microsoft.Management", "Microsoft.Management/managementGroups/read"},
		{"GET", "/{scope}/providers/Microsoft.Authorization/roleAssignments", "Microsoft.Authorization", "Microsoft.Authorization/roleAssignments/read"},
	}
	for _, c := range cases {
		ns, op := azureOperationFromPath(c.path, c.method)
		assert.Equal(t, c.ns, ns, c.path)
		assert.Equal(t, c.op, op, c.path)
	}
}

// azureTestIndex points the SDK lookup at the trimmed module cache under
// testdata, pinned the way a provider's go.mod would pin the real modules.
func azureTestIndex(t *testing.T) *azureSDKIndex {
	t.Helper()
	return &azureSDKIndex{
		cache: filepath.Join("testdata", "azure-modcache"),
		versions: map[string]string{
			"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2":         "v2.4.0",
			"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4": "v4.0.0",
			"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity":      "v0.15.0",
		},
	}
}

func TestParseAzureSDKVersions(t *testing.T) {
	gomod := []byte(`module example.com/azure

go 1.26

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2 v2.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity v0.15.0 // indirect
	github.com/stretchr/testify v1.11.1
)
`)
	assert.Equal(t, map[string]string{
		"github.com/Azure/azure-sdk-for-go/sdk/azcore":                               "v1.20.0",
		"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2":    "v2.4.0",
		"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity": "v0.15.0",
	}, parseAzureSDKVersions(gomod))
}

func TestAzureSDKIndexRequest(t *testing.T) {
	idx := azureTestIndex(t)
	kusto := "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"

	urlPath, method, err := idx.request(azureCall{importPath: kusto, client: "DatabasesClient", method: "NewListByClusterPager"})
	require.NoError(t, err)
	assert.Equal(t, "GET", method)
	assert.Contains(t, urlPath, "/clusters/{clusterName}/databases")

	_, method, err = idx.request(azureCall{importPath: kusto, client: "ClustersClient", method: "NewListCalloutPoliciesPager"})
	require.NoError(t, err)
	assert.Equal(t, "POST", method)

	// The generic Client lives in client.go.
	urlPath, _, err = idx.request(azureCall{importPath: "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4", client: "Client", method: "NewListPager"})
	require.NoError(t, err)
	assert.Equal(t, "/subscriptions/{subscriptionId}/resources", urlPath)

	_, _, err = idx.request(azureCall{importPath: kusto, client: "DatabasesClient", method: "NewListPager"})
	assert.ErrorContains(t, err, "no listCreateRequest on DatabasesClient")
	_, _, err = idx.request(azureCall{importPath: "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/nope/armnope", client: "ThingsClient", method: "Get"})
	assert.ErrorContains(t, err, "not pinned")
	_, _, err = idx.request(azureCall{importPath: kusto, client: "NopeClient", method: "Get"})
	assert.ErrorContains(t, err, "module cache")
}

func TestExtractAzurePermissions(t *testing.T) {
	details, err := extractAzurePermissionsWith(azureTestIndex(t), filepath.Join("testdata", "azure-provider"))
	require.NoError(t, err)

	got := map[string]PermissionDetail{}
	for _, d := range details {
		got[d.Permission+" "+d.Action] = d
	}
	// A package-qualified client: the parent path comes from the URL, not the
	// client name.
	assert.Contains(t, got, "Microsoft.Kusto/clusters/databases/read NewListByClusterPager")
	assert.Contains(t, got, "Microsoft.Kusto/clusters/databases/read Get")
	// A POST is an action named by its last segment.
	assert.Contains(t, got, "Microsoft.Kusto/clusters/listCalloutPolicies/action NewListCalloutPoliciesPager")
	// An inline factory chain, under a package imported with an alias.
	assert.Contains(t, got, "Microsoft.Security/pricings/read Get")
	// A package's generic client, in client.go, on a path with no /providers/.
	assert.Contains(t, got, "Microsoft.Resources/subscriptions/resources/read NewListPager")
	// An operation no provider registers is not emitted.
	for k := range got {
		assert.NotContains(t, k, "autoProvisioningSettings")
	}
	assert.Len(t, got, 5)

	d := got["Microsoft.Kusto/clusters/databases/read NewListByClusterPager"]
	assert.Equal(t, "Microsoft.Kusto", d.Service)
	assert.Equal(t, "kusto.go", d.SourceFile)
}

func TestAzureDetailOverrides(t *testing.T) {
	idx := azureTestIndex(t)
	kusto := "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"

	// A call whose request builder cannot be read is an error, not a silent drop...
	_, _, err := azureDetail(idx, azureCall{importPath: kusto, client: "DatabasesClient", method: "NewListPager", file: "x.go"})
	assert.ErrorContains(t, err, "azureSDKCallOverrides")

	// ...unless an override names its operation, or skips it.
	key := kusto + " DatabasesClient.NewListPager"
	azureSDKCallOverrides[key] = "Microsoft.Kusto/clusters/read"
	defer delete(azureSDKCallOverrides, key)
	d, emit, err := azureDetail(idx, azureCall{importPath: kusto, client: "DatabasesClient", method: "NewListPager", file: "x.go"})
	require.NoError(t, err)
	assert.True(t, emit)
	assert.Equal(t, "Microsoft.Kusto/clusters/read", d.Permission)
	assert.Equal(t, "Microsoft.Kusto", d.Service)
	azureSDKCallOverrides[key] = ""
	_, emit, err = azureDetail(idx, azureCall{importPath: kusto, client: "DatabasesClient", method: "NewListPager", file: "x.go"})
	require.NoError(t, err)
	assert.False(t, emit)

	// A registry deviation is renamed to the registered form.
	assert.Equal(t, "Microsoft.Insights/eventtypes/values/Read",
		azurePathOperationOverrides["microsoft.insights/eventtypes/management/values/read"])
}
