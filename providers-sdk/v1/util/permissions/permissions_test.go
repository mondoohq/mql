// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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

const (
	kustoPkg     = "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"
	securityPkg  = "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	resourcesPkg = "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4"
)

// sdkRequest is the shape of a generated SDK request builder, as far as the
// extractor reads it.
func sdkRequest(client, fn, method, urlPath string) string {
	return fmt.Sprintf(`
func (client *%s) %s(ctx context.Context) (*policy.Request, error) {
	urlPath := %q
	req, err := runtime.NewRequest(ctx, http.Method%s, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
`, client, fn, urlPath, method)
}

// fakeAzureSDK is a module cache in memory: the files the index would open,
// keyed by their path under the (empty) cache root.
var fakeAzureSDK = map[string]string{
	"github.com/!azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2@v2.4.0/databases_client.go": "package armkusto\n" +
		sdkRequest("DatabasesClient", "listByClusterCreateRequest", "Get", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/databases") +
		sdkRequest("DatabasesClient", "getCreateRequest", "Get", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/databases/{databaseName}"),
	"github.com/!azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2@v2.4.0/clusters_client.go": "package armkusto\n" +
		sdkRequest("ClustersClient", "listCalloutPoliciesCreateRequest", "Post", "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/listCalloutPolicies"),
	"github.com/!azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity@v0.15.0/autoprovisioningsettings_client.go": "package armsecurity\n" +
		sdkRequest("AutoProvisioningSettingsClient", "getCreateRequest", "Get", "/subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/{settingName}"),
	"github.com/!azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity@v0.15.0/pricings_client.go": "package armsecurity\n" +
		sdkRequest("PricingsClient", "getCreateRequest", "Get", "/{scopeId}/providers/Microsoft.Security/pricings/{pricingName}"),
	"github.com/!azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4@v4.0.0/client.go": "package armresources\n" +
		sdkRequest("Client", "listCreateRequest", "Get", "/subscriptions/{subscriptionId}/resources"),
}

func azureTestIndex() *azureSDKIndex {
	return &azureSDKIndex{
		cache: "",
		versions: map[string]string{
			kustoPkg:     "v2.4.0",
			securityPkg:  "v0.15.0",
			resourcesPkg: "v4.0.0",
		},
		read: func(path string) ([]byte, error) {
			src, ok := fakeAzureSDK[path]
			if !ok {
				return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
			}
			return []byte(src), nil
		},
	}
}

func TestAzureSDKIndexRequest(t *testing.T) {
	idx := azureTestIndex()

	urlPath, method, err := idx.request(azureCall{importPath: kustoPkg, client: "DatabasesClient", method: "NewListByClusterPager"})
	require.NoError(t, err)
	assert.Equal(t, "GET", method)
	assert.Contains(t, urlPath, "/clusters/{clusterName}/databases")

	_, method, err = idx.request(azureCall{importPath: kustoPkg, client: "ClustersClient", method: "NewListCalloutPoliciesPager"})
	require.NoError(t, err)
	assert.Equal(t, "POST", method)

	// The generic Client lives in client.go.
	urlPath, _, err = idx.request(azureCall{importPath: resourcesPkg, client: "Client", method: "NewListPager"})
	require.NoError(t, err)
	assert.Equal(t, "/subscriptions/{subscriptionId}/resources", urlPath)

	_, _, err = idx.request(azureCall{importPath: kustoPkg, client: "DatabasesClient", method: "NewListPager"})
	assert.ErrorContains(t, err, "no listCreateRequest on DatabasesClient")
	_, _, err = idx.request(azureCall{importPath: "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/nope/armnope", client: "ThingsClient", method: "Get"})
	assert.ErrorContains(t, err, "not pinned")
	_, _, err = idx.request(azureCall{importPath: kustoPkg, client: "NopeClient", method: "Get"})
	assert.ErrorContains(t, err, "module cache")
}

// providerSource is a provider file in the shapes the extractor must
// understand: a package-qualified client, a factory-created client stored in a
// variable, an inline factory chain, and a package's generic client.
const providerSource = `package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4"
	security "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
)

func databases(ctx context.Context) {
	client, err := armkusto.NewDatabasesClient("sub", nil, nil)
	if err != nil {
		return
	}
	_ = client.NewListByClusterPager("rg", "cluster", nil)
	_, _ = client.Get(ctx, "rg", "cluster", "db", nil)
}

func callouts() {
	clusters, _ := armkusto.NewClustersClient("sub", nil, nil)
	_ = clusters.NewListCalloutPoliciesPager("rg", "cluster", nil)
}

func defender(ctx context.Context) {
	f, _ := security.NewClientFactory("sub", nil, nil)
	settings := f.NewAutoProvisioningSettingsClient()
	_, _ = settings.Get(ctx, "default", nil)
	_ = f.NewPricingsClient().Get(ctx, "scope", "name", nil)
}

func resources() {
	generic, _ := armresources.NewClient("sub", nil, nil)
	_ = generic.NewListPager(nil)
}
`

func parseProvider(t *testing.T) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "kusto.go", providerSource, 0)
	require.NoError(t, err)
	return f
}

func TestAzureCallsInFile(t *testing.T) {
	calls := azureCallsInFile(parseProvider(t), "kusto.go")
	got := map[string]bool{}
	for _, c := range calls {
		got[c.key()] = true
		assert.Equal(t, "kusto.go", c.file)
	}
	assert.Equal(t, map[string]bool{
		kustoPkg + " DatabasesClient.NewListByClusterPager":      true,
		kustoPkg + " DatabasesClient.Get":                        true,
		kustoPkg + " ClustersClient.NewListCalloutPoliciesPager": true,
		securityPkg + " AutoProvisioningSettingsClient.Get":      true,
		securityPkg + " PricingsClient.Get":                      true,
		resourcesPkg + " Client.NewListPager":                    true,
	}, got)
}

func TestAzureDetails(t *testing.T) {
	idx := azureTestIndex()
	got := map[string]PermissionDetail{}
	for _, call := range azureCallsInFile(parseProvider(t), "kusto.go") {
		d, emit, err := azureDetail(idx, call)
		require.NoError(t, err, call.key())
		if emit {
			got[d.Permission+" "+d.Action] = d
		}
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
	idx := azureTestIndex()
	call := azureCall{importPath: kustoPkg, client: "DatabasesClient", method: "NewListPager", file: "x.go"}

	// A call whose request builder cannot be read is an error, not a silent drop...
	_, _, err := azureDetail(idx, call)
	assert.ErrorContains(t, err, "azureSDKCallOverrides")

	// ...unless an override names its operation, or skips it.
	azureSDKCallOverrides[call.key()] = "Microsoft.Kusto/clusters/read"
	defer delete(azureSDKCallOverrides, call.key())
	d, emit, err := azureDetail(idx, call)
	require.NoError(t, err)
	assert.True(t, emit)
	assert.Equal(t, "Microsoft.Kusto/clusters/read", d.Permission)
	assert.Equal(t, "Microsoft.Kusto", d.Service)
	azureSDKCallOverrides[call.key()] = ""
	_, emit, err = azureDetail(idx, call)
	require.NoError(t, err)
	assert.False(t, emit)

	// A registry deviation is renamed to the registered form.
	assert.Equal(t, "Microsoft.Insights/eventtypes/values/Read",
		azurePathOperationOverrides["microsoft.insights/eventtypes/management/values/read"])
}
