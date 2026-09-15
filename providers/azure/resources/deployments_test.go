// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	armdeployments "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armdeployments/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

const testDeploymentID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Resources/deployments/dep-1"

// A deployment that carried no template link supplied its template inline with
// the request. Reporting a resource of empty members there would say the
// deployment ran a template from nowhere, which a check for "deployed from a
// Template Spec" would read as a definite no rather than as unknown.
func TestDeploymentTemplateSourceIsNullWithoutALink(t *testing.T) {
	data, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID, nil)
	require.NoError(t, err)
	assert.Equal(t, llx.NilData, data)
}

// ARM documents TemplateLink.QueryString as where a SAS token goes, but a
// deployment run from a SAS-protected blob comes back with the whole signed
// URL in URI and QueryString empty. This was verified against a live
// deployment from a blob linked with a read SAS: the token arrived in URI.
//
// Both shapes are exercised because the documented one is what the fixture
// would otherwise assert, and it is the one that does not occur.
func TestDeploymentTemplateSourceDoesNotPublishTheSASToken(t *testing.T) {
	const base = "https://stg.blob.core.windows.net/templates/main.json"
	const query = "se=2026-09-15T18%3A32Z&sp=r&sv=2026-04-06&sr=b&sig=PLACEHOLDER-NOT-A-REAL-SIGNATURE"

	t.Run("the token arrives inside the URI, as ARM actually returns it", func(t *testing.T) {
		data, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID,
			&armdeployments.TemplateLink{URI: ptr(base + "?" + query), ContentVersion: ptr("1.0.0.0")})
		require.NoError(t, err)

		src, ok := data.Value.(*mqlAzureSubscriptionDeploymentTemplateSource)
		require.True(t, ok, "expected a template source resource, got %T", data.Value)
		assert.Equal(t, base, src.Uri.Data)
		assert.NotContains(t, src.Uri.Data, "sig=")
		assert.Equal(t, "1.0.0.0", src.ContentVersion.Data)
	})

	t.Run("the token arrives in QueryString, as ARM documents it", func(t *testing.T) {
		data, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID,
			&armdeployments.TemplateLink{URI: ptr(base), QueryString: ptr(query)})
		require.NoError(t, err)

		src := data.Value.(*mqlAzureSubscriptionDeploymentTemplateSource)
		assert.Equal(t, base, src.Uri.Data)
		assert.NotContains(t, src.Uri.Data, "sig=")
	})

	t.Run("a URI with no query string is published whole", func(t *testing.T) {
		data, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID,
			&armdeployments.TemplateLink{URI: ptr(base)})
		require.NoError(t, err)

		assert.Equal(t, base, data.Value.(*mqlAzureSubscriptionDeploymentTemplateSource).Uri.Data)
	})
}

// Both links on the deployment read off a URI that can carry the token, so
// both have to be stripped. ParametersLink is the stronger case of the two:
// unlike TemplateLink it has no QueryString member at all, so a SAS-protected
// parameters file has nowhere else to put its token.
func TestDeploymentLinksBothDropTheSASToken(t *testing.T) {
	const templateBase = "https://stg.blob.core.windows.net/templates/main.json"
	const paramsBase = "https://stg.blob.core.windows.net/templates/prod.parameters.json"
	const query = "?sp=r&sig=PLACEHOLDER-NOT-A-REAL-SIGNATURE"

	deployment := &armdeployments.DeploymentExtended{
		ID:   ptr(testDeploymentID),
		Name: ptr("from-uri"),
		Properties: &armdeployments.DeploymentPropertiesExtended{
			TemplateLink:   &armdeployments.TemplateLink{URI: ptr(templateBase + query)},
			ParametersLink: &armdeployments.ParametersLink{URI: ptr(paramsBase + query)},
		},
	}

	res, err := newMqlAzureDeployment(azureTestRuntime(), deployment)
	require.NoError(t, err)

	assert.Equal(t, templateBase, res.TemplateLink.Data)
	assert.NotContains(t, res.TemplateLink.Data, "sig=")
	assert.Equal(t, paramsBase, res.ParametersLink.Data)
	assert.NotContains(t, res.ParametersLink.Data, "sig=")
}

// A deployment run from a Template Spec carries an ID and no URI, and one run
// from a URI carries the reverse. Both directions have to survive, because
// "this deployment came from a Template Spec" is read off which one is set.
func TestDeploymentTemplateSourceSeparatesSpecFromURI(t *testing.T) {
	const specID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Resources/templateSpecs/base/versions/2.1"

	spec, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID,
		&armdeployments.TemplateLink{ID: ptr(specID), RelativePath: ptr("modules/network.json")})
	require.NoError(t, err)
	fromSpec := spec.Value.(*mqlAzureSubscriptionDeploymentTemplateSource)
	assert.Equal(t, specID, fromSpec.TemplateSpecId.Data)
	assert.Empty(t, fromSpec.Uri.Data)
	assert.Equal(t, "modules/network.json", fromSpec.RelativePath.Data)

	uri, err := deploymentTemplateSource(azureTestRuntime(), testDeploymentID,
		&armdeployments.TemplateLink{URI: ptr("https://example.com/t.json")})
	require.NoError(t, err)
	fromURI := uri.Value.(*mqlAzureSubscriptionDeploymentTemplateSource)
	assert.Empty(t, fromURI.TemplateSpecId.Data)
	assert.Equal(t, "https://example.com/t.json", fromURI.Uri.Data)
}

// Nothing in a diagnostic identifies it, so two findings of the same code on
// one deployment are indistinguishable by content. Keyed by content they would
// share a cache entry and the second would be dropped, which understates how
// many findings a deployment proceeded over.
func TestDeploymentDiagnosticsWithIdenticalContentStayDistinct(t *testing.T) {
	diags := []*armdeployments.DeploymentDiagnosticsDefinition{
		{
			Code:    ptr("NestedDeploymentShortCircuit"),
			Level:   ptr(armdeployments.LevelWarning),
			Message: ptr("first occurrence"),
		},
		{
			Code:    ptr("NestedDeploymentShortCircuit"),
			Level:   ptr(armdeployments.LevelWarning),
			Message: ptr("second occurrence"),
		},
	}

	res, err := deploymentDiagnostics(azureTestRuntime(), testDeploymentID, diags)
	require.NoError(t, err)
	require.Len(t, res, 2)

	first := res[0].(*mqlAzureSubscriptionDeploymentDiagnostic)
	second := res[1].(*mqlAzureSubscriptionDeploymentDiagnostic)
	assert.NotEqual(t, first.MqlID(), second.MqlID())
	assert.Equal(t, "first occurrence", first.Message.Data)
	assert.Equal(t, "second occurrence", second.Message.Data)
	assert.Equal(t, "Warning", first.Level.Data)
}

// An Error level finding on a deployment that reports Succeeded is the case
// the field exists for, so the level has to arrive as the SDK's own value
// rather than as an empty string.
func TestDeploymentDiagnosticLevelSurvivesTheEnum(t *testing.T) {
	res, err := deploymentDiagnostics(azureTestRuntime(), testDeploymentID,
		[]*armdeployments.DeploymentDiagnosticsDefinition{
			{Level: ptr(armdeployments.LevelError), Code: ptr("InvalidTemplate"), Target: ptr("resources[3]")},
		})
	require.NoError(t, err)
	require.Len(t, res, 1)

	d := res[0].(*mqlAzureSubscriptionDeploymentDiagnostic)
	assert.Equal(t, string(armdeployments.LevelError), d.Level.Data)
	assert.Equal(t, "resources[3]", d.Target.Data)
	assert.Empty(t, d.Message.Data)
}

// The typed view exists to carry what the []string outputResources field drops.
// A resource deployed through an extension has no ARM ID, so those entries also
// prove the key does not collapse when ID is absent.
func TestDeploymentProvisionedResourcesCarryTypeAndVersion(t *testing.T) {
	refs := []*armdeployments.ResourceReference{
		{
			ID:               ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/stg1"),
			ResourceType:     ptr("Microsoft.Storage/storageAccounts"),
			APIVersion:       ptr("2021-04-01"),
			SymbolicNamePath: []*string{ptr("network"), nil, ptr("storage")},
		},
		nil,
		{ResourceType: ptr("Kubernetes.Core/configMaps")},
		{ResourceType: ptr("Kubernetes.Core/secrets")},
	}

	res, err := deploymentProvisionedResources(azureTestRuntime(), testDeploymentID, refs)
	require.NoError(t, err)
	require.Len(t, res, 3, "the nil reference should be skipped, not carried as an empty resource")

	first := res[0].(*mqlAzureSubscriptionDeploymentProvisionedResource)
	assert.Equal(t, "Microsoft.Storage/storageAccounts", first.ResourceType.Data)
	assert.Equal(t, "2021-04-01", first.ApiVersion.Data)
	// A nil element in the SDK slice is skipped rather than dereferenced.
	assert.Equal(t, []any{"network", "storage"}, first.SymbolicNamePath.Data)

	// Two extension-deployed resources share an empty ID; keyed on it they
	// would be one entry reporting the first one's type.
	assert.NotEqual(t, res[1].(*mqlAzureSubscriptionDeploymentProvisionedResource).MqlID(),
		res[2].(*mqlAzureSubscriptionDeploymentProvisionedResource).MqlID())
	assert.Equal(t, "Kubernetes.Core/secrets",
		res[2].(*mqlAzureSubscriptionDeploymentProvisionedResource).ResourceType.Data)
}

// Every deployment that updates a storage account records it again, each with
// the API version its own template was written against. Keyed on the ARM ID
// alone these share one cache entry, and the second deployment reports the
// first one's API version, which is the value the field exists to carry.
func TestDeploymentProvisionedResourcesDoNotCollideAcrossDeployments(t *testing.T) {
	const stg = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/stg1"
	runtime := azureTestRuntime()

	old, err := deploymentProvisionedResources(runtime, testDeploymentID+"-2019",
		[]*armdeployments.ResourceReference{{ID: ptr(stg), APIVersion: ptr("2019-06-01")}})
	require.NoError(t, err)
	current, err := deploymentProvisionedResources(runtime, testDeploymentID+"-2024",
		[]*armdeployments.ResourceReference{{ID: ptr(stg), APIVersion: ptr("2024-01-01")}})
	require.NoError(t, err)

	assert.Equal(t, "2019-06-01", old[0].(*mqlAzureSubscriptionDeploymentProvisionedResource).ApiVersion.Data)
	assert.Equal(t, "2024-01-01", current[0].(*mqlAzureSubscriptionDeploymentProvisionedResource).ApiVersion.Data)
}

// The same dependency recorded by two deployments is two records, for the same
// reason.
func TestDeploymentDependenciesDoNotCollideAcrossDeployments(t *testing.T) {
	const vnet = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet"
	runtime := azureTestRuntime()

	first, err := deploymentDependencies(runtime, testDeploymentID+"-a",
		[]*armdeployments.Dependency{{ID: ptr(vnet), ResourceName: ptr("vnet-as-named-in-a")}})
	require.NoError(t, err)
	second, err := deploymentDependencies(runtime, testDeploymentID+"-b",
		[]*armdeployments.Dependency{{ID: ptr(vnet), ResourceName: ptr("vnet-as-named-in-b")}})
	require.NoError(t, err)

	assert.Equal(t, "vnet-as-named-in-a", first[0].(*mqlAzureSubscriptionDeploymentDependency).ResourceName.Data)
	assert.Equal(t, "vnet-as-named-in-b", second[0].(*mqlAzureSubscriptionDeploymentDependency).ResourceName.Data)
}

// A resource deployed directly through ARM has no extension, and reports null
// rather than an extension resource of empty members.
func TestDeploymentProvisionedResourceExtensionIsNullWhenAbsent(t *testing.T) {
	res, err := deploymentProvisionedResources(azureTestRuntime(), testDeploymentID,
		[]*armdeployments.ResourceReference{{ID: ptr("/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts/s")}})
	require.NoError(t, err)
	require.Len(t, res, 1)

	assert.Nil(t, res[0].(*mqlAzureSubscriptionDeploymentProvisionedResource).Extension.Data)
}

// The same resource can be waited on by two different resources in one
// template. Keyed by the dependency's own ID alone, the second parent's child
// would resolve to the first parent's cached node.
func TestDeploymentDependenciesNestUnderTheirParent(t *testing.T) {
	shared := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/virtualNetworks/vnet"
	deps := []*armdeployments.Dependency{
		{
			ID:           ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm1"),
			ResourceName: ptr("vm1"),
			ResourceType: ptr("Microsoft.Compute/virtualMachines"),
			DependsOn:    []*armdeployments.BasicDependency{{ID: ptr(shared), ResourceName: ptr("vnet")}},
		},
		{
			ID:           ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm2"),
			ResourceName: ptr("vm2"),
			ResourceType: ptr("Microsoft.Compute/virtualMachines"),
			DependsOn:    []*armdeployments.BasicDependency{{ID: ptr(shared), ResourceName: ptr("vnet")}},
		},
	}

	res, err := deploymentDependencies(azureTestRuntime(), testDeploymentID, deps)
	require.NoError(t, err)
	require.Len(t, res, 2)

	vm1 := res[0].(*mqlAzureSubscriptionDeploymentDependency)
	vm2 := res[1].(*mqlAzureSubscriptionDeploymentDependency)
	require.Len(t, vm1.DependsOn.Data, 1)
	require.Len(t, vm2.DependsOn.Data, 1)

	under1 := vm1.DependsOn.Data[0].(*mqlAzureSubscriptionDeploymentDependency)
	under2 := vm2.DependsOn.Data[0].(*mqlAzureSubscriptionDeploymentDependency)
	assert.NotEqual(t, under1.MqlID(), under2.MqlID())
	assert.Equal(t, shared, under1.Id.Data)
	assert.Equal(t, "vnet", under2.ResourceName.Data)
	// The leaves carry no dependencies of their own, and report that as an
	// empty list rather than as null.
	assert.Equal(t, []any{}, under1.DependsOn.Data)
}

// A template that declared no dependencies reports an empty list. Null there
// would pass a check written as "every dependency is in an approved type",
// which is the direction that matters.
func TestDeploymentDependenciesAreEmptyNotNullWhenAbsent(t *testing.T) {
	res, err := deploymentDependencies(azureTestRuntime(), testDeploymentID, nil)
	require.NoError(t, err)
	assert.Equal(t, []any{}, res)
}

// Extensions have no ARM ID at all, so every entry is keyed by position.
func TestDeploymentExtensionsStayDistinctWithoutIDs(t *testing.T) {
	exts := []*armdeployments.DeploymentExtensionDefinition{
		{Name: ptr("Microsoft.Kubernetes"), Version: ptr("1.0.0"), Alias: ptr("k8sProd"), ConfigID: ptr("cfg"), ConfigHash: ptr("h1")},
		{Name: ptr("Microsoft.Kubernetes"), Version: ptr("1.0.0"), Alias: ptr("k8sStaging"), ConfigID: ptr("cfg"), ConfigHash: ptr("h2")},
	}

	res, err := deploymentExtensions(azureTestRuntime(), testDeploymentID, exts)
	require.NoError(t, err)
	require.Len(t, res, 2)

	first := res[0].(*mqlAzureSubscriptionDeploymentExtension)
	second := res[1].(*mqlAzureSubscriptionDeploymentExtension)
	assert.NotEqual(t, first.MqlID(), second.MqlID())
	// Same extension and same configId, different configuration: configHash is
	// what tells the two targets apart.
	assert.Equal(t, "h1", first.ConfigHash.Data)
	assert.Equal(t, "h2", second.ConfigHash.Data)
	assert.Equal(t, "k8sStaging", second.Alias.Data)
}
