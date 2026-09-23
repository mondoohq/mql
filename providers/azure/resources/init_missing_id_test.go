// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// runtimeForAsset builds a runtime whose connection reports the given asset.
// Nothing here reaches the network: the inits under test bail out before they
// build a client, and constructing an Azure credential only assembles the
// sign-in chain.
//
// The resource cache is real because the inits resolve their resource out of
// the parent service's list, so they reach NewResource before they reach
// anything that would talk to Azure.
func runtimeForAsset(t *testing.T, platformIds []string) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{Name: "some asset", PlatformIds: platformIds}
	conf := &inventory.Config{Options: map[string]string{"tenant-id": "tid", "client-id": "cid", "subscription-id": "sub-1"}}
	conn, err := connection.NewAzureConnection(1, asset, conf)
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// A resource queried bare -- no id, and a scanned asset that is not itself that
// resource -- used to fall through and hand the runtime a blank resource. Every
// field of it then came back as neither data nor error, which the client logs
// once per field as an untyped primitive coerced to null, with an empty id to
// identify it by. The init has to say so instead.
//
// A subscription asset is the case that reaches this: its platform ids carry
// only the //platformid.api.mondoo.app form, never the /subscriptions/... ARM id
// that getAssetIdentifier looks for.
func TestInitsReportAMissingID(t *testing.T) {
	inits := []struct {
		resource string
		init     func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)
	}{
		{"azure.subscription.networkService.firewall", initAzureSubscriptionNetworkServiceFirewall},
		{"azure.subscription.networkService.applicationGateway", initAzureSubscriptionNetworkServiceApplicationGateway},
		{"azure.subscription.containerAppService.containerApp", initAzureSubscriptionContainerAppServiceContainerApp},
		{"azure.subscription.containerAppService.sandboxGroup", initAzureSubscriptionContainerAppServiceSandboxGroup},
		{"azure.subscription.functionsService.functionApp", initAzureSubscriptionFunctionsServiceFunctionApp},
		{"azure.subscription.computeService.vm", initAzureSubscriptionComputeServiceVm},
		{"azure.subscription.keyVaultService.vault", initAzureSubscriptionKeyVaultServiceVault},
		{"azure.subscription.cosmosDbService.account", initAzureSubscriptionCosmosDbServiceAccount},
		{"azure.subscription.cacheService.redisInstance", initAzureSubscriptionCacheServiceRedisInstance},
		{"azure.subscription.cognitiveServicesService.account", initAzureSubscriptionCognitiveServicesServiceAccount},
	}

	subscriptionAsset := []string{"//platformid.api.mondoo.app/runtime/azure/subscriptions/sub-1"}

	for _, tc := range inits {
		t.Run(tc.resource, func(t *testing.T) {
			runtime := runtimeForAsset(t, subscriptionAsset)

			args, res, err := tc.init(runtime, map[string]*llx.RawData{})
			require.Error(t, err, "a bare init with no asset id must not report success")
			require.Nil(t, res, "no resource may be built without an id")
			require.Nil(t, args, "returning args would let the runtime build a blank resource")
			require.Contains(t, err.Error(), tc.resource)
		})
	}
}

// The asset-scoped path still works: scanning the resource itself supplies the
// ARM id, and the init gets far enough to want a client.
func TestInitsAcceptTheAssetsArmID(t *testing.T) {
	armID := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw-1"
	runtime := runtimeForAsset(t, []string{
		"//platformid.api.mondoo.app/runtime/azure" + armID,
		armID,
	})

	args := map[string]*llx.RawData{}
	_, _, err := initAzureSubscriptionNetworkServiceFirewall(runtime, args)
	// the id was taken from the asset, so this got past the guard and only
	// failed later, on the call we deliberately cannot make in a test
	require.Equal(t, armID, args["id"].Value)
	if err != nil {
		require.NotContains(t, err.Error(), "requires an id")
	}
}
