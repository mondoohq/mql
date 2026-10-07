// A trimmed provider file in the shapes the extractor must understand: a
// package-qualified client, a factory-created client stored in a variable, an
// inline factory chain, and a generic Client. It is parsed, never compiled.
package resources

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
	pager := client.NewListByClusterPager("rg", "cluster", nil)
	_ = pager
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
