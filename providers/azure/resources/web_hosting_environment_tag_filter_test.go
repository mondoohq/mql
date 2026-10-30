// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const (
	testEnvA  = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/hostingEnvironments/ase-a"
	testEnvB  = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/hostingEnvironments/ase-b"
	testSiteB = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/app-b"
)

func taggedHostingEnvironment(t *testing.T, runtime *plugin.Runtime, id string, tags map[string]any) *mqlAzureSubscriptionWebServiceHostingEnvironment {
	t.Helper()
	res, err := CreateResource(runtime, ResourceAzureSubscriptionWebServiceHostingEnvironment, map[string]*llx.RawData{
		"id":   llx.StringData(id),
		"tags": llx.MapData(tags, types.String),
	})
	require.NoError(t, err)
	return res.(*mqlAzureSubscriptionWebServiceHostingEnvironment)
}

// webServiceWithEnvironments puts the web service in the cache with its
// hostingEnvironments field resolved the way the lister resolves it: the full
// list, narrowed by keepTagMatches.
func webServiceWithEnvironments(t *testing.T, runtime *plugin.Runtime, envs ...any) []any {
	t.Helper()
	svcRes, err := NewResource(runtime, ResourceAzureSubscriptionWebService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData("sub-1"),
	})
	require.NoError(t, err)
	kept := keepTagMatches(runtime, envs)
	svcRes.(*mqlAzureSubscriptionWebService).HostingEnvironments = plugin.TValue[[]any]{Data: kept, State: plugin.StateIsSet}
	return kept
}

// The subscription's App Service Environments honor the tag filter, as its
// apps do, and an app still resolves the environment it runs in when the
// filter left that environment out of the list.
func TestHostingEnvironmentsHonorTagFilter(t *testing.T) {
	runtime := runtimeWithTagFilters(t, map[string]string{"env": "a"}, nil)
	a := taggedHostingEnvironment(t, runtime, testEnvA, map[string]any{"env": "a"})
	b := taggedHostingEnvironment(t, runtime, testEnvB, map[string]any{"env": "b"})
	kept := webServiceWithEnvironments(t, runtime, a, b)
	assert.Equal(t, []any{a}, kept)

	_, res, err := initAzureSubscriptionWebServiceHostingEnvironment(runtime, map[string]*llx.RawData{"id": llx.StringData(testEnvB)})
	require.NoError(t, err)
	assert.Same(t, b, res, "an init by id resolves an environment the filter left out")

	siteRes, err := CreateResource(runtime, ResourceAzureSubscriptionWebServiceAppsite, map[string]*llx.RawData{
		"id": llx.StringData(testSiteB),
		"properties": llx.DictData(map[string]any{
			"hostingEnvironmentProfile": map[string]any{"id": testEnvB},
		}),
	})
	require.NoError(t, err)
	env, err := siteRes.(*mqlAzureSubscriptionWebServiceAppsite).hostingEnvironment()
	require.NoError(t, err)
	assert.Same(t, b, env, "an app resolves the environment it runs in although the filter left it out")
}
