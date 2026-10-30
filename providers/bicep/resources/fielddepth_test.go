// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A nested `name:` must not win over the resource's own. This is the ordinary
// shape of a VNet — subnets carry names, and Bicep does not require the
// resource's own `name` to come first — so the wrong value is what a naming
// convention or "this specific resource" policy would have matched on.
func TestParseResourceNameIgnoresNestedKeys(t *testing.T) {
	parsed := parseBicep(`resource vnet 'Microsoft.Network/virtualNetworks@2023-01-01' = {
  properties: {
    subnets: [
      {
        name: 'subnet-1'
        properties: {
          addressPrefix: '10.0.0.0/24'
        }
      }
    ]
  }
  name: 'my-vnet'
  location: 'eastus'
}
`)

	require.Len(t, parsed.resources, 1)
	r := parsed.resources[0]
	assert.Equal(t, "'my-vnet'", r.name, "the resource's own name, not the subnet's")
	assert.Equal(t, "'eastus'", r.location)
}

func TestParseResourceLocationIgnoresNestedKeys(t *testing.T) {
	parsed := parseBicep(`resource site 'Microsoft.Web/sites@2023-01-01' = {
  properties: {
    siteConfig: {
      location: 'nested-should-lose'
    }
  }
  name: 'my-site'
  location: 'westeurope'
}
`)

	require.Len(t, parsed.resources, 1)
	assert.Equal(t, "'westeurope'", parsed.resources[0].location)
}

// `Microsoft.Resources/deployments` embeds a whole template under
// `properties.template`, which has its own `tags` and `dependsOn`. Those belong
// to the inner template, not to the deployment resource.
func TestParseResourceTagsIgnoresNestedTemplate(t *testing.T) {
	parsed := parseBicep(`resource deploy 'Microsoft.Resources/deployments@2022-09-01' = {
  name: 'nested-deploy'
  properties: {
    template: {
      tags: {
        inner: 'yes'
      }
      resources: []
    }
  }
  tags: {
    owner: 'platform'
    env: 'prod'
  }
}
`)

	require.Len(t, parsed.resources, 1)
	assert.Equal(t, map[string]string{"owner": "platform", "env": "prod"}, parsed.resources[0].tags)
}

func TestParseResourceDependsOnIgnoresNestedTemplate(t *testing.T) {
	parsed := parseBicep(`resource deploy 'Microsoft.Resources/deployments@2022-09-01' = {
  name: 'nested-deploy'
  properties: {
    template: {
      dependsOn: [
        innerThing
      ]
    }
  }
  dependsOn: [
    outerThing
    otherThing
  ]
}
`)

	require.Len(t, parsed.resources, 1)
	assert.Equal(t, []string{"outerThing", "otherThing"}, parsed.resources[0].dependsOn)
}

// A resource that genuinely has no top-level `tags`/`dependsOn` must report
// none, rather than borrowing a nested block's.
func TestParseResourceNoTopLevelTagsOrDependsOn(t *testing.T) {
	parsed := parseBicep(`resource deploy 'Microsoft.Resources/deployments@2022-09-01' = {
  name: 'nested-deploy'
  properties: {
    template: {
      tags: {
        inner: 'yes'
      }
      dependsOn: [
        innerThing
      ]
    }
  }
}
`)

	require.Len(t, parsed.resources, 1)
	assert.Nil(t, parsed.resources[0].tags, "a nested tags block is not the resource's own")
	assert.Nil(t, parsed.resources[0].dependsOn, "a nested dependsOn is not the resource's own")
}

// The existing behavior for a plain, correctly-ordered body must be unchanged.
func TestParseResourceTopLevelFieldsStillResolve(t *testing.T) {
	parsed := parseBicep(`resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mysa'
  location: 'eastus'
  tags: {
    env: 'dev'
  }
  dependsOn: [
    rg
  ]
  properties: {
    supportsHttpsTrafficOnly: true
  }
}
`)

	require.Len(t, parsed.resources, 1)
	r := parsed.resources[0]
	assert.Equal(t, "'mysa'", r.name)
	assert.Equal(t, "'eastus'", r.location)
	assert.Equal(t, map[string]string{"env": "dev"}, r.tags)
	assert.Equal(t, []string{"rg"}, r.dependsOn)
}

// A `for`-loop resource's per-iteration object is the body, so depth-1 there is
// relative to that object.
func TestParseLoopResourceFieldsIgnoreNestedKeys(t *testing.T) {
	parsed := parseBicep(`resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = [for n in names: {
  properties: {
    subnets: [
      {
        name: 'inner'
      }
    ]
  }
  name: n
}]
`)

	require.Len(t, parsed.resources, 1)
	assert.True(t, parsed.resources[0].loop.isLoop)
	assert.Equal(t, "n", parsed.resources[0].name)
}

// A module body goes through the same extractor for `scope`.
func TestParseModuleScopeIgnoresNestedKeys(t *testing.T) {
	parsed := parseBicep(`module m 'storage.bicep' = {
  name: 'deploy-storage'
  params: {
    scope: 'inner-should-lose'
  }
  scope: resourceGroup('other-rg')
}
`)

	require.Len(t, parsed.modules, 1)
	assert.Equal(t, "resourceGroup('other-rg')", parsed.modules[0].scope)
}

func TestBodyObjectInner(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"declaration header is skipped", "resource r 'T@v' = {\n  name: 'x'\n}", "\n  name: 'x'\n"},
		{"conditional header is skipped", "resource r 'T@v' = if (a) {\n  name: 'x'\n}", "\n  name: 'x'\n"},
		{"brace inside a string is not the opener", "resource r 'T@{v}' = {\n  name: 'x'\n}", "\n  name: 'x'\n"},
		{"no object yields empty", "param p string", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bodyObjectInner(tc.in))
		})
	}
}
