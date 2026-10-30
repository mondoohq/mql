// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
)

// armFixtureRuntime writes an ARM template into a temp dir and returns a
// runtime backed by a real BicepConnection scanning it, plus the connection.
func armFixtureRuntime(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "bicep", Options: map[string]string{"path": dir}},
		},
	}
	conn, err := connection.NewBicepConnection(0, asset, asset.Connections[0])
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &mapResources{m: map[string]plugin.Resource{}},
	}
}

// firstTemplate materializes the connection's first ARM template.
func firstTemplate(t *testing.T, runtime *plugin.Runtime) *mqlBicepTemplate {
	t.Helper()
	conn := runtime.Connection.(*connection.BicepConnection)
	require.NotEmpty(t, conn.ARMTemplates())
	mqlT, err := newMqlBicepTemplate(runtime, conn.ARMTemplates()[0].Path, conn.ARMTemplate())
	require.NoError(t, err)
	return mqlT
}

func templateResources(t *testing.T, runtime *plugin.Runtime) []*mqlBicepTemplateResource {
	t.Helper()
	list, err := firstTemplate(t, runtime).resources()
	require.NoError(t, err)
	out := make([]*mqlBicepTemplateResource, 0, len(list))
	for _, r := range list {
		out = append(out, r.(*mqlBicepTemplateResource))
	}
	return out
}

const armHeader = `"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",`

// F4: ARM's `condition` is boolean-valued. A literal false means the resource
// is NEVER deployed, but the comma-ok string assertion swallowed it and left
// "", which the schema documents as "unconditional".
func TestARMResourceLiteralBooleanCondition(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"azuredeploy.json": `{
  ` + armHeader + `
  "resources": [
    {
      "condition": false,
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stnever"
    },
    {
      "condition": true,
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stalways"
    },
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stplain"
    }
  ]
}`})

	byName := map[string]*mqlBicepTemplateResource{}
	for _, r := range templateResources(t, runtime) {
		byName[r.Name.Data] = r
	}

	assert.Equal(t, "false", byName["stnever"].Condition.Data,
		"a literal false condition must not be reported as unconditional")
	assert.Equal(t, "true", byName["stalways"].Condition.Data)
	assert.Empty(t, byName["stplain"].Condition.Data, "a genuinely absent condition stays empty")
}

// F8: resources() must return an empty list, not nil, matching the documented
// convention its parameters/variables/outputs siblings already follow.
func TestARMTemplateEmptyResourcesIsEmptyList(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"azuredeploy.json": `{
  ` + armHeader + `
  "resources": []
}`})

	list, err := firstTemplate(t, runtime).resources()
	require.NoError(t, err)
	assert.NotNil(t, list, "an empty resources array must yield an empty list, not nil")
	assert.Empty(t, list)

	// A bicep.template with no ARM template behind it (no Bicep connection to
	// re-fetch from) behaves the same way.
	detached, err := newMqlBicepTemplate(testRuntime(), "detached", nil)
	require.NoError(t, err)
	empty, err := detached.resources()
	require.NoError(t, err)
	assert.NotNil(t, empty, "an absent template must yield an empty list, not nil")
}

// F9: ARM permits an object form of dependsOn, and symbolic-name templates use
// `[reference(...)]` objects. Dropping them silently loses graph edges.
func TestARMResourceNonStringDependsOn(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"azuredeploy.json": `{
  ` + armHeader + `
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2023-01-01",
      "name": "app",
      "dependsOn": [
        "[resourceId('Microsoft.Storage/storageAccounts', 'st1')]",
        { "$ref": "storageAccount" }
      ]
    }
  ]
}`})

	res := templateResources(t, runtime)
	require.Len(t, res, 1)
	deps := res[0].DependsOn.Data
	require.Len(t, deps, 2, "an object dependsOn entry must not be dropped")
	assert.Equal(t, "[resourceId('Microsoft.Storage/storageAccounts', 'st1')]", deps[0])
	assert.Equal(t, `{"$ref":"storageAccount"}`, deps[1],
		"an object entry is rendered to its raw JSON text")
}

// F2: a symbolic-name template's resource id must carry the symbolic name
// rather than a bare positional index.
func TestARMSymbolicNameInResourceID(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"main.json": `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "resources": {
    "primarySa": {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stsym"
    }
  }
}`})

	res := templateResources(t, runtime)
	require.Len(t, res, 1)
	assert.True(t, strings.HasSuffix(res[0].__id, ":primarySa"),
		"the symbolic key is the resource's identity in a languageVersion 2.0 template, got %q", res[0].__id)
}

// F3: a classic ARM resource may carry its own `resources` array of children:
// Microsoft.Web/sites to config/web, Microsoft.Sql/servers to auditingSettings
// and firewallRules, Microsoft.Storage/storageAccounts to blobServices. Only
// top-level resources were materialized, so a policy on
// Microsoft.Web/sites/config matched nothing and passed vacuously, while the
// equivalent query against Bicep source found it.
func TestARMResourceNestedChildren(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"azuredeploy.json": `{
  ` + armHeader + `
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2023-01-01",
      "name": "app",
      "location": "eastus",
      "resources": [
        {
          "type": "config",
          "apiVersion": "2023-01-01",
          "name": "web",
          "properties": {
            "ftpsState": "AllAllowed",
            "minTlsVersion": "1.0"
          },
          "resources": [
            {
              "type": "grandchild",
              "apiVersion": "2023-01-01",
              "name": "deep"
            }
          ]
        },
        {
          "type": "config",
          "apiVersion": "2023-01-01",
          "name": "appsettings"
        }
      ]
    },
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "st1"
    }
  ]
}`})

	top := templateResources(t, runtime)
	require.Len(t, top, 2, "nested children are not top-level resources")

	var site *mqlBicepTemplateResource
	var storage *mqlBicepTemplateResource
	for _, r := range top {
		switch r.Type.Data {
		case "Microsoft.Web/sites":
			site = r
		case "Microsoft.Storage/storageAccounts":
			storage = r
		}
	}
	require.NotNil(t, site)
	require.NotNil(t, storage)

	children, err := site.resources()
	require.NoError(t, err)
	require.Len(t, children, 2, "the nested config children must be materialized")

	web := children[0].(*mqlBicepTemplateResource)
	assert.Equal(t, "config", web.Type.Data)
	assert.Equal(t, "web", web.Name.Data)
	props, ok := web.Properties.Data.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "AllAllowed", props["ftpsState"])
	assert.Equal(t, "1.0", props["minTlsVersion"])

	// Children of children resolve the same way.
	grandchildren, err := web.resources()
	require.NoError(t, err)
	require.Len(t, grandchildren, 1)
	assert.Equal(t, "deep", grandchildren[0].(*mqlBicepTemplateResource).Name.Data)

	// Each child's id is parent-qualified, so same-typed children under
	// different parents never collide.
	assert.NotEqual(t, web.__id, children[1].(*mqlBicepTemplateResource).__id)
	assert.True(t, strings.HasPrefix(web.__id, "bicep.template.resource:"))
	assert.Contains(t, web.__id, site.__id)

	// A resource with no children yields an empty list, not nil.
	none, err := storage.resources()
	require.NoError(t, err)
	assert.NotNil(t, none)
	assert.Empty(t, none)
}

// The tags field must exist on bicep.template.resource so one tagging policy
// covers both Bicep source and compiled ARM JSON.
func TestARMResourceTags(t *testing.T) {
	runtime := armFixtureRuntime(t, map[string]string{"azuredeploy.json": `{
  ` + armHeader + `
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "sttagged",
      "tags": { "env": "prod", "owner": "platform" }
    },
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "stuntagged"
    }
  ]
}`})

	byName := map[string]*mqlBicepTemplateResource{}
	for _, r := range templateResources(t, runtime) {
		byName[r.Name.Data] = r
	}

	assert.Equal(t, map[string]any{"env": "prod", "owner": "platform"}, byName["sttagged"].Tags.Data)
	assert.Empty(t, byName["stuntagged"].Tags.Data, "an untagged resource reports no tags, not null")
}

// F1: every discovered ARM template must be reachable, each carrying the
// resources of its own file.
func TestBicepTemplatesAccessor(t *testing.T) {
	storage := `{
  ` + armHeader + `
  "resources": [
    { "type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01", "name": "st1" }
  ]
}`
	network := `{
  ` + armHeader + `
  "resources": [
    { "type": "Microsoft.Network/virtualNetworks", "apiVersion": "2023-05-01", "name": "vnet1" }
  ]
}`
	runtime := armFixtureRuntime(t, map[string]string{
		"azuredeploy.json":     storage,
		"modules/network.json": network,
	})

	root, err := CreateResource(runtime, "bicep", map[string]*llx.RawData{})
	require.NoError(t, err)
	bicepRes := root.(*mqlBicep)

	all, err := bicepRes.templates()
	require.NoError(t, err)
	require.Len(t, all, 2, "both templates in the tree must be surfaced")

	// Each template carries only its own resources, so the two must not share
	// a cache id.
	first := all[0].(*mqlBicepTemplate)
	second := all[1].(*mqlBicepTemplate)
	assert.NotEqual(t, first.__id, second.__id)

	firstRes, err := first.resources()
	require.NoError(t, err)
	require.Len(t, firstRes, 1)
	assert.Equal(t, "st1", firstRes[0].(*mqlBicepTemplateResource).Name.Data)

	secondRes, err := second.resources()
	require.NoError(t, err)
	require.Len(t, secondRes, 1)
	assert.Equal(t, "vnet1", secondRes[0].(*mqlBicepTemplateResource).Name.Data)

	// The singular accessor keeps working and points at the first template.
	single, err := bicepRes.template()
	require.NoError(t, err)
	require.NotNil(t, single)
	assert.Equal(t, first.__id, single.__id)
}
