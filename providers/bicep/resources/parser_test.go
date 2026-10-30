// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBicepFullFile(t *testing.T) {
	input := `targetScope = 'subscription'

@description('The Azure region')
param location string = 'eastus'

var rgName = 'myResourceGroup'

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: rgName
  location: location
}

module network './modules/network.bicep' = {
  name: 'networkDeploy'
  scope: rg
  params: {
    location: location
  }
}

output rgId string = rg.id
`

	result := parseBicep(input)

	assert.Equal(t, "subscription", result.targetScope)
	assert.Len(t, result.parameters, 1)
	assert.Len(t, result.variables, 1)
	assert.Len(t, result.resources, 1)
	assert.Len(t, result.modules, 1)
	assert.Len(t, result.outputs, 1)
}

func TestParseBicepNoTargetScope(t *testing.T) {
	input := `param name string`
	result := parseBicep(input)
	assert.Equal(t, "", result.targetScope)
	assert.Len(t, result.parameters, 1)
}

func TestParseParameterDefaultValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantType string
		wantDef  string
	}{
		{
			name:     "empty string default",
			input:    "param teradiciRegKey string = ''",
			wantName: "teradiciRegKey",
			wantType: "string",
			wantDef:  "",
		},
		{
			name:     "non-empty string default",
			input:    "param location string = 'eastus'",
			wantName: "location",
			wantType: "string",
			wantDef:  "eastus",
		},
		{
			name:     "int default not quoted",
			input:    "param count int = 3",
			wantName: "count",
			wantType: "int",
			wantDef:  "3",
		},
		{
			name:     "bool default not quoted",
			input:    "param enabled bool = true",
			wantName: "enabled",
			wantType: "bool",
			wantDef:  "true",
		},
		{
			name:     "no default value",
			input:    "param name string",
			wantName: "name",
			wantType: "string",
			wantDef:  "",
		},
		{
			name:     "string with content",
			input:    "param sku string = 'Standard_LRS'",
			wantName: "sku",
			wantType: "string",
			wantDef:  "Standard_LRS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseParameter(tt.input, nil)
			require.True(t, ok, "well-formed declaration must parse")
			assert.Equal(t, tt.wantName, p.name)
			assert.Equal(t, tt.wantType, p.typ)
			assert.Equal(t, tt.wantDef, p.defaultValue)
		})
	}
}

func TestParseParameterMultilineAndCommentDefaults(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantDef string
	}{
		{
			name: "multi-line array default preserved",
			input: `param locations array = [
  'eastus'
  'westus'
]`,
			wantDef: "[ 'eastus' 'westus' ]",
		},
		{
			name: "multi-line object default preserved",
			input: `param config object = {
  environment: 'prod'
  count: 3
}`,
			wantDef: "{ environment: 'prod' count: 3 }",
		},
		{
			name:    "trailing line comment stripped",
			input:   "param sku string = 'Standard_LRS' // default sku",
			wantDef: "Standard_LRS",
		},
		{
			name:    "double-slash inside string is not a comment",
			input:   "param endpoint string = 'https://example.com'",
			wantDef: "https://example.com",
		},
		{
			name:    "internal string whitespace preserved",
			input:   "param greeting string = 'hello   world'",
			wantDef: "hello   world",
		},
		{
			name: "comment on a continuation line stripped",
			input: `param locations array = [
  'eastus' // primary
  'westus'
]`,
			wantDef: "[ 'eastus' 'westus' ]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBicep(tt.input)
			require.Len(t, result.parameters, 1)
			assert.Equal(t, tt.wantDef, result.parameters[0].defaultValue)
		})
	}
}

func TestParseParameterDecorators(t *testing.T) {
	input := `@description('Teradici Registration Key')
@secure()
param teradiciRegKey string = ''`

	result := parseBicep(input)
	require.Len(t, result.parameters, 1)
	p := result.parameters[0]

	assert.Equal(t, "teradiciRegKey", p.name)
	assert.Equal(t, "string", p.typ)
	assert.Equal(t, "", p.defaultValue)
	assert.Equal(t, "Teradici Registration Key", p.description)
	assert.True(t, p.secure)
	assert.Equal(t, []string{
		"@description('Teradici Registration Key')",
		"@secure()",
	}, p.decorators)
}

func TestParseParameterAllowed(t *testing.T) {
	t.Run("multiline newline-separated", func(t *testing.T) {
		input := `@allowed([
  'Standard_LRS'
  'Standard_GRS'
])
param storageSku string`

		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]

		assert.Equal(t, "storageSku", p.name)
		assert.Equal(t, []string{"Standard_LRS", "Standard_GRS"}, p.allowed)
	})

	t.Run("single-line comma-separated", func(t *testing.T) {
		input := `@allowed([ 'win10', 'ws2019' ])
param osType string = 'win10'`

		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]

		assert.Equal(t, "osType", p.name)
		assert.Equal(t, []string{"win10", "ws2019"}, p.allowed)
	})

	t.Run("mixed comma and newline", func(t *testing.T) {
		input := `@allowed([
  'a', 'b'
  'c'
])
param x string`

		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		assert.Equal(t, []string{"a", "b", "c"}, result.parameters[0].allowed)
	})
}

func TestParseAllowedValues(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "newline-separated",
			raw:  "'a'\n'b'\n'c'",
			want: []string{"a", "b", "c"},
		},
		{
			name: "comma-separated on one line",
			raw:  " 'win10', 'ws2019' ",
			want: []string{"win10", "ws2019"},
		},
		{
			name: "empty input",
			raw:  "",
			want: nil,
		},
		{
			name: "whitespace only",
			raw:  "   \n   ",
			want: nil,
		},
		{
			name: "empty string value",
			raw:  "''",
			want: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAllowedValues(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseVariable(t *testing.T) {
	t.Run("simple expression", func(t *testing.T) {
		v := parseVariable("var rgName = 'myRG'", nil)
		assert.Equal(t, "rgName", v.name)
		assert.Equal(t, "'myRG'", v.expression)
	})

	t.Run("complex expression", func(t *testing.T) {
		v := parseVariable("var subnetRef = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName)", nil)
		assert.Equal(t, "subnetRef", v.name)
		assert.Equal(t, "resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, subnetName)", v.expression)
	})

	t.Run("with description decorator", func(t *testing.T) {
		input := `@description('Resource group name')
var rgName = 'myRG'`
		result := parseBicep(input)
		require.Len(t, result.variables, 1)
		assert.Equal(t, "rgName", result.variables[0].name)
		assert.Equal(t, "Resource group name", result.variables[0].description)
	})
}

func TestParseResourceDecl(t *testing.T) {
	t.Run("basic resource", func(t *testing.T) {
		input := `resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
}`
		lines := splitLines(input)
		res, consumed := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.Equal(t, "storageAccount", res.symbolicName)
		assert.Equal(t, "Microsoft.Storage/storageAccounts", res.typ)
		assert.Equal(t, "2023-01-01", res.apiVersion)
		assert.Equal(t, "storageName", res.name)
		assert.Equal(t, "location", res.location)
		assert.False(t, res.existing)
		assert.Equal(t, len(lines), consumed)
	})

	t.Run("existing resource reference", func(t *testing.T) {
		input := `resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' existing = {
  name: 'myVnet'
}`
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.True(t, res.existing)
		assert.Equal(t, "vnet", res.symbolicName)
	})

	t.Run("resource with condition", func(t *testing.T) {
		input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = if (deployStorage) {
  name: storageName
  location: location
}`
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.Equal(t, "deployStorage", res.condition)
	})

	t.Run("resource with parent", func(t *testing.T) {
		input := `resource subnet 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' = {
  name: 'mySubnet'
  parent: vnet
  properties: {
    addressPrefix: '10.0.0.0/24'
  }
}`
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.Equal(t, "vnet", res.parent)
	})

	t.Run("resource with dependsOn", func(t *testing.T) {
		input := `resource app 'Microsoft.Web/sites@2022-09-01' = {
  name: 'myApp'
  location: location
  dependsOn: [
    storageAccount
    appPlan
  ]
}`
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.Equal(t, []string{"storageAccount", "appPlan"}, res.dependsOn)
	})

	t.Run("resource with decorators", func(t *testing.T) {
		input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'test'
}`
		decorators := []string{"@description('My storage account')"}
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, decorators)
		require.NotNil(t, res)
		assert.Equal(t, decorators, res.decorators)
	})

	t.Run("type without api version", func(t *testing.T) {
		input := `resource rg 'Microsoft.Resources/resourceGroups' = {
  name: 'myRG'
}`
		lines := splitLines(input)
		res, _ := parseResourceDecl(lines, 0, nil)
		require.NotNil(t, res)
		assert.Equal(t, "Microsoft.Resources/resourceGroups", res.typ)
		assert.Equal(t, "", res.apiVersion)
	})
}

func TestResourceBodyInner(t *testing.T) {
	t.Run("exposes top-level fields beyond properties", func(t *testing.T) {
		body := `resource webApp 'Microsoft.Web/sites@2024-04-01' = {
  name: 'example-webapp'
  identity: {
    type: 'SystemAssigned'
  }
  kind: 'app'
  properties: {
    httpsOnly: true
  }
}`
		obj := parseBicepObject(resourceBodyInner(body))
		identity, ok := obj["identity"].(map[string]any)
		require.True(t, ok, "identity should be a top-level field")
		assert.Equal(t, "SystemAssigned", identity["type"])
		assert.Equal(t, "app", obj["kind"])
		props, ok := obj["properties"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, true, props["httpsOnly"])
	})

	t.Run("skips nested resource declarations", func(t *testing.T) {
		body := `resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: 'pg'
  properties: {
    version: '16'
  }
  resource cfg 'configurations@2024-08-01' = {
    name: 'require_secure_transport'
    properties: {
      value: 'ON'
    }
  }
}`
		obj := parseBicepObject(resourceBodyInner(body))
		assert.Equal(t, "pg", obj["name"])
		_, hasProps := obj["properties"].(map[string]any)
		assert.True(t, hasProps)
		// the nested `resource cfg ...` block carries no top-level colon and
		// must not leak in as a key; reach nested resources via `resources`.
		for k := range obj {
			assert.NotContains(t, k, "resource cfg")
		}
	})

	t.Run("microsoft graph resource (no properties wrapper)", func(t *testing.T) {
		body := `resource ca 'Microsoft.Graph/conditionalAccessPolicies@v1.0' = {
  displayName: 'Block legacy'
  state: 'enabled'
  grantControls: {
    builtInControls: ['block']
  }
}`
		obj := parseBicepObject(resourceBodyInner(body))
		assert.Equal(t, "enabled", obj["state"])
		assert.Equal(t, "Block legacy", obj["displayName"])
		gc, ok := obj["grantControls"].(map[string]any)
		require.True(t, ok)
		controls, ok := gc["builtInControls"].([]any)
		require.True(t, ok)
		assert.Equal(t, []any{"block"}, controls)
	})

	t.Run("no braces returns empty", func(t *testing.T) {
		assert.Equal(t, "", resourceBodyInner("resource x 'T' = "))
		assert.Empty(t, parseBicepObject(resourceBodyInner("")))
	})
}

func TestParseModuleDecl(t *testing.T) {
	t.Run("local module", func(t *testing.T) {
		input := `module network './modules/network.bicep' = {
  name: 'networkDeploy'
  scope: rg
  params: {
    location: location
    vnetName: 'myVnet'
  }
}`
		lines := splitLines(input)
		mod, consumed := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.Equal(t, "network", mod.name)
		assert.Equal(t, "./modules/network.bicep", mod.source)
		assert.Equal(t, "rg", mod.scope)
		assert.False(t, mod.isRegistry)
		assert.False(t, mod.isTemplateSpec)
		assert.Equal(t, len(lines), consumed)
	})

	t.Run("registry module br:", func(t *testing.T) {
		input := `module registry 'br:myregistry.azurecr.io/bicep/modules/storage:v1' = {
  name: 'registryDeploy'
}`
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.True(t, mod.isRegistry)
		assert.False(t, mod.isTemplateSpec)
	})

	t.Run("registry module br/", func(t *testing.T) {
		input := `module registry 'br/public:avm/res/storage/storage-account:0.9.0' = {
  name: 'registryDeploy'
}`
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.True(t, mod.isRegistry)
	})

	t.Run("template spec module ts:", func(t *testing.T) {
		input := `module ts 'ts:mySubscription/myRG/mySpec:v1' = {
  name: 'tsDeploy'
}`
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.True(t, mod.isTemplateSpec)
		assert.False(t, mod.isRegistry)
	})

	t.Run("template spec module ts/", func(t *testing.T) {
		input := `module ts 'ts/myAlias:mySpec:v1' = {
  name: 'tsDeploy'
}`
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.True(t, mod.isTemplateSpec)
	})

	t.Run("module with condition", func(t *testing.T) {
		input := `module optionalNet './modules/network.bicep' = if (deployNet) {
  name: 'netDeploy'
}`
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, nil)
		require.NotNil(t, mod)
		assert.Equal(t, "deployNet", mod.condition)
	})

	t.Run("module with decorators", func(t *testing.T) {
		input := `module network './modules/network.bicep' = {
  name: 'networkDeploy'
}`
		decorators := []string{"@description('Deploy the network module')"}
		lines := splitLines(input)
		mod, _ := parseModuleDecl(lines, 0, decorators)
		require.NotNil(t, mod)
		assert.Equal(t, "Deploy the network module", mod.description)
		assert.Equal(t, decorators, mod.decorators)
	})

	t.Run("non-matching line returns nil", func(t *testing.T) {
		lines := splitLines("var x = 1")
		mod, consumed := parseModuleDecl(lines, 0, nil)
		assert.Nil(t, mod)
		assert.Equal(t, 1, consumed)
	})
}

func TestParseOutput(t *testing.T) {
	t.Run("simple output", func(t *testing.T) {
		o, ok := parseOutput("output rgId string = rg.id", nil)
		require.True(t, ok)
		assert.Equal(t, "rgId", o.name)
		assert.Equal(t, "string", o.typ)
		assert.Equal(t, "rg.id", o.expression)
	})

	t.Run("output with description", func(t *testing.T) {
		input := `@description('The resource group ID')
output rgId string = rg.id`
		result := parseBicep(input)
		require.Len(t, result.outputs, 1)
		assert.Equal(t, "The resource group ID", result.outputs[0].description)
	})

	t.Run("int output", func(t *testing.T) {
		o, ok := parseOutput("output count int = length(items)", nil)
		require.True(t, ok)
		assert.Equal(t, "count", o.name)
		assert.Equal(t, "int", o.typ)
		assert.Equal(t, "length(items)", o.expression)
	})
}

func TestExtractBlock(t *testing.T) {
	t.Run("simple block", func(t *testing.T) {
		lines := splitLines("resource sa 'Type@ver' = {\n  name: 'test'\n}")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "name: 'test'")
		assert.Equal(t, 3, consumed)
	})

	t.Run("nested blocks", func(t *testing.T) {
		lines := splitLines("{\n  sku: {\n    name: 'Standard'\n  }\n}")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "sku: {")
		assert.Contains(t, block, "name: 'Standard'")
		assert.Equal(t, 5, consumed)
	})

	t.Run("no braces returns empty", func(t *testing.T) {
		lines := splitLines("no braces here")
		block, consumed := extractBlock(lines, 0)
		assert.Equal(t, "", block)
		assert.Equal(t, 1, consumed)
	})

	t.Run("unclosed block returns all remaining", func(t *testing.T) {
		lines := splitLines("{\n  name: 'test'")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "name: 'test'")
		assert.Equal(t, 2, consumed)
	})

	t.Run("brace inside string literal does not close the block early", func(t *testing.T) {
		// The `}` inside the string must not be counted as the block's
		// closing brace, otherwise the block boundary shifts to line 2 and
		// the `sku` field below it is lost.
		lines := splitLines("resource sa 'Type@ver' = {\n  name: 'pre}post'\n  sku: 'Standard'\n}")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "sku: 'Standard'")
		assert.Equal(t, 4, consumed)
	})

	t.Run("brace inside line comment does not affect depth", func(t *testing.T) {
		// The lone `}` in the comment would, with naive counting, close the
		// block at line 2 and drop the `name` field that follows.
		lines := splitLines("resource sa 'Type@ver' = {\n  // closing brace } in a comment\n  name: 'test'\n}")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "name: 'test'")
		assert.Equal(t, 4, consumed)
	})

	t.Run("brace inside interpolation does not open a phantom block", func(t *testing.T) {
		// `${...}` interpolation contains a `}`; with naive counting the
		// opening `{` of `${` would push depth to 2 and the real closing
		// brace would drop it to 1, leaving the block unterminated.
		lines := splitLines("resource sa 'Type@ver' = {\n  name: 'sa${env}001'\n}")
		block, consumed := extractBlock(lines, 0)
		assert.Contains(t, block, "name: 'sa${env}001'")
		assert.Equal(t, 3, consumed)
	})
}

func TestExtractFieldValue(t *testing.T) {
	body := `{
  name: storageName
  location: location
  kind: 'StorageV2'
}`

	assert.Equal(t, "storageName", extractFieldValue(body, "name"))
	assert.Equal(t, "location", extractFieldValue(body, "location"))
	assert.Equal(t, "", extractFieldValue(body, "parent"))
}

func TestExtractFieldValueUncachedField(t *testing.T) {
	body := "  custom: myValue"
	assert.Equal(t, "myValue", extractFieldValue(body, "custom"))
}

func TestExtractCondition(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "simple condition",
			line: "resource sa 'Type@ver' = if (deployStorage) {",
			want: "deployStorage",
		},
		{
			name: "nested parens",
			line: "resource sa 'Type@ver' = if (contains(env, 'prod')) {",
			want: "contains(env, 'prod')",
		},
		{
			name: "no condition",
			line: "resource sa 'Type@ver' = {",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractCondition(tt.line))
		})
	}
}

func TestExtractFieldBlock(t *testing.T) {
	t.Run("params block", func(t *testing.T) {
		body := `{
  name: 'deploy'
  params: {
    location: location
    sku: 'Standard'
  }
}`
		result := extractFieldBlock(body, "params")
		assert.Contains(t, result, "location: location")
		assert.Contains(t, result, "sku: 'Standard'")
	})

	t.Run("field not found", func(t *testing.T) {
		body := `{
  name: 'deploy'
}`
		result := extractFieldBlock(body, "params")
		assert.Equal(t, "", result)
	})

	t.Run("nested blocks within field", func(t *testing.T) {
		body := `{
  params: {
    config: {
      nested: true
    }
  }
}`
		result := extractFieldBlock(body, "params")
		assert.Contains(t, result, "config: {")
		assert.Contains(t, result, "nested: true")
	})
}

func TestExtractDependsOn(t *testing.T) {
	t.Run("multiple dependencies", func(t *testing.T) {
		body := `{
  name: 'test'
  dependsOn: [
    storageAccount
    appPlan
  ]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"storageAccount", "appPlan"}, deps)
	})

	t.Run("single dependency", func(t *testing.T) {
		body := `{
  dependsOn: [
    vnet
  ]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"vnet"}, deps)
	})

	t.Run("no dependsOn", func(t *testing.T) {
		body := `{
  name: 'test'
}`
		deps := extractDependsOn(body)
		assert.Nil(t, deps)
	})

	t.Run("inline dependencies", func(t *testing.T) {
		body := `{
  dependsOn: [storageAccount]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"storageAccount"}, deps)
	})
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// parseVariable used to read only the first source line, so a var
// initializer that opened an object or array literal had its tail
// truncated at the first newline. parseVariableDecl now reassembles
// the continuation lines before regex matching.
func TestParseVariable_MultiLine(t *testing.T) {
	t.Run("object literal across lines", func(t *testing.T) {
		input := `var settings = {
  name: 'myService'
  enabled: true
}`
		result := parseBicep(input)
		require.Len(t, result.variables, 1)
		v := result.variables[0]
		assert.Equal(t, "settings", v.name)
		assert.Contains(t, v.expression, "name: 'myService'")
		assert.Contains(t, v.expression, "enabled: true")
	})

	t.Run("array literal across lines", func(t *testing.T) {
		input := `var regions = [
  'eastus'
  'westus'
]`
		result := parseBicep(input)
		require.Len(t, result.variables, 1)
		v := result.variables[0]
		assert.Equal(t, "regions", v.name)
		assert.Contains(t, v.expression, "'eastus'")
		assert.Contains(t, v.expression, "'westus'")
	})

	t.Run("single-line still works", func(t *testing.T) {
		input := `var rgName = 'myRG'`
		result := parseBicep(input)
		require.Len(t, result.variables, 1)
		assert.Equal(t, "rgName", result.variables[0].name)
		assert.Equal(t, "'myRG'", result.variables[0].expression)
	})
}

// extractFieldBlock used to require `{` on the same line as `name:`,
// which doesn't match the Cuddle-Yaml-style layout people sometimes
// reach for in Bicep. The opening brace is now picked up from the
// next non-blank line.
func TestExtractFieldBlock_NextLineBrace(t *testing.T) {
	body := `{
  params:
  {
    location: 'eastus'
    enabled: true
  }
}`
	result := extractFieldBlock(body, "params")
	assert.Contains(t, result, "location: 'eastus'")
	assert.Contains(t, result, "enabled: true")
}

// extractCondition used to receive only the resource's first source
// line, dropping conditions that spanned multiple lines. joinDeclHeader
// now reassembles the header up to the body's opening `{`.
func TestExtractCondition_MultiLine(t *testing.T) {
	input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = if (
  deployStorage &&
  contains(env, 'prod')
) {
  name: 'mystorage'
}`
	result := parseBicep(input)
	require.Len(t, result.resources, 1)
	cond := result.resources[0].condition
	assert.Contains(t, cond, "deployStorage")
	assert.Contains(t, cond, "contains(env, 'prod')")
}

// extractDependsOn used a `\[([^\]]*)\]` regex that terminated on the
// first inner `]`, so entries containing indexed expressions or any
// inline array dropped half the list. The depth-tracking scanner walks
// past nested brackets.
func TestExtractDependsOn_NestedBrackets(t *testing.T) {
	t.Run("indexed dependency expression", func(t *testing.T) {
		body := `{
  dependsOn: [
    storageAccounts[0]
    appPlan
  ]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"storageAccounts[0]", "appPlan"}, deps)
	})

	t.Run("unclosed bracket returns nil", func(t *testing.T) {
		body := `{
  dependsOn: [
    storageAccount`
		deps := extractDependsOn(body)
		assert.Nil(t, deps)
	})
}

// parseBicepObject replaces the previous `{raw: <whole body>}` blob
// for resource.properties and module.params; the dict now mirrors the
// source structure so audits can query individual keys.
func TestParseBicepObject(t *testing.T) {
	t.Run("scalars and nesting", func(t *testing.T) {
		body := `
  accessTier: 'Hot'
  supportsHttpsTrafficOnly: true
  minimumTlsVersion: 'TLS1_2'
  networkAcls: {
    defaultAction: 'Deny'
    bypass: 'AzureServices'
  }
  allowedIps: [
    '10.0.0.0/8'
    '192.168.0.0/16'
  ]
`
		obj := parseBicepObject(body)
		assert.Equal(t, "Hot", obj["accessTier"])
		assert.Equal(t, true, obj["supportsHttpsTrafficOnly"])
		assert.Equal(t, "TLS1_2", obj["minimumTlsVersion"])

		nested, ok := obj["networkAcls"].(map[string]any)
		require.True(t, ok, "networkAcls should be a nested map")
		assert.Equal(t, "Deny", nested["defaultAction"])
		assert.Equal(t, "AzureServices", nested["bypass"])

		ips, ok := obj["allowedIps"].([]any)
		require.True(t, ok, "allowedIps should be an array")
		assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"}, ips)
	})

	t.Run("line comments are skipped", func(t *testing.T) {
		body := `
  // inline note
  enabled: true
  // another comment
  count: 3
`
		obj := parseBicepObject(body)
		assert.Equal(t, true, obj["enabled"])
		assert.Equal(t, float64(3), obj["count"])
		_, present := obj["inline"]
		assert.False(t, present)
	})

	t.Run("expressions and function calls stay raw", func(t *testing.T) {
		body := `
  name: resourceId('Microsoft.Storage/storageAccounts', sa.name)
  location: resourceGroup().location
`
		obj := parseBicepObject(body)
		assert.Equal(t, "resourceId('Microsoft.Storage/storageAccounts', sa.name)", obj["name"])
		assert.Equal(t, "resourceGroup().location", obj["location"])
	})

	t.Run("strings containing colons and braces are preserved", func(t *testing.T) {
		body := `
  url: 'https://example.com/path:port'
  json: '{"key": "value"}'
`
		obj := parseBicepObject(body)
		assert.Equal(t, "https://example.com/path:port", obj["url"])
		assert.Equal(t, `{"key": "value"}`, obj["json"])
	})

	t.Run("escaped quotes inside string literals", func(t *testing.T) {
		// `'it\\'s here'` — the escaped `'` shouldn't terminate the
		// string and split the entry early.
		body := `
  message: 'it\'s here'
  other: 'plain'
`
		obj := parseBicepObject(body)
		assert.Equal(t, `it\'s here`, obj["message"])
		assert.Equal(t, "plain", obj["other"])
	})

	// Regression test for #9081: keys that must be quoted in Bicep source
	// (dotted keys, e.g. API Management `customProperties`) landed in the map
	// with their quotes attached, so an index lookup written without quotes
	// missed and returned null. The quotes must be stripped from the key.
	t.Run("quoted dotted keys are unquoted", func(t *testing.T) {
		body := `
  customProperties: {
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'True'
    publisherName: 'Contoso'
  }
`
		obj := parseBicepObject(body)
		cp, ok := obj["customProperties"].(map[string]any)
		require.True(t, ok, "customProperties should be a nested map")
		assert.Equal(t, "True", cp["Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10"])
		assert.Equal(t, "Contoso", cp["publisherName"])
		_, quotedPresent := cp["'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10'"]
		assert.False(t, quotedPresent, "the quoted form must not leak into the map key")
	})

	t.Run("double-quoted keys are unquoted", func(t *testing.T) {
		body := `
  "a.b.c": 'x'
`
		obj := parseBicepObject(body)
		assert.Equal(t, "x", obj["a.b.c"])
	})
}

// A brace inside a string literal used to fool the naive
// `parenBracketDepth + braceDepth` counter into thinking the var's
// block had closed, so the reassembled expression dropped trailing
// lines. The string-aware scanner ignores it.
func TestParseVariable_BraceInsideStringLiteral(t *testing.T) {
	input := `var settings = {
  message: 'closing brace } not real'
  enabled: true
}`
	result := parseBicep(input)
	require.Len(t, result.variables, 1)
	v := result.variables[0]
	assert.Equal(t, "settings", v.name)
	assert.Contains(t, v.expression, "message: 'closing brace } not real'")
	assert.Contains(t, v.expression, "enabled: true")
}

// Same idea on the resource side: a `{` inside the `if (...)` clause's
// string argument shouldn't be mistaken for the body opener and
// truncate the condition prematurely.
func TestExtractCondition_BraceInsideStringLiteral(t *testing.T) {
	input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = if (contains(env, 'prod{1}')) {
  name: 'mystorage'
}`
	result := parseBicep(input)
	require.Len(t, result.resources, 1)
	assert.Equal(t, "contains(env, 'prod{1}')", result.resources[0].condition)
}

// Triple-quoted strings (`”'…”'`) are Bicep's multi-line string
// syntax. The body can contain literal `{`/`[`/`}`/`]` that must not
// touch the depth counter, so the scanner has to recognize the
// opener as a single token rather than three single-quote flips.
func TestParseBicep_TripleQuotedMultilineString(t *testing.T) {
	t.Run("brackets inside triple-quoted var body don't break depth", func(t *testing.T) {
		input := `var script = '''
echo "{ not a real brace }"
exit [0]
'''

resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'aftertripled'
  location: 'eastus'
}`
		result := parseBicep(input)
		require.Len(t, result.variables, 1)
		assert.Equal(t, "script", result.variables[0].name)
		// The trailing resource still has to be picked up — if the
		// `'''` block's `{` leaked into the depth counter the rest of
		// the file would have been swallowed. `name` keeps the
		// quotes the source had — extractFieldValue returns the raw
		// expression verbatim.
		require.Len(t, result.resources, 1)
		assert.Equal(t, "sa", result.resources[0].symbolicName)
		assert.Equal(t, "'aftertripled'", result.resources[0].name)
	})

	t.Run("triple-quoted value in properties block parses cleanly", func(t *testing.T) {
		body := `
  script: '''
hello { world }
'''
  enabled: true
`
		obj := parseBicepObject(body)
		// We don't unquote `'''` strings (the surrounding quotes are
		// part of the value form), but the scanner has to walk past
		// them without splitting the entry — `enabled` must survive.
		assert.Equal(t, true, obj["enabled"])
		_, present := obj["script"]
		assert.True(t, present, "triple-quoted entry should still be captured")
	})
}

// `extractDependsOn` previously walked raw bytes, so a `]` inside an
// indexed expression or a string literal would drop the rest of the
// list. Sharing the scanState lexer fixes both.
func TestExtractDependsOn_BracketInsideStringAndIndex(t *testing.T) {
	t.Run("indexed expression entry", func(t *testing.T) {
		body := `{
  dependsOn: [
    storageAccounts['blobServices']
    appPlan
  ]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"storageAccounts['blobServices']", "appPlan"}, deps)
	})

	t.Run("string with closing bracket", func(t *testing.T) {
		body := `{
  dependsOn: [ 'literal]' , other ]
}`
		deps := extractDependsOn(body)
		assert.Equal(t, []string{"'literal]'", "other"}, deps)
	})
}

func TestParseParameterBounds(t *testing.T) {
	t.Run("string length bounds", func(t *testing.T) {
		input := `@minLength(8)
@maxLength(64)
param adminPassword string`
		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]
		assert.Equal(t, "adminPassword", p.name)
		require.NotNil(t, p.minLength)
		assert.Equal(t, int64(8), *p.minLength)
		require.NotNil(t, p.maxLength)
		assert.Equal(t, int64(64), *p.maxLength)
		assert.Nil(t, p.minValue)
		assert.Nil(t, p.maxValue)
	})

	t.Run("int value bounds", func(t *testing.T) {
		input := `@minValue(1)
@maxValue(1000)
param replicaCount int`
		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]
		require.NotNil(t, p.minValue)
		assert.Equal(t, int64(1), *p.minValue)
		require.NotNil(t, p.maxValue)
		assert.Equal(t, int64(1000), *p.maxValue)
		assert.Nil(t, p.minLength)
		assert.Nil(t, p.maxLength)
	})

	t.Run("no bounds decorators", func(t *testing.T) {
		input := `param simple string`
		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]
		assert.Nil(t, p.minLength)
		assert.Nil(t, p.maxLength)
		assert.Nil(t, p.minValue)
		assert.Nil(t, p.maxValue)
	})

	t.Run("explicit zero is distinct from absent", func(t *testing.T) {
		input := `@minValue(0)
@maxValue(0)
param zeroBounds int`
		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		p := result.parameters[0]
		require.NotNil(t, p.minValue)
		assert.Equal(t, int64(0), *p.minValue)
		require.NotNil(t, p.maxValue)
		assert.Equal(t, int64(0), *p.maxValue)
	})

	t.Run("malformed argument is ignored", func(t *testing.T) {
		input := `@minLength(abc)
param thing string`
		result := parseBicep(input)
		require.Len(t, result.parameters, 1)
		assert.Nil(t, result.parameters[0].minLength)
	})
}

func TestParseResourceTags(t *testing.T) {
	t.Run("literal string tags", func(t *testing.T) {
		input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorage'
  location: 'eastus'
  tags: {
    env: 'prod'
    owner: 'platform-team'
    'cost-center': '1234'
  }
}`
		result := parseBicep(input)
		require.Len(t, result.resources, 1)
		assert.Equal(t, map[string]string{
			"env":         "prod",
			"owner":       "platform-team",
			"cost-center": "1234",
		}, result.resources[0].tags)
	})

	t.Run("expression-valued tags are skipped", func(t *testing.T) {
		input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorage'
  tags: {
    env: parameters('env')
    owner: 'platform-team'
  }
}`
		result := parseBicep(input)
		require.Len(t, result.resources, 1)
		// Only the literal entry is captured; the expression-valued one is
		// dropped (audits can still reach it through `properties`).
		assert.Equal(t, map[string]string{"owner": "platform-team"}, result.resources[0].tags)
	})

	t.Run("no tags block", func(t *testing.T) {
		input := `resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorage'
}`
		result := parseBicep(input)
		require.Len(t, result.resources, 1)
		assert.Nil(t, result.resources[0].tags)
	})
}

func TestParseBicepParam(t *testing.T) {
	t.Run("using target plus literal and expression params", func(t *testing.T) {
		input := `using './main.bicep'

param storageSku = 'Standard_LRS'
param location = resourceGroup().location
param adminPassword = readEnvironmentVariable('ADMIN_PW')
`
		using, params := parseBicepParam(input)
		assert.Equal(t, "./main.bicep", using)
		assert.Equal(t, map[string]string{
			// Literal stays quoted; expressions stay bare. The raw RHS text is
			// preserved verbatim so audits can tell a literal from an expression.
			"storageSku":    "'Standard_LRS'",
			"location":      "resourceGroup().location",
			"adminPassword": "readEnvironmentVariable('ADMIN_PW')",
		}, params)
	})

	t.Run("using none", func(t *testing.T) {
		input := `using 'none'
param foo = 'bar'
`
		using, params := parseBicepParam(input)
		assert.Equal(t, "none", using)
		assert.Equal(t, map[string]string{"foo": "'bar'"}, params)
	})

	t.Run("registry using ref", func(t *testing.T) {
		input := `using 'br:example.azurecr.io/bicep/modules/storage:v1'
param env = 'prod'
`
		using, _ := parseBicepParam(input)
		assert.Equal(t, "br:example.azurecr.io/bicep/modules/storage:v1", using)
	})

	t.Run("no using statement", func(t *testing.T) {
		input := `param foo = 'bar'`
		using, params := parseBicepParam(input)
		assert.Equal(t, "", using)
		assert.Equal(t, map[string]string{"foo": "'bar'"}, params)
	})

	t.Run("multi-line object value", func(t *testing.T) {
		input := `using './main.bicep'
param config = {
  name: 'example'
  tier: 'standard'
}
`
		_, params := parseBicepParam(input)
		assert.Equal(t, "{ name: 'example' tier: 'standard' }", params["config"])
	})
}

func TestParseBicepForLoops(t *testing.T) {
	// The committed fixture is the single source of truth for the loop
	// scenarios asserted below — read it rather than duplicating the Bicep
	// inline, so the fixture and the test can't drift apart.
	data, err := os.ReadFile("testdata/loops.bicep")
	require.NoError(t, err)

	result := parseBicep(string(data))

	// --- variables ---
	vars := map[string]parsedVariable{}
	for _, v := range result.variables {
		vars[v.name] = v
	}
	require.Contains(t, vars, "itemNames")
	require.Contains(t, vars, "storageNames")

	t.Run("looped variable with range", func(t *testing.T) {
		v := vars["itemNames"]
		assert.True(t, v.loop.isLoop)
		assert.Equal(t, "i", v.loop.iterator)
		assert.Equal(t, "", v.loop.indexVar)
		assert.Equal(t, "range(0, 3)", v.loop.expression)
		assert.Equal(t, "'item-${i}'", v.expression)
	})

	t.Run("non-looped variable", func(t *testing.T) {
		v := vars["storageNames"]
		assert.False(t, v.loop.isLoop)
		assert.Equal(t, "", v.loop.iterator)
		assert.Equal(t, "", v.loop.expression)
	})

	// --- resources ---
	resources := map[string]parsedResource{}
	for _, r := range result.resources {
		resources[r.symbolicName] = r
	}
	require.Contains(t, resources, "sas")
	require.Contains(t, resources, "kv")

	t.Run("looped resource indexed form", func(t *testing.T) {
		r := resources["sas"]
		assert.True(t, r.loop.isLoop)
		assert.Equal(t, "name", r.loop.iterator)
		assert.Equal(t, "i", r.loop.indexVar)
		assert.Equal(t, "storageNames", r.loop.expression)
		// body-derived fields must still be extracted from the loop body
		assert.Equal(t, "name", r.name)
		assert.Equal(t, "location", r.location)
		assert.Contains(t, r.body, "sku")
	})

	t.Run("non-looped resource", func(t *testing.T) {
		r := resources["kv"]
		assert.False(t, r.loop.isLoop)
		assert.Equal(t, "", r.loop.iterator)
		assert.Equal(t, "", r.loop.indexVar)
		assert.Equal(t, "", r.loop.expression)
		assert.Equal(t, "'mykeyvault'", r.name)
	})

	// --- modules ---
	require.Len(t, result.modules, 1)
	t.Run("looped module", func(t *testing.T) {
		m := result.modules[0]
		assert.Equal(t, "stamps", m.name)
		assert.True(t, m.loop.isLoop)
		assert.Equal(t, "sku", m.loop.iterator)
		assert.Equal(t, "", m.loop.indexVar)
		assert.Equal(t, "storageNames", m.loop.expression)
		// body-derived name still extracted from the loop body
		assert.Equal(t, "'stamp-${sku}'", extractFieldValue(m.body, "name"))
		assert.Contains(t, m.body, "params")
	})

	// --- outputs ---
	outputs := map[string]parsedOutput{}
	for _, o := range result.outputs {
		outputs[o.name] = o
	}
	require.Contains(t, outputs, "ids")
	require.Contains(t, outputs, "region")

	t.Run("looped output", func(t *testing.T) {
		o := outputs["ids"]
		assert.True(t, o.loop.isLoop)
		assert.Equal(t, "sa", o.loop.iterator)
		assert.Equal(t, "", o.loop.indexVar)
		assert.Equal(t, "sas", o.loop.expression)
		assert.Equal(t, "sa.id", o.expression)
	})

	t.Run("non-looped output", func(t *testing.T) {
		o := outputs["region"]
		assert.False(t, o.loop.isLoop)
		assert.Equal(t, "", o.loop.iterator)
		assert.Equal(t, "location", o.expression)
	})
}

func TestParseBicepNestedResources(t *testing.T) {
	// The committed fixture is the single source of truth for the nested /
	// scope scenarios asserted below — read it rather than duplicating the
	// Bicep inline, so the fixture and the test can't drift apart.
	data, err := os.ReadFile("testdata/nested.bicep")
	require.NoError(t, err)

	result := parseBicep(string(data))

	top := map[string]parsedResource{}
	for _, r := range result.resources {
		top[r.symbolicName] = r
	}

	t.Run("top-level list excludes nested resources", func(t *testing.T) {
		require.Len(t, result.resources, 3)
		require.Contains(t, top, "sa")
		require.Contains(t, top, "lock")
		require.Contains(t, top, "kv")
		// nested resources must NOT appear at the top level
		assert.NotContains(t, top, "blob")
		assert.NotContains(t, top, "container")
	})

	t.Run("parent exposes its nested child", func(t *testing.T) {
		sa := top["sa"]
		assert.Empty(t, sa.parent)
		require.Len(t, sa.nested, 1)
		blob := sa.nested[0]
		assert.Equal(t, "blob", blob.symbolicName)
		assert.Equal(t, "blobServices", blob.typ)
		// relative child type inherits no apiVersion when omitted
		assert.Equal(t, "", blob.apiVersion)
		assert.Equal(t, "'default'", blob.name)
		assert.Equal(t, "sa", blob.parent)
	})

	t.Run("child exposes its grandchild", func(t *testing.T) {
		blob := top["sa"].nested[0]
		require.Len(t, blob.nested, 1)
		container := blob.nested[0]
		assert.Equal(t, "container", container.symbolicName)
		assert.Equal(t, "containers", container.typ)
		assert.Equal(t, "2023-01-01", container.apiVersion)
		assert.Equal(t, "'data'", container.name)
		assert.Equal(t, "blob", container.parent)
		// grandchild has no further nesting
		assert.Empty(t, container.nested)
	})

	t.Run("scope keyword is captured", func(t *testing.T) {
		lock := top["lock"]
		assert.Equal(t, "sa", lock.scope)
		assert.Empty(t, lock.nested)
	})

	t.Run("flat resource has no scope and no nesting", func(t *testing.T) {
		kv := top["kv"]
		assert.Equal(t, "", kv.scope)
		assert.Empty(t, kv.nested)
		assert.Empty(t, kv.parent)
	})
}
