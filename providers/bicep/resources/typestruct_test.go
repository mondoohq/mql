// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// loadTypeStructFixture parses the typestruct.bicep fixture and returns a
// runtime plus the file's symbol resolver, mirroring loadResolverFixture.
func loadTypeStructFixture(t *testing.T) (*plugin.Runtime, *symbolResolver, *parsedBicepFile) {
	data, err := os.ReadFile("testdata/typestruct.bicep")
	require.NoError(t, err)
	parsed := parseBicep(string(data))
	return testRuntime(), newSymbolResolver("testdata/typestruct.bicep", parsed), parsed
}

func findType(parsed *parsedBicepFile, name string) parsedType {
	for _, ty := range parsed.types {
		if ty.name == name {
			return ty
		}
	}
	return parsedType{}
}

func TestClassifyTypeDefinition(t *testing.T) {
	_, _, parsed := loadTypeStructFixture(t)

	t.Run("union type", func(t *testing.T) {
		ty := findType(parsed, "sku")
		assert.Equal(t, "union", ty.kind)
		assert.Equal(t, []string{"'Standard_LRS'", "'Premium_LRS'"}, ty.unionMembers)
		assert.Empty(t, ty.properties)
		assert.Empty(t, ty.discriminator)
	})

	t.Run("object type with property naming another type", func(t *testing.T) {
		ty := findType(parsed, "cfg")
		assert.Equal(t, "object", ty.kind)
		assert.Empty(t, ty.unionMembers)
		require.Len(t, ty.properties, 2)
		assert.Equal(t, parsedTypeProperty{name: "name", typ: "string"}, ty.properties[0])
		assert.Equal(t, parsedTypeProperty{name: "tier", typ: "sku"}, ty.properties[1])
	})

	t.Run("exported object type strips optional marker", func(t *testing.T) {
		ty := findType(parsed, "exportedCfg")
		assert.True(t, ty.exported)
		assert.Equal(t, "object", ty.kind)
		require.Len(t, ty.properties, 2)
		assert.Equal(t, "id", ty.properties[0].name)
		// `optional: bool?` -> the trailing `?` is stripped from the key.
		assert.Equal(t, "optional", ty.properties[1].name)
		assert.Equal(t, "bool?", ty.properties[1].typ)
	})

	t.Run("discriminated tagged union", func(t *testing.T) {
		ty := findType(parsed, "shape")
		assert.Equal(t, "union", ty.kind)
		assert.Equal(t, "kind", ty.discriminator)
		require.Len(t, ty.unionMembers, 2)
		assert.Contains(t, ty.unionMembers[0], "circle")
		assert.Contains(t, ty.unionMembers[1], "square")
	})

	t.Run("alias type", func(t *testing.T) {
		ty := findType(parsed, "skuAlias")
		assert.Equal(t, "alias", ty.kind)
		assert.Equal(t, "sku", ty.definition)
	})
}

func TestClassifyTypeDefinitionPrimitivesAndArrays(t *testing.T) {
	cases := []struct {
		def  string
		kind string
	}{
		{"string", "primitive"},
		{"int", "primitive"},
		{"bool", "primitive"},
		{"object", "primitive"},
		{"array", "primitive"},
		{"secureString", "primitive"},
		{"secureObject", "primitive"},
		{"string[]", "array"},
		{"[string, int]", "array"},
		{"myType", "alias"},
	}
	for _, c := range cases {
		kind, _, _ := classifyTypeDefinition(c.def)
		assert.Equal(t, c.kind, kind, "def %q", c.def)
	}
}

func TestTypeResourceFields(t *testing.T) {
	runtime, _, parsed := loadTypeStructFixture(t)

	mqlTypes, err := createMqlTypes(runtime, "testdata/typestruct.bicep", parsed.types)
	require.NoError(t, err)

	byName := map[string]*mqlBicepType{}
	for _, mt := range mqlTypes {
		ty := mt.(*mqlBicepType)
		byName[ty.Name.Data] = ty
	}

	t.Run("union members surface on the resource", func(t *testing.T) {
		ty := byName["sku"]
		require.NotNil(t, ty)
		assert.Equal(t, "union", ty.Kind.Data)
		assert.Equal(t, []any{"'Standard_LRS'", "'Premium_LRS'"}, ty.UnionMembers.Data)
	})

	t.Run("object properties materialize", func(t *testing.T) {
		ty := byName["cfg"]
		require.NotNil(t, ty)
		assert.Equal(t, "object", ty.Kind.Data)
		props, err := ty.properties()
		require.NoError(t, err)
		require.Len(t, props, 2)
		p0 := props[0].(*mqlBicepTypeProperty)
		p1 := props[1].(*mqlBicepTypeProperty)
		assert.Equal(t, "name", p0.Name.Data)
		assert.Equal(t, "string", p0.Type.Data)
		assert.Equal(t, "tier", p1.Name.Data)
		assert.Equal(t, "sku", p1.Type.Data)
	})

	t.Run("discriminator surfaces", func(t *testing.T) {
		ty := byName["shape"]
		require.NotNil(t, ty)
		assert.Equal(t, "kind", ty.Discriminator.Data)
	})
}

func TestParameterResolvedType(t *testing.T) {
	runtime, resolver, parsed := loadTypeStructFixture(t)

	mqlParams, err := createMqlParameters(runtime, "testdata/typestruct.bicep", parsed.parameters, resolver)
	require.NoError(t, err)

	byName := map[string]*mqlBicepParameter{}
	for _, mp := range mqlParams {
		p := mp.(*mqlBicepParameter)
		byName[p.Name.Data] = p
	}

	t.Run("user-defined typed param resolves", func(t *testing.T) {
		p := byName["appCfg"]
		require.NotNil(t, p)
		rt, err := p.resolvedType()
		require.NoError(t, err)
		require.NotNil(t, rt)
		assert.Equal(t, "cfg", rt.Name.Data)
		assert.Equal(t, "object", rt.Kind.Data)
	})

	t.Run("built-in typed param resolves to null", func(t *testing.T) {
		p := byName["appName"]
		require.NotNil(t, p)
		rt, err := p.resolvedType()
		require.NoError(t, err)
		assert.Nil(t, rt)
	})
}

func TestOutputResolvedType(t *testing.T) {
	runtime, resolver, parsed := loadTypeStructFixture(t)

	mqlOutputs, err := createMqlOutputs(runtime, "testdata/typestruct.bicep", parsed.outputs, resolver)
	require.NoError(t, err)
	require.NotEmpty(t, mqlOutputs)

	o := mqlOutputs[0].(*mqlBicepOutput)
	assert.Equal(t, "usedSku", o.Name.Data)
	rt, err := o.resolvedType()
	require.NoError(t, err)
	require.NotNil(t, rt)
	assert.Equal(t, "sku", rt.Name.Data)
	assert.Equal(t, "union", rt.Kind.Data)
}
