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

// mapResources is a trivial in-memory implementation of the plugin resource
// cache, enough to let CreateResource/NewResource dedupe by __id without a
// real provider runtime.
type mapResources struct {
	m map[string]plugin.Resource
}

func (r *mapResources) Get(key string) (plugin.Resource, bool) {
	v, ok := r.m[key]
	return v, ok
}

func (r *mapResources) Set(key string, value plugin.Resource) {
	r.m[key] = value
}

func (r *mapResources) GetOrSet(key string, value plugin.Resource) (plugin.Resource, bool) {
	if existing, ok := r.m[key]; ok {
		return existing, true
	}
	r.m[key] = value
	return value, false
}

func testRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &mapResources{m: map[string]plugin.Resource{}}}
}

// exprNodeFor parses the named declaration's relevant raw expression from the
// fixture and returns it as a wired-up bicep.expression resource carrying the
// file's symbol resolver — mirroring exactly what the *Tree() accessors build.
func loadResolverFixture(t *testing.T) (*plugin.Runtime, *symbolResolver, *parsedBicepFile) {
	data, err := os.ReadFile("testdata/resolvedref.bicep")
	require.NoError(t, err)
	parsed := parseBicep(string(data))
	return testRuntime(), newSymbolResolver("testdata/resolvedref.bicep", parsed), parsed
}

func findVar(parsed *parsedBicepFile, name string) parsedVariable {
	for _, v := range parsed.variables {
		if v.name == name {
			return v
		}
	}
	return parsedVariable{}
}

func findResource(parsed *parsedBicepFile, sym string) parsedResource {
	for _, r := range parsed.resources {
		if r.symbolicName == sym {
			return r
		}
	}
	return parsedResource{}
}

func findOutput(parsed *parsedBicepFile, name string) parsedOutput {
	for _, o := range parsed.outputs {
		if o.name == name {
			return o
		}
	}
	return parsedOutput{}
}

func findParam(parsed *parsedBicepFile, name string) parsedParameter {
	for _, p := range parsed.parameters {
		if p.name == name {
			return p
		}
	}
	return parsedParameter{}
}

// exprFor builds a bicep.expression resource for a raw expression string,
// wired with the given resolver, the way expressionTreeFor does.
func exprFor(t *testing.T, runtime *plugin.Runtime, resolver *symbolResolver, raw string) *mqlBicepExpression {
	return exprForID(t, runtime, resolver, "test:"+raw, raw)
}

// exprForID is exprFor with an explicit cache id. Two expressions wired with
// DIFFERENT resolvers must not share an id: CreateResource returns the cached
// instance for an id it already holds, so the second call would read the first
// call's resolver.
func exprForID(t *testing.T, runtime *plugin.Runtime, resolver *symbolResolver, id, raw string) *mqlBicepExpression {
	node := parseExpression(raw)
	expr, err := newMqlBicepExpression(runtime, id, node, resolver)
	require.NoError(t, err)
	return expr
}

// assertOnlyKind verifies referenceKind and that exactly the matching
// referenced*() accessor is non-null while the others resolve to null.
func assertOnlyKind(t *testing.T, expr *mqlBicepExpression, wantKind string) {
	t.Helper()

	kind, err := expr.referenceKind()
	require.NoError(t, err)
	assert.Equal(t, wantKind, kind)

	p, err := expr.referencedParameter()
	require.NoError(t, err)
	v, err := expr.referencedVariable()
	require.NoError(t, err)
	res, err := expr.referencedResource()
	require.NoError(t, err)
	m, err := expr.referencedModule()
	require.NoError(t, err)
	ty, err := expr.referencedType()
	require.NoError(t, err)

	switch wantKind {
	case refKindParameter:
		assert.NotNil(t, p)
		assert.Nil(t, v)
		assert.Nil(t, res)
		assert.Nil(t, m)
		assert.Nil(t, ty)
	case refKindVariable:
		assert.Nil(t, p)
		assert.NotNil(t, v)
		assert.Nil(t, res)
		assert.Nil(t, m)
		assert.Nil(t, ty)
	case refKindResource:
		assert.Nil(t, p)
		assert.Nil(t, v)
		assert.NotNil(t, res)
		assert.Nil(t, m)
		assert.Nil(t, ty)
	case refKindModule:
		assert.Nil(t, p)
		assert.Nil(t, v)
		assert.Nil(t, res)
		assert.NotNil(t, m)
		assert.Nil(t, ty)
	case refKindType:
		assert.Nil(t, p)
		assert.Nil(t, v)
		assert.Nil(t, res)
		assert.Nil(t, m)
		assert.NotNil(t, ty)
	case "":
		assert.Nil(t, p)
		assert.Nil(t, v)
		assert.Nil(t, res)
		assert.Nil(t, m)
		assert.Nil(t, ty)
	}
}

func TestSymbolResolverKind(t *testing.T) {
	_, resolver, _ := loadResolverFixture(t)

	assert.Equal(t, refKindParameter, resolver.kind("namePrefix"))
	assert.Equal(t, refKindParameter, resolver.kind("skuName"))
	assert.Equal(t, refKindVariable, resolver.kind("saName"))
	assert.Equal(t, refKindResource, resolver.kind("sa"))
	assert.Equal(t, refKindResource, resolver.kind("lock"))
	assert.Equal(t, refKindModule, resolver.kind("net"))
	assert.Equal(t, refKindType, resolver.kind("storageSku"))
	// built-in function and unknown symbols don't resolve
	assert.Equal(t, "", resolver.kind("resourceGroup"))
	assert.Equal(t, "", resolver.kind("nope"))
	assert.Equal(t, "", resolver.kind(""))
}

func TestExpressionReferenceResolution(t *testing.T) {
	runtime, resolver, parsed := loadResolverFixture(t)

	t.Run("variable expression references a parameter", func(t *testing.T) {
		// var saName = '${namePrefix}-sa' — interpolation; the embedded
		// segment is a symbolicRef whose target is the parameter.
		v := findVar(parsed, "saName")
		node := parseExpression(v.expression)
		require.Equal(t, exprKindInterpolation, node.kind)
		seg, err := newMqlBicepExpression(runtime, "seg", node.segments[1], resolver)
		require.NoError(t, err)
		assertOnlyKind(t, seg, refKindParameter)
		p, _ := seg.referencedParameter()
		assert.Equal(t, "namePrefix", p.Name.Data)
	})

	t.Run("resource name interpolates a variable", func(t *testing.T) {
		// resource sa { name: saName } — bare symbolicRef to the variable.
		r := findResource(parsed, "sa")
		expr := exprFor(t, runtime, resolver, r.name)
		assertOnlyKind(t, expr, refKindVariable)
		v, _ := expr.referencedVariable()
		assert.Equal(t, "saName", v.Name.Data)
	})

	t.Run("resource location references a parameter", func(t *testing.T) {
		// location: namePrefix — bare symbolicRef to the parameter.
		r := findResource(parsed, "sa")
		expr := exprFor(t, runtime, resolver, r.location)
		assertOnlyKind(t, expr, refKindParameter)
		p, _ := expr.referencedParameter()
		assert.Equal(t, "namePrefix", p.Name.Data)
	})

	t.Run("propertyAccess resolves the root resource", func(t *testing.T) {
		// output saId string = sa.id — propertyAccess, target is the resource.
		o := findOutput(parsed, "saId")
		expr := exprFor(t, runtime, resolver, o.expression)
		require.Equal(t, exprKindPropertyAccess, expr.node.kind)
		assert.Equal(t, "sa", expr.node.target)
		assertOnlyKind(t, expr, refKindResource)
		res, _ := expr.referencedResource()
		assert.Equal(t, "sa", res.SymbolicName.Data)
	})

	t.Run("scope references a resource symbolically", func(t *testing.T) {
		// resource lock { scope: sa } — bare symbolicRef to the resource.
		r := findResource(parsed, "lock")
		expr := exprFor(t, runtime, resolver, r.scope)
		assertOnlyKind(t, expr, refKindResource)
		res, _ := expr.referencedResource()
		assert.Equal(t, "sa", res.SymbolicName.Data)
	})

	t.Run("output references a module by name", func(t *testing.T) {
		// output netName string = net.name — propertyAccess on the module.
		o := findOutput(parsed, "netName")
		expr := exprFor(t, runtime, resolver, o.expression)
		assert.Equal(t, "net", expr.node.target)
		assertOnlyKind(t, expr, refKindModule)
		m, _ := expr.referencedModule()
		assert.Equal(t, "net", m.Name.Data)
	})

	t.Run("param type references a user-defined type", func(t *testing.T) {
		// param skuName storageSku — the type name resolves to the type decl.
		p := findParam(parsed, "skuName")
		require.Equal(t, "storageSku", p.typ)
		expr := exprFor(t, runtime, resolver, p.typ)
		assertOnlyKind(t, expr, refKindType)
		ty, _ := expr.referencedType()
		assert.Equal(t, "storageSku", ty.Name.Data)
	})

	t.Run("built-in function call resolves to empty kind", func(t *testing.T) {
		// output rgLoc string = resourceGroup().location — the root is the
		// built-in resourceGroup, which is not a same-file declaration.
		o := findOutput(parsed, "rgLoc")
		expr := exprFor(t, runtime, resolver, o.expression)
		// The propertyAccess base is a functionCall; its target is empty, so
		// the node itself resolves to the empty kind.
		assertOnlyKind(t, expr, "")
	})

	t.Run("unparented expression with nil resolver resolves to empty", func(t *testing.T) {
		// Defensive: a node built without a resolver (e.g. reconstructed
		// across gRPC) must not panic and resolves to the empty kind. It needs
		// its own cache id: an earlier subtest already built "namePrefix" WITH
		// a resolver, and a resource is stamped once, by whichever caller
		// created it.
		expr := exprForID(t, runtime, nil, "test:nilresolver:namePrefix", "namePrefix")
		assertOnlyKind(t, expr, "")
	})
}
