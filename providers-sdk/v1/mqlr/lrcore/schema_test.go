// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

const provider = "🐱"

func schemaFor(t *testing.T, s string) *resources.Schema {
	ast := parse(t, s)
	ast.Options = map[string]string{"provider": provider}
	res, err := Schema(ast)
	require.NoError(t, err)
	return res
}

func TestSchema(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		res := schemaFor(t, "")
		assert.Empty(t, res.Resources)
	})

	t.Run("chain resource creation", func(t *testing.T) {
		res := schemaFor(t, `
			platform.has.name {
				str string
				comp() string
				}
		`)
		require.NotEmpty(t, res.Resources)
		expectedPlatform := &resources.ResourceInfo{
			Id:          "platform",
			IsExtension: true,
			Fields: map[string]*resources.Field{
				"has": {
					Name:               "has",
					Type:               string(types.Resource("platform.has")),
					Provider:           provider,
					IsImplicitResource: true,
				},
			},
		}
		expectedPlatforHas := &resources.ResourceInfo{
			Id:          "platform.has",
			IsExtension: true,
			Fields: map[string]*resources.Field{
				"name": {
					Name:               "name",
					Type:               string(types.Resource("platform.has.name")),
					Provider:           provider,
					IsImplicitResource: true,
				},
			},
		}
		expectedPlatformHasName := &resources.ResourceInfo{
			Id:       "platform.has.name",
			Provider: provider,
			Name:     "platform.has.name",
			Fields: map[string]*resources.Field{
				"str": {
					Name: "str",
					Type: string(types.String),
					// is mandatory because its's static (not computed)
					IsMandatory: true,
					Refs:        []string{},
					Provider:    provider,
				},
				"comp": {
					Name:     "comp",
					Type:     string(types.String),
					Refs:     []string{},
					Provider: provider,
				},
			},
		}
		assert.Equal(t, expectedPlatform, res.Resources["platform"])
		assert.Equal(t, expectedPlatforHas, res.Resources["platform.has"])
		assert.Equal(t, expectedPlatformHasName, res.Resources["platform.has.name"])
	})
}

func TestSchemaMaturity(t *testing.T) {
	t.Run("resource maturity propagates to schema", func(t *testing.T) {
		res := schemaFor(t, `name @maturity("experimental") { field string }`)
		assert.Equal(t, "experimental", res.Resources["name"].Maturity)
	})

	t.Run("field maturity propagates to schema", func(t *testing.T) {
		res := schemaFor(t, `name { field @maturity("deprecated") string }`)
		assert.Equal(t, "deprecated", res.Resources["name"].Fields["field"].Maturity)
	})

	t.Run("maturity propagates to implicit fields", func(t *testing.T) {
		res := schemaFor(t, `platform.config @maturity("experimental") { value string }`)
		require.NotNil(t, res.Resources["platform"])
		require.NotNil(t, res.Resources["platform"].Fields["config"])
		assert.Equal(t, "experimental", res.Resources["platform"].Fields["config"].Maturity)
	})

	t.Run("invalid maturity is rejected", func(t *testing.T) {
		ast := parse(t, `name @maturity("bogus") { field string }`)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid maturity")
	})

	t.Run("invalid field maturity is rejected", func(t *testing.T) {
		ast := parse(t, `name { field @maturity("bogus") string }`)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid maturity")
	})

	t.Run("implicit intermediate inherits maturity from leaf", func(t *testing.T) {
		// x is stable (default), x.y.z is deprecated.
		// x.y is implicitly created and should inherit deprecated from x.y.z.
		res := schemaFor(t, `
			x { val string }
			x.y.z @maturity("deprecated") { val string }
		`)
		require.NotNil(t, res.Resources["x.y"])
		require.NotNil(t, res.Resources["x.y"].Fields["z"])
		assert.Equal(t, "deprecated", res.Resources["x.y"].Fields["z"].Maturity,
			"implicit field z on x.y should inherit deprecated from x.y.z")
		// x.y itself (the implicit resource) has no maturity annotation
		assert.Equal(t, "", res.Resources["x.y"].Maturity)
		// x's field "y" pointing to x.y should inherit x.y.z's maturity
		require.NotNil(t, res.Resources["x"].Fields["y"])
		assert.Equal(t, "deprecated", res.Resources["x"].Fields["y"].Maturity)
	})

	t.Run("explicit intermediate is not affected by leaf maturity", func(t *testing.T) {
		// x, x.y, and x.y.z are all declared. x.y.z is deprecated.
		// x.y is explicitly declared (stable), so x's field "y" should be stable.
		res := schemaFor(t, `
			x { val string }
			x.y { val string }
			x.y.z @maturity("deprecated") { val string }
		`)
		require.NotNil(t, res.Resources["x.y"])
		// x.y is explicitly declared with no maturity = stable
		assert.Equal(t, "", res.Resources["x.y"].Maturity)
		// x.y's field "z" should still be deprecated (from x.y.z)
		require.NotNil(t, res.Resources["x.y"].Fields["z"])
		assert.Equal(t, "deprecated", res.Resources["x.y"].Fields["z"].Maturity)
		// x's field "y" should be stable because x.y is explicitly declared
		require.NotNil(t, res.Resources["x"].Fields["y"])
		assert.Equal(t, "", res.Resources["x"].Fields["y"].Maturity,
			"explicit x.y is stable, so x's field y should be stable too")
	})
}

func TestDetermnisticSchema(t *testing.T) {
	lrSchema, err := os.ReadFile("testdata/new.lr")
	require.NoError(t, err)
	ast := parse(t, string(lrSchema))
	schema, err := Schema(ast)
	require.NoError(t, err)
	for range 100 {
		newAst := parse(t, string(lrSchema))
		newSchema, err := Schema(newAst)
		require.NoError(t, err)
		require.Equal(t, schema, newSchema)
	}
}

func TestReplacedBy(t *testing.T) {
	// The annotation is a pointer with no runtime behavior (ADR 040): what it
	// buys is a deprecation notice that names a real destination, so the only
	// thing that can go wrong is the destination not existing.
	schemaWithErr := func(t *testing.T, s string) error {
		ast := parse(t, s)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		return err
	}

	t.Run("field target", func(t *testing.T) {
		res := schemaFor(t, `
			os @maturity("deprecated") @replaced_by("os.base") {
				hostname() @maturity("deprecated") @replaced_by("os.base.hostname") string
			}
			os.base @root {
				hostname() string
			}
		`)
		assert.Equal(t, "os.base", res.Resources["os"].ReplacedBy)
		assert.Equal(t, "os.base.hostname", res.Resources["os"].Fields["hostname"].ReplacedBy)
		// The target itself carries nothing; only the deprecated side points.
		assert.Empty(t, res.Resources["os.base"].ReplacedBy)
		assert.Empty(t, res.Resources["os.base"].Fields["hostname"].ReplacedBy)
	})

	t.Run("unknown resource target", func(t *testing.T) {
		err := schemaWithErr(t, `
			os @maturity("deprecated") @replaced_by("osbase") {
				hostname() string
			}
		`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `@replaced_by("osbase") does not name a resource or field`)
	})

	t.Run("dotted target falls back to the field reading", func(t *testing.T) {
		// `os.nope` is ambiguous on its face: it could be a resource we do not
		// have, or a field on one we do. The resource lookup misses and the
		// field lookup hits an owner that exists, so the specific message wins.
		err := schemaWithErr(t, `
			os @maturity("deprecated") @replaced_by("os.nope") {
				hostname() string
			}
		`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `resource "os" has no field "nope"`)
	})

	t.Run("unknown field on a known resource", func(t *testing.T) {
		err := schemaWithErr(t, `
			os @maturity("deprecated") {
				hostname() @replaced_by("os.base.hostnaem") string
			}
			os.base @root {
				hostname() string
			}
		`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `resource "os.base" has no field "hostnaem"`)
	})

	t.Run("self reference", func(t *testing.T) {
		err := schemaWithErr(t, `
			os {
				hostname() @replaced_by("os.hostname") string
			}
		`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "points at itself")
	})
}

// Existence is not enough: the replacement has to still be addressable once the
// root is the namespace (ADR 031 v15). Catching it when the provider is built
// is the whole point - the alternative is a user reading a notice that points
// at something they cannot type.
func TestReplacedByReachability(t *testing.T) {
	schemaWithErr := func(t *testing.T, s string) error {
		ast := parse(t, s)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		return err
	}

	t.Run("reached through a member, not an embed", func(t *testing.T) {
		// `sshd.config` hangs off no embed chain, but `_.sshd.config` resolves,
		// so it survives the cutover and is a legal target.
		ast := parse(t, `
			os @maturity("deprecated") @replaced_by("sshd.config.params") {
				sshd() @maturity("deprecated") string
			}
			os.base @root {
				sshd() sshd
			}
			sshd {
				config() sshd.config
			}
			sshd.config {
				params() string
			}
		`)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		require.NoError(t, err)
	})

	t.Run("target hanging off nothing", func(t *testing.T) {
		err := schemaWithErr(t, `
			os @maturity("deprecated") @replaced_by("orphan.thing") {
				hostname() string
			}
			os.base @root {
				hostname() string
			}
			orphan.thing {
				name() string
			}
		`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `@replaced_by target "orphan.thing" cannot be reached from any asset root`)
	})

	t.Run("a provider with no roots is not asked the question", func(t *testing.T) {
		// Nothing to be outside of yet. Rejecting here would block every
		// provider that has not been rooted from recording a replacement.
		ast := parse(t, `
			thing @maturity("deprecated") @replaced_by("other.name") {
				name() string
			}
			other {
				name string
			}
		`)
		ast.Options = map[string]string{"provider": provider}
		_, err := Schema(ast)
		require.NoError(t, err)
	})
}

// TestSchemaAliasOrderIsDeterministic pins the bug where AWS codegen reported
// three phantom "breaking schema change" warnings on roughly half of its runs.
//
// aws.lr declares `aws.accessanalyzer` and `aws.accessAnalyzer` as aliases of
// the same resource, and likewise for their `.analyzer` children. An alias and
// its target share one *ResourceInfo, so both children wrote the same `analyzer`
// field on the same object and the first writer won. The finalization loop
// ordered names by depth only, which left the two same-depth spellings in map
// order, so the winner -- and therefore the field's type in the emitted schema
// -- changed from run to run on identical input.
func TestSchemaAliasOrderIsDeterministic(t *testing.T) {
	src := `
option provider = "🐱"

alias x.thing = x.y.Thing
alias x.Thing = x.y.Thing
alias x.thing.leaf = x.y.Thing.leaf
alias x.Thing.leaf = x.y.Thing.leaf

x.y.Thing {
  name string
}

x.y.Thing.leaf {
  val string
}
`
	read := func(string) ([]byte, error) { return []byte(src), nil }

	schemaOf := func(t *testing.T) *resources.Schema {
		t.Helper()
		ast, err := Resolve("providers/x/resources/x.lr", read)
		require.NoError(t, err)
		schema, err := Schema(ast)
		require.NoError(t, err)
		return schema
	}

	first := schemaOf(t)
	target := first.Resources["x.y.Thing"]
	require.NotNil(t, target)
	require.NotNil(t, target.Fields["leaf"])

	// Both alias spellings sit at the same depth, so the tie-break is the name:
	// "x.Thing.leaf" sorts before "x.thing.leaf" (uppercase T is the lower byte).
	assert.Equal(t, string(types.Resource("x.Thing.leaf")), target.Fields["leaf"].Type,
		"the lexicographically first spelling must win the shared field")

	for range 50 {
		next := schemaOf(t)
		require.Equal(t, first, next, "identical input must produce an identical schema")
	}
}
