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

// `asset` is true of every root and always the same shape, so the builder
// attaches it rather than each provider restating it. A provider declaring a
// root gets it without knowing this exists - which is the point, because
// forgetting it would be quiet: `asset` is `@global`, so a bare mention still
// resolves, to whichever runtime is executing rather than to the asset the
// query is standing on (ADR 031).
func TestRootsCarryAsset(t *testing.T) {
	res := schemaFor(t, `
		os.base @root {
			hostname() string
		}
		os.windows @root {
			hostname() string
		}
		notARoot {
			name string
		}
	`)

	for _, root := range []string{"os.base", "os.windows"} {
		field := res.Resources[root].Fields["asset"]
		require.NotNil(t, field, "root %s carries asset", root)
		// It names core's `asset` directly. An alias would generate a separate
		// resource holding only what this provider extends onto it, which then
		// has to be reconciled with the real one somewhere else.
		assert.Equal(t, string(types.Resource("asset")), field.Type)
		assert.True(t, field.IsImplicitResource)
	}

	assert.Nil(t, res.Resources["notARoot"].Fields["asset"], "only roots get it")
	assert.NotContains(t, res.Resources, "os.base.asset", "no bridging resource is generated")
}

// A provider that declares its own `asset` member keeps it. The attachment
// fills a gap; it does not overrule a schema that says something deliberate.
func TestRootsCarryAssetDoesNotOverwrite(t *testing.T) {
	res := schemaFor(t, `
		mine {
			name string
		}
		os.base @root {
			asset() mine
		}
	`)

	assert.Equal(t, string(types.Resource("mine")), res.Resources["os.base"].Fields["asset"].Type)
}

// A replacement can live in a peer provider. Every rooted provider carries
// `asset`, which core owns, so retiring a provider's own scalar `version` in
// favour of the canonical `asset.version` is the natural migration - and it is
// only expressible if the gate can see across the import.
//
// Seeing across it is not the same as trusting it: the peer's members are
// recorded while imports resolve, so a target is still checked down to the
// field. A cross-provider pointer nobody verifies is exactly the kind that rots.
func TestReplacedByAcrossProviders(t *testing.T) {
	schemaOf := func(t *testing.T, src string) error {
		t.Helper()
		files := map[string]string{
			"providers/demo/resources/demo.lr": src,
			"providers/core/resources/core.lr": `
option provider = "go.mondoo.com/mql/providers/core"
option go_package = "go.mondoo.com/mql/providers/core/resources"

asset @global {
  version string
  platform string
}
`,
		}
		res, err := Resolve("providers/demo/resources/demo.lr", func(path string) ([]byte, error) {
			raw, ok := files[path]
			require.Truef(t, ok, "unexpected read of %q", path)
			return []byte(raw), nil
		})
		require.NoError(t, err)
		_, err = Schema(res)
		return err
	}

	const header = `
import core

option provider = "go.mondoo.com/mql/providers/demo"
option go_package = "go.mondoo.com/mql/providers/demo/resources"
option root = "demo.instance"
`

	t.Run("a field on a peer's resource", func(t *testing.T) {
		err := schemaOf(t, header+`
demo.instance @root {
  version @maturity("deprecated") @replaced_by("asset.version") string
}
`)
		require.NoError(t, err)
	})

	t.Run("the peer's resource itself", func(t *testing.T) {
		err := schemaOf(t, header+`
demo.instance @root {
  details @maturity("deprecated") @replaced_by("asset") dict
}
`)
		require.NoError(t, err)
	})

	// Crossing a provider boundary must not turn the check off.
	t.Run("a field the peer does not have", func(t *testing.T) {
		err := schemaOf(t, header+`
demo.instance @root {
  version @maturity("deprecated") @replaced_by("asset.noSuchField") string
}
`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"asset" is imported but has no field "noSuchField"`)
	})

	t.Run("a resource no provider here has", func(t *testing.T) {
		err := schemaOf(t, header+`
demo.instance @root {
  version @maturity("deprecated") @replaced_by("nosuch.thing") string
}
`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not name a resource or field")
	})
}
