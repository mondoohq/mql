// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// The mockprovider carries both asset-root cases: `muser.running` is typed
// `asset<mgroup>`, whose root this schema defines, and `muser.runningUnknown` is
// typed `asset<mcp>`, whose root no loaded schema defines.
var assetConf = mqlc.NewConfig(
	core_schema.Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "mockprovider"})),
	mql.Features{byte(mql.ResourceContext)},
)

// chunkShape renders one block's chunks as `id(type)`, which is what the asset
// tests are about: whether the deref chunk is there, how many there are, and
// what the chain is typed as.
func chunkShape(t *testing.T, block *llx.Block) []string {
	t.Helper()
	res := make([]string, len(block.Chunks))
	for i, c := range block.Chunks {
		res[i] = c.Id + "(" + c.Type().Label() + ")"
	}
	return res
}

func TestAssetChain(t *testing.T) {
	t.Run("the reference itself needs no deref", func(t *testing.T) {
		res, err := mqlc.Compile("muser.running", nil, assetConf)
		require.NoError(t, err)
		assert.Equal(t, []string{"muser(muser)", "running(asset<mgroup>)"},
			chunkShape(t, res.CodeV2.Blocks[0]))
	})

	// The nil comparisons are the only thing MQL could do with an asset before
	// this change, and they are registered on the asset type itself. Chaining is
	// tried after them, so a root field named `==` could never shadow one.
	t.Run("nil comparisons stay on the asset", func(t *testing.T) {
		for _, q := range []string{"muser.running == null", "muser.running != null"} {
			res, err := mqlc.Compile(q, nil, assetConf)
			require.NoError(t, err, q)
			shape := chunkShape(t, res.CodeV2.Blocks[0])
			assert.Len(t, shape, 3, q)
			assert.NotContains(t, shape, llx.AssetRootChunkID+"(mgroup)", q)
		}
	})

	t.Run("a field derefs into the root, then reads it as a resource", func(t *testing.T) {
		res, err := mqlc.Compile("muser.running.name", nil, assetConf)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"muser(muser)", "running(asset<mgroup>)",
			llx.AssetRootChunkID + "(mgroup)", "name(string)",
		}, chunkShape(t, res.CodeV2.Blocks[0]))

		// The deref is not a step the user wrote, so it must not show up in the
		// label the result is reported under.
		labels := []string{}
		for _, l := range res.Labels.GetLabels() {
			labels = append(labels, l)
		}
		assert.Contains(t, labels, "muser.running.name")
	})

	// One deref for the whole block, not one per field: each deref resolves the
	// referenced asset, so a block of five fields would otherwise resolve it
	// five times.
	t.Run("a block derefs once", func(t *testing.T) {
		res, err := mqlc.Compile("muser.running { name }", nil, assetConf)
		require.NoError(t, err)

		derefs := 0
		for _, block := range res.CodeV2.Blocks {
			for _, c := range block.Chunks {
				if c.Id == llx.AssetRootChunkID {
					derefs++
					assert.Equal(t, string(types.Resource("mgroup")), c.Function.Type)
				}
			}
		}
		assert.Equal(t, 1, derefs)
	})

	t.Run("unknown field of a known root", func(t *testing.T) {
		_, err := mqlc.Compile("muser.running.nope", nil, assetConf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find field 'nope'")
	})

	// The fields reachable through a reference are the root's fields, so they
	// are what gets offered - for the error above, and for shell completion,
	// which reads the same list. A trailing dot is the "which fields are here"
	// question in its plainest form.
	t.Run("suggestions come from the root", func(t *testing.T) {
		res, err := mqlc.Compile("muser.running.", nil, assetConf)
		require.Error(t, err)
		suggestions := []string{}
		for _, s := range res.GetSuggestions() {
			suggestions = append(suggestions, s.Field)
		}
		assert.Equal(t, []string{"name"}, suggestions)
	})

	// Nothing can be offered for a root this compile cannot see, and guessing
	// from the asset's own type would offer fields of the wrong resource.
	t.Run("no suggestions for an unloaded root", func(t *testing.T) {
		res, err := mqlc.Compile("muser.runningUnknown.", nil, assetConf)
		require.Error(t, err)
		assert.Empty(t, res.GetSuggestions())
	})
}

// A root whose schema is not loaded here is the compile-here / run-there case:
// the compiler knows the root by name only, so the member cannot be checked and
// its type is left to the executing runtime, which does have the schema. See
// ADR 031 decision 2.
func TestAssetChainDegradesWithoutTheRootSchema(t *testing.T) {
	t.Run("a single field defers its type to runtime", func(t *testing.T) {
		res, err := mqlc.Compile("muser.runningUnknown.tools", nil, assetConf)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"muser(muser)", "runningUnknown(asset<mcp>)",
			llx.AssetRootChunkID + "(mcp)", "tools(any)",
		}, chunkShape(t, res.CodeV2.Blocks[0]))
	})

	// A block needs a real type to compile against, so it cannot degrade the way
	// a single field can. The error has to say why rather than report a missing
	// resource, which reads like a typo.
	t.Run("a block cannot", func(t *testing.T) {
		_, err := mqlc.Compile("muser.runningUnknown { tools }", nil, assetConf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "asset root 'mcp'")
		assert.Contains(t, err.Error(), "not loaded")
	})

	// Arguments would have to be checked against an init signature this compile
	// cannot see, so they are refused rather than passed along unchecked.
	t.Run("arguments are refused", func(t *testing.T) {
		_, err := mqlc.Compile(`muser.runningUnknown.tools("x")`, nil, assetConf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not loaded")
	})
}

// `_` at the top level is the connected asset's root resource (ADR 031
// decision 6). The root comes from the provider serving the connection, so the
// compiler is handed a name rather than discovering one.
func TestTopLevelUnderscore(t *testing.T) {
	rooted := assetConf
	rooted.AssetRoot = "muser"

	t.Run("resolves to the root resource", func(t *testing.T) {
		res, err := mqlc.Compile("_", nil, rooted)
		require.NoError(t, err)
		assert.Equal(t, []string{"muser(muser)"}, chunkShape(t, res.CodeV2.Blocks[0]))
	})

	t.Run("fields and blocks read off it", func(t *testing.T) {
		res, err := mqlc.Compile("_.name", nil, rooted)
		require.NoError(t, err)
		assert.Equal(t, []string{"muser(muser)", "name(string)"}, chunkShape(t, res.CodeV2.Blocks[0]))

		_, err = mqlc.Compile("_ { name }", nil, rooted)
		require.NoError(t, err)
	})

	// Nothing is guessed when the connection declares no root: answering with a
	// resource that only partly covers the asset would be worse than failing,
	// and this is the state every provider starts in.
	t.Run("without a declared root", func(t *testing.T) {
		_, err := mqlc.Compile("_", nil, assetConf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "declares no root resource")
	})

	// A bare `_` inside a block emits no chunk of its own - it is the binding -
	// so the operand's value is the binding's ref. The top-level case had to
	// stop reading that binding unconditionally, which is a nil dereference
	// once `_` compiles without one.
	t.Run("inside a block it is still the binding", func(t *testing.T) {
		for _, q := range []string{"muser { _ }", "muser { _.name }", "muser.groups { _ }"} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoError(t, err, q)
		}
	})
}

// The os provider declares `os.any` as its root: the union of the OS roots,
// with the universal surface arriving through the embedded `os.base` and the
// family-specific surface through aliases. This pins the chain end to end -
// alias or embed -> implicit field on the root -> compiled field read - for
// members from every root, including the ones that take arguments.
func TestOsRootAttachments(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	conf.AssetRoot = "os.any"

	for _, q := range []string{
		"_",
		"_.hostname",
		"_.packages.list.length",
		"_.users.list { name }",
		"_.services.where(running).length",
		"_.kernel.info",
		"_.sshd.config.params",
		// a resource that takes arguments cannot be a plain field, which is why
		// these are aliases rather than accessors on the root
		`_.file("/etc/hostname").exists`,
		`_.command("echo hi").stdout`,
	} {
		t.Run(q, func(t *testing.T) {
			_, err := mqlc.Compile(q, nil, conf)
			assert.NoError(t, err)
		})
	}

	// The global names are untouched: an alias adds a path, it does not move
	// the resource.
	for _, q := range []string{"packages.list.length", "sshd.config.params", `file("/etc/hostname").exists`} {
		t.Run(q, func(t *testing.T) {
			_, err := mqlc.Compile(q, nil, conf)
			assert.NoError(t, err)
		})
	}
}

// A field missing from a platform root is a platform mismatch, not version
// skew, so the diagnostic has to say which root does carry it instead of
// suggesting a provider upgrade that cannot help. See ADR 031.
func TestMissingFieldOnAPlatformRoot(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	conf.AssetRoot = "os.linux"
	conf.DeclaredAssetRoot = "os.any"

	// Only roots are alternatives. `os.date` shares the namespace and has a
	// `timezone` field, but no asset is ever rooted there, so offering it
	// answers nothing - which the namespace-shaped guess this replaced did.
	t.Run("offers roots, not neighbours", func(t *testing.T) {
		_, err := mqlc.Compile("_.timezone", nil, conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find field 'timezone' in os.linux")
		assert.NotContains(t, err.Error(), "os.date")
	})

	t.Run("names the root that has it", func(t *testing.T) {
		_, err := mqlc.Compile("_.registrykey", nil, conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rooted at os.linux")
		assert.Contains(t, err.Error(), "available on os.windows")
		// The union carries every platform's members, so offering it as the
		// place to find one answers nothing.
		assert.NotContains(t, err.Error(), "os.any")
		// And this is not a version problem.
		assert.NotContains(t, err.Error(), "may require a newer one")
	})

	// A name no root carries gets no platform hint - there is no platform to
	// point at - and falls through to the version-skew lead, which needs
	// provider versions in the schema to render (it does live, where the
	// coordinator supplies them).
	t.Run("no platform hint when no root has it", func(t *testing.T) {
		_, err := mqlc.Compile("_.nosuchthing", nil, conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find field 'nosuchthing' in os.linux")
		assert.NotContains(t, err.Error(), "available on")
	})

	t.Run("the platform's own members still resolve", func(t *testing.T) {
		for _, q := range []string{"_.iptables", "_.selinux.mode", "_.hostname", "_.packages.list.length"} {
			_, err := mqlc.Compile(q, nil, conf)
			assert.NoError(t, err, q)
		}
	})
}

// A query is a block on the asset root, so a bare member of the root resolves:
// `hostname` means `assetRoot.hostname` (ADR 031 point 7). Before this, only
// `_.hostname` worked and `hostname` failed outright.
func TestBareRootMembers(t *testing.T) {
	rooted := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	rooted.AssetRoot = "os.linux"
	unrooted := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})

	// Members of the root, reached through its embed chain (os.linux -> os.unix
	// -> os.base) and through aliases attached to it.
	for _, q := range []string{"hostname", "uptime", "machineid", "date.timezone", "env.length"} {
		t.Run(q, func(t *testing.T) {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoError(t, err, "resolves as a member of the root")

			_, err = mqlc.Compile(q, nil, unrooted)
			assert.Error(t, err, "without a root there is nothing to resolve it against")
		})
	}

	// A name that is neither a global resource nor a root member fails the way
	// it always did - the fallback must not change what an unknown name says.
	t.Run("unknown name", func(t *testing.T) {
		_, err := mqlc.Compile("nosuchthing", nil, rooted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find resource for identifier 'nosuchthing'")
	})
}

// The v14 rule is global-first, root-fallback, and this is what it buys: every
// query that compiles today compiles to the *same code*. Root-first would
// recompile `packages.list.length` through the root, changing its checksum -
// which cnspec keys scoring continuity on, and which would bake one platform
// into a bundle it shares across assets. See ADR 031 point 7.
func TestRootedFallbackDoesNotChangeExistingBundles(t *testing.T) {
	rooted := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	rooted.AssetRoot = "os.linux"
	unrooted := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})

	for _, q := range []string{
		"packages.list.length",
		"users.list { name }",
		"sshd.config.params",
		`file("/etc/hostname").exists`,
		"asset.platform",
		"services.where(running).length",
	} {
		t.Run(q, func(t *testing.T) {
			with, err := mqlc.Compile(q, nil, rooted)
			require.NoError(t, err)
			without, err := mqlc.Compile(q, nil, unrooted)
			require.NoError(t, err)

			assert.Equal(t, without.CodeV2.Id, with.CodeV2.Id,
				"a root must not change the compilation of a name the global namespace already answers")
		})
	}
}

// A bundle records the resources it reaches globally that have no home in an
// asset's tree, so the v15 cutover is measurable rather than guessed (ADR 031
// point 7). A resource is fine three ways: marked `@global`, reachable from its
// provider's root, or belonging to a provider with no root yet.
func TestUnrootedResourcesAreRecorded(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})

	t.Run("core resources are marked global", func(t *testing.T) {
		res, err := mqlc.Compile("asset.platform", nil, conf)
		require.NoError(t, err)
		assert.Empty(t, res.UnrootedResources)

		res, err = mqlc.Compile("time.now.unix", nil, conf)
		require.NoError(t, err)
		assert.Empty(t, res.UnrootedResources)
	})

	// The os provider attaches its whole surface to its roots, so nothing it
	// exposes is left outside the tree. This asserts that state rather than the
	// mechanism - it is the check that catches a resource added later without a
	// placement.
	// The mechanism itself: pin the provider to a root that deliberately does
	// not carry everything, and the resources outside it get recorded. This is
	// what a half-migrated provider looks like.
	t.Run("records what the root does not carry", func(t *testing.T) {
		schema := core_schema.Add(os_schema)
		narrow := mqlc.NewConfig(schema, mql.Features{byte(mql.ResourceContext)})
		s, ok := schema.(*resources.Schema)
		require.True(t, ok, "expected a *resources.Schema")
		// Add merges in place, so this is the shared schema every other test
		// compiles against - put it back.
		original := s.ProviderRoots
		defer func() { s.ProviderRoots = original }()
		s.ProviderRoots = map[string]string{"go.mondoo.com/mql/providers/os": "os.linux"}

		// registrykey lives on os.windows, so a Linux root does not carry it.
		res, err := mqlc.Compile("registrykey", nil, narrow)
		require.NoError(t, err)
		assert.Equal(t, []string{"registrykey"}, res.UnrootedResources)

		// while a member of the Linux root stays unrecorded
		res, err = mqlc.Compile("selinux.mode", nil, narrow)
		require.NoError(t, err)
		assert.Empty(t, res.UnrootedResources)
	})

	t.Run("the os surface is fully rooted", func(t *testing.T) {
		for _, q := range []string{
			"packages.list.length",
			"sshd.config.params",
			"users.list { name }",
			"selinux.mode",
			`file("/etc/hostname").exists`,
		} {
			res, err := mqlc.Compile(q, nil, conf)
			require.NoError(t, err, q)
			assert.Empty(t, res.UnrootedResources, q)
		}
	})
}

// RootedNamespace is the v15 model available early (ADR 031 point 7): the root
// is the namespace, the global namespace is reachable only through `@global`,
// and a compile without a root is an error rather than a silent fall back.
func TestRootedNamespace(t *testing.T) {
	rooted := mqlc.NewConfig(core_schema.Add(os_schema),
		mql.Features{byte(mql.ResourceContext), byte(mql.RootedNamespace)})
	rooted.AssetRoot = "os.linux"

	t.Run("members of the root resolve", func(t *testing.T) {
		for _, q := range []string{
			"hostname",
			"uptime",
			"packages.list.length",
			"users.list { name }",
			"selinux.mode",
			`file("/etc/hostname").exists`,
			"sshd.config.params",
		} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoError(t, err, q)
		}
	})

	// Core marks itself `@global`, which is the only way out of the tree.
	t.Run("marked globals still resolve", func(t *testing.T) {
		for _, q := range []string{"asset.platform", "time.now.unix", `regex.ipv4`} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoError(t, err, q)
		}
	})

	// The point of the mode: a resource outside this asset's tree stops
	// resolving instead of answering with an unset field.
	// `_` names the root itself. Compiling it by feeding the root's name back
	// through identifier resolution asked whether the root is a member of
	// itself, which under this mode is answered with "not part of this asset's
	// tree" - so `_.sshd` failed while bare `sshd` worked.
	t.Run("`_` is the root, not a name to resolve", func(t *testing.T) {
		for _, q := range []string{"_", "_.hostname", "_.sshd.config.params", "_ { hostname }"} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoError(t, err, q)
		}
	})

	// The root is what everything else hangs off, so it is never itself
	// recorded as reaching outside the tree.
	t.Run("the root is not noted as unrooted", func(t *testing.T) {
		res, err := mqlc.Compile("_.hostname", nil, rooted)
		require.NoError(t, err)
		assert.Empty(t, res.UnrootedResources)
	})

	t.Run("off-tree resources are rejected", func(t *testing.T) {
		_, err := mqlc.Compile("registrykey", nil, rooted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not part of this asset's tree")
	})

	// A root is no longer optional, so its absence is reported rather than
	// quietly resolving against the globals.
	t.Run("a root is required", func(t *testing.T) {
		noRoot := mqlc.NewConfig(core_schema.Add(os_schema),
			mql.Features{byte(mql.ResourceContext), byte(mql.RootedNamespace)})
		_, err := mqlc.Compile("packages.list.length", nil, noRoot)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs an asset root")
	})

	// Without the feature the same queries keep v14 behavior, which is what
	// makes the flag a way to try v15 rather than a switch that strands content.
	t.Run("v14 is unaffected", func(t *testing.T) {
		v14 := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
		v14.AssetRoot = "os.linux"
		_, err := mqlc.Compile("registrykey", nil, v14)
		assert.NoError(t, err, "the global namespace still answers in v14")
	})
}

// A label is what the author wrote. Reaching a member of the asset root costs
// chunks the author never typed - the root itself, and one hop per embed - and
// none of them belong in the label: `hostname` is `hostname`, the same way
// `sshd` is `sshd` whether or not `_` was spelled out. Asking for the root
// itself still labels it, because then it is the answer. See ADR 031.
func TestRootedLabels(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	conf.AssetRoot = "os.linux"

	labelOf := func(t *testing.T, q string) string {
		t.Helper()
		res, err := mqlc.Compile(q, nil, conf)
		require.NoError(t, err, q)
		require.Len(t, res.CodeV2.Entrypoints(), 1, q)
		checksum := res.CodeV2.Checksums[res.CodeV2.Entrypoints()[0]]
		return res.Labels.Labels[checksum]
	}

	for _, test := range []struct{ query, expected string }{
		// through the embed chain: os.linux -> unix -> base -> hostname
		{"hostname", "hostname"},
		{"_.hostname", "hostname"},
		{"uptime", "uptime"},
		// through an alias attached to a root, which compiles as a resource
		{"sshd.config.params.length", "sshd.config.params.length"},
		{"_.sshd.config.params.length", "sshd.config.params.length"},
		{"_.packages.list.length", "packages.list.length"},
		// the global spelling is unchanged, which is what keeps v14 output stable
		{"packages.list.length", "packages.list.length"},
		{"os.hostname", "os.hostname"},
		{"asset.platform", "asset.platform"},
		// and the root itself is still named when it is what was asked for
		{"_", "os.linux"},
	} {
		t.Run(test.query, func(t *testing.T) {
			assert.Equal(t, test.expected, labelOf(t, test.query))
		})
	}
}

// The shell suggests what it accepts. A bare member of the asset root compiles
// (`hostname`), so it has to be offered too - and reaching it through the root's
// embed chain must not hide it, which is what the asset-context gate on embedded
// fields used to do. See ADR 031.
func TestRootMemberSuggestions(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	conf.AssetRoot = "os.linux"

	suggestionsFor := func(t *testing.T, q string) []string {
		t.Helper()
		res, err := mqlc.Compile(q, nil, conf)
		require.Error(t, err, "a partial name does not compile; it is the suggestion case")
		out := []string{}
		for _, s := range res.GetSuggestions() {
			out = append(out, s.Field)
		}
		return out
	}

	// through the root's embed chain: os.linux -> os.unix -> os.base
	t.Run("inherited members", func(t *testing.T) {
		assert.Equal(t, []string{"hostname"}, suggestionsFor(t, "host"))
		assert.Equal(t, []string{"uptime"}, suggestionsFor(t, "upti"))
		assert.Equal(t, []string{"machineid"}, suggestionsFor(t, "mach"))
	})

	// through an alias attached to a root
	t.Run("attached resources", func(t *testing.T) {
		assert.Contains(t, suggestionsFor(t, "pack"), "packages")
	})

	// listing the root's members outright, which is what `_.<tab>` does
	t.Run("the whole root", func(t *testing.T) {
		all := suggestionsFor(t, "_.")
		assert.Contains(t, all, "hostname", "inherited from os.base")
		assert.Contains(t, all, "iptables", "declared on os.linux")
		assert.Contains(t, all, "packages", "attached by alias")
	})

	// Without a root there is nothing to inherit from, so the global namespace
	// answers alone - which is what every provider that declares no root gets.
	t.Run("no root, no root members", func(t *testing.T) {
		noRoot := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
		res, err := mqlc.Compile("host", nil, noRoot)
		require.Error(t, err)
		out := []string{}
		for _, s := range res.GetSuggestions() {
			out = append(out, s.Field)
		}
		assert.NotContains(t, out, "hostname")
	})
}

// Narrowing derives applicability from what a query reads (ADR 031 point 4):
// compiled against the union of roots, the bundle records which of them can
// actually run it. That is the job a hand-written platform filter does today.
func TestRootNarrowing(t *testing.T) {
	union := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	union.AssetRoot = "os.any"

	rootsFor := func(t *testing.T, q string) []string {
		t.Helper()
		res, err := mqlc.Compile(q, nil, union)
		require.NoError(t, err, q)
		return res.CompatibleRoots
	}

	t.Run("universal members stay portable", func(t *testing.T) {
		assert.Equal(t,
			[]string{"os.base", "os.linux", "os.macos", "os.unix", "os.windows"},
			rootsFor(t, "_.hostname"),
			"the union is not listed: no connection reports it, and it carries everything")
	})

	t.Run("a platform member narrows to its family", func(t *testing.T) {
		assert.Equal(t, []string{"os.linux"}, rootsFor(t, "_.iptables.output"))
		assert.Equal(t, []string{"os.windows"}, rootsFor(t, "_.registrykey"))
		assert.Equal(t, []string{"os.macos"}, rootsFor(t, "_.launchd"))
		// sshd is a unix-family facility, so macOS qualifies and Windows does not
		assert.Equal(t, []string{"os.linux", "os.macos", "os.unix"},
			rootsFor(t, "_.sshd.config.params"))
	})

	t.Run("the narrowest member wins", func(t *testing.T) {
		assert.Equal(t, []string{"os.linux"},
			rootsFor(t, "_ { hostname iptables.output }"), "reads inside a block narrow too")
	})

	// The global namespace says nothing about which asset a query is about, so
	// v14 content that never touches a root carries no requirement and keeps
	// running everywhere.
	t.Run("global reads derive nothing", func(t *testing.T) {
		assert.Empty(t, rootsFor(t, "packages.list.length"))
		assert.Empty(t, rootsFor(t, "asset.platform"))
	})

	// Deliberately cross-platform content - one branch per platform - has no
	// single root that carries everything. Refusing it, or marking it runnable
	// nowhere, would break that pattern, so it records no requirement and each
	// member degrades on the platform that lacks it.
	t.Run("content spanning platforms records no requirement", func(t *testing.T) {
		assert.Empty(t, rootsFor(t, "_ { iptables.output registrykey }"))
	})
}

// SupportsRoot is the other half: it turns the recorded set into a decision
// about one asset, and it does not withhold on weak evidence.
func TestSupportsRoot(t *testing.T) {
	narrowed := &llx.CodeBundle{AssetRoot: "os.any", CompatibleRoots: []string{"os.linux"}}

	assert.True(t, mqlc.SupportsRoot(narrowed, "os.linux"))
	assert.False(t, mqlc.SupportsRoot(narrowed, "os.windows"))

	t.Run("no requirement runs anywhere", func(t *testing.T) {
		assert.True(t, mqlc.SupportsRoot(&llx.CodeBundle{}, "os.windows"))
	})

	// A provider that has not refined its root per connection reports the union
	// it declared, which is what the content was compiled against.
	t.Run("the compile-time root is always compatible", func(t *testing.T) {
		assert.True(t, mqlc.SupportsRoot(narrowed, "os.any"))
	})

	t.Run("an unknown root is not refused", func(t *testing.T) {
		assert.True(t, mqlc.SupportsRoot(narrowed, ""),
			"not knowing the root is not evidence of a mismatch")
	})
}

// Completion compiles the partial input on every keystroke, so anything the
// compiler prints lands in the middle of the shell UI. Typing `os` used to be
// enough: it resolves the deprecated `os` resource, which hangs off no root, and
// the note about that was logged as well as recorded. The note belongs on the
// bundle - what to show, and when, is the caller's call.
func TestUnrootedNoteIsRecordedNotLogged(t *testing.T) {
	conf := mqlc.NewConfig(core_schema.Add(os_schema), mql.Features{byte(mql.ResourceContext)})
	conf.AssetRoot = "os.linux"

	var logged bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&logged).Level(zerolog.DebugLevel)
	defer func() { log.Logger = previous }()

	res, err := mqlc.Compile("os", nil, conf)
	require.NoError(t, err)

	assert.Equal(t, []string{"os"}, res.UnrootedResources, "the note is on the bundle")
	assert.Empty(t, logged.String(), "and nothing was written to the log while compiling it")
}

// A field that exists on other roots is a statement about which assets a query
// targets, not a failure. A caller running over several assets has to be able to
// tell the two apart - it should skip an asset the query does not apply to and
// keep the ones it does - so the compile error carries that distinction as a
// type, not only as prose.
func TestRootScopeMissIsTypedAsAMismatch(t *testing.T) {
	schema := provenanceSchema(t)
	conf := mqlc.NewConfig(schema, mql.Features{})
	conf.AssetRoot = "os.linux"

	t.Run("a field that lives on another root", func(t *testing.T) {
		_, err := mqlc.Compile("_.registrykey", nil, conf)
		require.Error(t, err)
		assert.ErrorIs(t, err, mqlc.ErrRootMismatch)
		// The message still says the useful thing; the type is additional.
		assert.Contains(t, err.Error(), "this asset is rooted at os.linux")
		assert.Contains(t, err.Error(), "os.windows")
	})

	// A name no root carries is a real failure and must not be skipped over:
	// treating it as "not for this asset" would silently drop every asset in a
	// run over a typo.
	t.Run("a field no root has", func(t *testing.T) {
		_, err := mqlc.Compile("_.thisFieldDoesNotExistAnywhere", nil, conf)
		require.Error(t, err)
		assert.NotErrorIs(t, err, mqlc.ErrRootMismatch)
	})
}

// A name can be both a member of the root and a resource you construct with a
// target, and the two are told apart by arity.
//
// `network.host.tls` hands back the TLS endpoint of the host you connected to;
// the `tls` resource points anywhere you give it. Under RootedNamespace the
// member is found first, so without this the member swallowed the call and
// `tls("example.com")` failed with "cannot call field with arguments" - a
// capability that worked in v14 and would have gone missing in v15.
//
// This is the same disambiguation type conversions get: an interpretation that
// cannot serve the call declines instead of failing on it.
func TestRootedNamespaceKeepsConstructibleResources(t *testing.T) {
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "network"})
	core := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"})
	merged := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	merged.Add(schema)
	merged.Add(core)

	rooted := mqlc.NewConfig(merged, mql.Features{byte(mql.ResourceContext), byte(mql.RootedNamespace)})
	rooted.AssetRoot = "network.host"

	t.Run("called with a target, it is the resource", func(t *testing.T) {
		for _, q := range []string{
			`tls("example.com").versions`,
			`dns("example.com").fqdn`,
			`domainName("sub.example.co.uk").tld`,
		} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoErrorf(t, err, q)
		}
	})

	t.Run("bare, it is the member of the connected host", func(t *testing.T) {
		for _, q := range []string{"tls.versions", "dns.fqdn", "domainName.tld", "_.tls.versions"} {
			_, err := mqlc.Compile(q, nil, rooted)
			assert.NoErrorf(t, err, q)
		}
	})

	// A member that *is* an implicit resource does take the arguments through
	// to its init, and must keep doing so - that is how `_.file("/x")` works.
	t.Run("an implicit member still takes its arguments", func(t *testing.T) {
		osSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"})
		m := &resources.Schema{
			Resources:    map[string]*resources.ResourceInfo{},
			Dependencies: map[string]*resources.ProviderInfo{},
		}
		m.Add(osSchema)
		m.Add(core)
		osRooted := mqlc.NewConfig(m, mql.Features{byte(mql.ResourceContext), byte(mql.RootedNamespace)})
		osRooted.AssetRoot = "os.linux"

		for _, q := range []string{`file("/etc/hostname").exists`, `_.file("/etc/hostname").exists`} {
			_, err := mqlc.Compile(q, nil, osRooted)
			assert.NoErrorf(t, err, q)
		}
	})
}
