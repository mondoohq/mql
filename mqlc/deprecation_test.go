// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func deprecatedUses(res *llx.CodeBundle) map[string]string {
	out := map[string]string{}
	for _, d := range res.DeprecatedUses {
		out[d.From] = d.To
	}
	return out
}

// `os.hostname` is deprecated in favor of `os.base.hostname` (ADR 031/040). The
// bundle has to say so as data -- the compiler runs per keystroke behind
// autocomplete, so it cannot be the thing that talks to the user.
func TestDeprecationRecordsTheReplacement(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `os.hostname`)
	uses := deprecatedUses(res)
	assert.Equal(t, "os.base.hostname", uses["os.hostname"])
	// The resource is deprecated too, and both are recorded. Collapsing the
	// two into one notice is the renderer's call, not the compiler's.
	assert.Equal(t, "os.base", uses["os"])
}

// The destination is not itself deprecated, so reading it says nothing.
func TestDeprecationSaysNothingAboutTheReplacement(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `os.base.hostname`)
	assert.Empty(t, res.DeprecatedUses)
}

// A name used more than once is one notice, and the order is the query's.
func TestDeprecationDedupesAndKeepsUseOrder(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `os { hostname machineid hostname }`)
	var from []string
	for _, d := range res.DeprecatedUses {
		from = append(from, d.From)
	}
	assert.Equal(t, []string{"os", "os.hostname", "os.machineid"}, from)
}

// Nothing else in the tree carries a replacement target yet, so ordinary
// queries stay silent. A deprecation with no destination has nothing
// actionable to say and is deliberately not recorded.
func TestDeprecationIsSilentWithoutATarget(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `sshd.config.params`)
	assert.Empty(t, res.DeprecatedUses)
}

// The annotation stores `os.base.hostname`; a user under an OS root types
// `hostname`. The message has to say the second one, or it points at something
// that will not compile in v15.
func TestDeprecationRendersRelativeToTheRoot(t *testing.T) {
	schema := provenanceSchema(t)

	for _, root := range []string{"os.any", "os.linux", "os.unix", "os.windows", "os.macos"} {
		t.Run(root, func(t *testing.T) {
			assert.Equal(t, "hostname", mqlc.RelativeToRoot(schema, root, "os.base.hostname"))
			// The root target itself is what `_` means.
			assert.Equal(t, "_", mqlc.RelativeToRoot(schema, root, "os.base"))
		})
	}
}

// Without a root there is nothing to shorten against, and a shortened name
// that does not resolve would be worse than a long one that does.
func TestDeprecationKeepsThePathWhenItCannotShorten(t *testing.T) {
	schema := provenanceSchema(t)

	assert.Equal(t, "os.base.hostname", mqlc.RelativeToRoot(schema, "", "os.base.hostname"))
	// A root that cannot reach the target leaves it alone. `sshd.config` is not
	// in any root's embed chain.
	assert.Equal(t, "sshd.config.params", mqlc.RelativeToRoot(schema, "os.any", "sshd.config.params"))
	assert.Equal(t, "os.base.nosuchfield", mqlc.RelativeToRoot(schema, "os.any", "os.base.nosuchfield"))
}

func TestDeprecationNotices(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `os.hostname`)
	assert.Equal(t, []string{
		"os.hostname has migrated to os.base.hostname",
	}, mqlc.DeprecationNotices(res, schema), "no root: the schema path is the honest answer")

	res.AssetRoot = "os.linux"
	assert.Equal(t, []string{
		"os.hostname has migrated to hostname",
	}, mqlc.DeprecationNotices(res, schema))

	assert.Nil(t, mqlc.DeprecationNotices(compileForProvenance(t, schema, `os.base.hostname`), schema))
}

// The resource is deprecated too, but saying so alongside the field notice is
// saying the same thing twice. Only the most specific one is shown; the
// resource notice is what a query naming only the resource gets.
func TestDeprecationShowsOnlyTheMostSpecificNotice(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `os { hostname machineid }`)
	res.AssetRoot = "os.linux"
	assert.Equal(t, []string{
		"os.hostname has migrated to hostname",
		"os.machineid has migrated to machineid",
	}, mqlc.DeprecationNotices(res, schema))

	bare := compileForProvenance(t, schema, `os`)
	bare.AssetRoot = "os.linux"
	assert.Equal(t, []string{"os has migrated to _"}, mqlc.DeprecationNotices(bare, schema))
}

// Against the real os schema, not a fixture: `sshd.config` is reachable because
// `_.sshd` is a member of a root, while `os` is the bridging namespace node
// nothing points at - which is precisely why `os.hostname` stops resolving in
// v15 and why these annotations exist.
func TestRootReachabilityOnTheRealSchema(t *testing.T) {
	schema := provenanceSchema(t)

	assert.True(t, resources.RootReachable(schema, "os.base"), "the universal root")
	assert.True(t, resources.RootReachable(schema, "sshd.config"), "reached as _.sshd.config")
	assert.True(t, resources.RootReachable(schema, "os.update"), "reached as the element of _.updates")
	assert.False(t, resources.RootReachable(schema, "os"), "the namespace node nothing hangs off")
}
