// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// TestGetCtyValue_UnknownFunctionSurfacesReferences is a regression test for
// arguments() returning an EMPTY list for any expression built with a function
// the evaluator does not register.
//
// The function table carries only jsondecode/jsonencode, so `format`, `merge`,
// `join`, `lookup`, `try`, `coalesce`, ... all fail evaluation with "Call to
// unknown function". The FunctionCallExpr arm returned its empty results slice
// on that failure with no reference fallback (unlike ScopeTraversalExpr and
// ConditionalExpr, which do surface references), so `arguments["tags"]` came
// back as `[]` and a tag-governance check saw nothing to complain about.
func TestGetCtyValue_UnknownFunctionSurfacesReferences(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		attrs := parseAttrs(t, `bucket = format("%s-logs", local.env)`)
		got, err := hclResolvedAttributesToDict(attrs, nil)
		require.NoError(t, err)
		assert.True(t, containsString(got["bucket"], "local.env"),
			"an unresolvable function call must still surface its argument references, got: %#v", got["bucket"])
	})

	t.Run("merge", func(t *testing.T) {
		attrs := parseAttrs(t, `tags = merge(var.common_tags, { Name = "x" })`)
		got, err := hclResolvedAttributesToDict(attrs, nil)
		require.NoError(t, err)
		require.NotEmpty(t, got["tags"], "merge() must not resolve to an empty value")
		assert.True(t, containsString(got["tags"], "var.common_tags"),
			"merge() must surface var.common_tags, got: %#v", got["tags"])
		assert.True(t, containsString(got["tags"], "x"),
			"merge() must surface the inline tag value, got: %#v", got["tags"])
	})

	t.Run("nested", func(t *testing.T) {
		attrs := parseAttrs(t, `name = join("-", [var.prefix, lookup(local.names, "primary")])`)
		got, err := hclResolvedAttributesToDict(attrs, nil)
		require.NoError(t, err)
		assert.True(t, containsString(got["name"], "var.prefix"),
			"nested function calls must surface references, got: %#v", got["name"])
		assert.True(t, containsString(got["name"], "local.names"),
			"nested function calls must surface references, got: %#v", got["name"])
	})
}

// TestGetCtyValue_JsonencodeStillResolves guards the registered-function path
// against the reference fallback added above: a call that DOES evaluate must
// keep returning its value, not its argument references.
func TestGetCtyValue_JsonencodeStillResolves(t *testing.T) {
	attrs := parseAttrs(t, `policy = jsonencode({ Version = "2012-10-17" })`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	list, ok := got["policy"].([]any)
	require.True(t, ok, "expected a list-wrapped map, got: %#v", got["policy"])
	require.Len(t, list, 1)
	assert.Equal(t, "2012-10-17", list[0].(map[string]any)["Version"])
}

// TestGetCtyValue_OperatorsEvaluateToTheirResult is a regression test for
// BinaryOpExpr, ForExpr, IndexExpr and SplatExpr returning their OPERANDS
// rather than the computed result.
//
// ConditionalExpr and UnaryOpExpr already try t.Value(ctx) first and only fall
// back to reference-surfacing; these four never did. So `8080 + 1` read as
// [8080, 1] instead of 8081 and `8080 > 80` read as [8080, 80] instead of true,
// which defeats every scalar comparison a policy writes against them.
func TestGetCtyValue_OperatorsEvaluateToTheirResult(t *testing.T) {
	t.Run("binary arithmetic", func(t *testing.T) {
		attrs := parseAttrs(t, `sum = 8080 + 1`)
		got, err := hclResolvedAttributesToDict(attrs, nil)
		require.NoError(t, err)
		assert.Equal(t, float64(8081), got["sum"])
	})

	t.Run("binary comparison", func(t *testing.T) {
		attrs := parseAttrs(t, `cmp = 8080 > 80`)
		got, err := hclResolvedAttributesToDict(attrs, nil)
		require.NoError(t, err)
		assert.Equal(t, true, got["cmp"])
	})

	t.Run("binary over resolved locals", func(t *testing.T) {
		attrs := parseAttrs(t, `open = local.port == 22`)
		ctx := resolvingCtx(nil, map[string]cty.Value{"port": cty.NumberIntVal(22)})
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		assert.Equal(t, true, got["open"])
	})

	t.Run("for expression", func(t *testing.T) {
		attrs := parseAttrs(t, `forx = [for p in local.list : p + 1]`)
		ctx := resolvingCtx(nil, map[string]cty.Value{
			"list": cty.TupleVal([]cty.Value{cty.NumberIntVal(10), cty.NumberIntVal(20)}),
		})
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		assert.Equal(t, []any{float64(11), float64(21)}, got["forx"])
	})

	t.Run("index expression", func(t *testing.T) {
		attrs := parseAttrs(t, `dyn = local.m[local.k]`)
		ctx := resolvingCtx(nil, map[string]cty.Value{
			"m": cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1), "b": cty.NumberIntVal(2)}),
			"k": cty.StringVal("a"),
		})
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		assert.Equal(t, float64(1), got["dyn"])
	})

	t.Run("splat expression", func(t *testing.T) {
		attrs := parseAttrs(t, `ids = local.items[*].id`)
		ctx := resolvingCtx(nil, map[string]cty.Value{
			"items": cty.TupleVal([]cty.Value{
				cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("one")}),
				cty.ObjectVal(map[string]cty.Value{"id": cty.StringVal("two")}),
			}),
		})
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		assert.Equal(t, []any{"one", "two"}, got["ids"])
	})
}

// TestGetCtyValue_OperatorsKeepReferenceFallback guards the other half: when an
// operand cannot be evaluated the arms must keep surfacing references rather
// than collapsing to nil.
func TestGetCtyValue_OperatorsKeepReferenceFallback(t *testing.T) {
	cases := map[string]struct{ src, ref string }{
		"binary": {`match = var.availability_zone == "account_based"`, "var.availability_zone"},
		"index":  {`subnet_id = local.subnet_id_by_az_suffix[local.az_suffix]`, "local.subnet_id_by_az_suffix"},
		"splat":  {`instance_ids = data.aws_instances.all[*].id`, "data.aws_instances.all"},
		"for":    {`sg_ids = [for sg in data.aws_security_group.ec2 : sg.id]`, "data.aws_security_group.ec2"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			attrs := parseAttrs(t, tc.src)
			got, err := hclResolvedAttributesToDict(attrs, nil)
			require.NoError(t, err)
			for _, v := range got {
				assert.True(t, containsString(v, tc.ref),
					"unresolvable %s expression must still surface %s, got: %#v", name, tc.ref, v)
			}
		})
	}
}

// TestGetCtyValue_UnknownStringDoesNotPanic hardens the three AsString() call
// sites against unknown cty values. cty.Value.AsString panics on a null AND on
// an unknown value, and an unknown one reaches these paths whenever a function
// can be resolved but one of its arguments cannot.
func TestGetCtyValue_UnknownStringDoesNotPanic(t *testing.T) {
	// `jsonencode(var.x)` with an unknown var evaluates to an UNKNOWN string
	// with no diagnostic at all — the exact shape that panics on AsString().
	attrs := parseAttrs(t, `policy = jsonencode(var.unknown_input)`)
	ctx := resolvingCtx(map[string]cty.Value{"unknown_input": cty.UnknownVal(cty.String)}, nil)

	require.NotPanics(t, func() {
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		_ = got["policy"]
	})
}

// TestGetCtyValue_UnknownTemplateDoesNotPanic covers the TemplateExpr
// AsString() call site with the same unknown-value shape.
func TestGetCtyValue_UnknownTemplateDoesNotPanic(t *testing.T) {
	attrs := parseAttrs(t, `name = "app-${var.env}-bucket"`)
	ctx := resolvingCtx(map[string]cty.Value{"env": cty.UnknownVal(cty.String)}, nil)

	require.NotPanics(t, func() {
		got, err := hclResolvedAttributesToDict(attrs, ctx)
		require.NoError(t, err)
		assert.NotNil(t, got["name"], "an unknown interpolation must still surface something")
	})
}
