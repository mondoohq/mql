// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
)

func blockWithLabels(labels ...string) *mqlTerraformBlock {
	data := make([]any, len(labels))
	for i, l := range labels {
		data[i] = l
	}
	b := &mqlTerraformBlock{}
	b.Labels = plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
	return b
}

func TestBlockResourceTypeAndName(t *testing.T) {
	// resource "aws_instance" "web" { ... }
	b := blockWithLabels("aws_instance", "web")
	rt, err := b.resourceType()
	require.NoError(t, err)
	assert.Equal(t, "aws_instance", rt)
	rn, err := b.resourceName()
	require.NoError(t, err)
	assert.Equal(t, "web", rn)

	// resourceType mirrors nameLabel (first label)
	nl, err := b.nameLabel()
	require.NoError(t, err)
	assert.Equal(t, nl, rt)

	// Blocks without a second label (e.g. provider blocks) yield an empty name.
	single := blockWithLabels("aws")
	rn, err = single.resourceName()
	require.NoError(t, err)
	assert.Equal(t, "", rn)
	rt, err = single.resourceType()
	require.NoError(t, err)
	assert.Equal(t, "aws", rt)

	// Blocks with no labels yield empty strings rather than panicking.
	none := blockWithLabels()
	rt, err = none.resourceType()
	require.NoError(t, err)
	assert.Equal(t, "", rt)
	rn, err = none.resourceName()
	require.NoError(t, err)
	assert.Equal(t, "", rn)
}

// TestHclResources_NoParser_DoNotPanic is a regression test for
// https://github.com/mondoohq/mql/issues/2970: the terraform.files,
// terraform.file.blocks and terraform.module.block resources used to
// dereference a nil *hclparse.Parser and crash the provider on plan and
// state assets (which have no HCL parser). They must now return empty
// results instead of panicking.
func TestHclResources_NoParser_DoNotPanic(t *testing.T) {
	// A zero-value Connection mirrors what NewPlanConnection / NewStateConnection
	// produce: no HCL parser is set, so Parser() returns nil.
	runtime := &plugin.Runtime{Connection: &connection.Connection{}}

	t.Run("terraform.files", func(t *testing.T) {
		tf := &mqlTerraform{}
		tf.MqlRuntime = runtime
		files, err := tf.files()
		require.NoError(t, err)
		assert.Empty(t, files)
	})

	t.Run("terraform.file.blocks", func(t *testing.T) {
		file := &mqlTerraformFile{}
		file.MqlRuntime = runtime
		file.Path = plugin.TValue[string]{Data: "main.tf", State: plugin.StateIsSet}
		blocks, err := file.blocks()
		require.NoError(t, err)
		assert.Empty(t, blocks)
	})

	t.Run("terraform.module.block", func(t *testing.T) {
		module := &mqlTerraformModule{}
		module.MqlRuntime = runtime
		module.Key = plugin.TValue[string]{Data: "vpc", State: plugin.StateIsSet}
		block, err := module.block()
		require.NoError(t, err)
		assert.Nil(t, block)
		// The accessor must mark the field resolved-and-null so the runtime
		// does not re-fetch indefinitely.
		assert.True(t, module.Block.State&plugin.StateIsNull != 0)
	})
}

// parseAttrs parses an HCL snippet and returns the top-level attributes.
// The snippet must contain attribute definitions only (no blocks).
func parseAttrs(t *testing.T, src string) map[string]*hcl.Attribute {
	t.Helper()
	f, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "parse errors: %s", diags.Error())
	attrs, diags := f.Body.JustAttributes()
	require.False(t, diags.HasErrors(), "attribute errors: %s", diags.Error())
	return attrs
}

// containsString reports whether v (which may be a string, []any, or nested
// list) contains the given string anywhere in its tree.
func containsString(v any, target string) bool {
	switch x := v.(type) {
	case string:
		return x == target
	case []any:
		for _, item := range x {
			if containsString(item, target) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if containsString(item, target) {
				return true
			}
		}
	}
	return false
}

// TestGetCtyValue_ForExpr_Tuple verifies that tuple-form for-expressions
// like `[for sg in data.x : sg.id]` return the references they contain
// instead of triggering an "unknown type *hclsyntax.ForExpr" warning and
// nil result.
func TestGetCtyValue_ForExpr_Tuple(t *testing.T) {
	attrs := parseAttrs(t, `vpc_security_group_ids = [for sg in data.aws_security_group.ec2 : sg.id]`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["vpc_security_group_ids"]
	require.NotNil(t, v, "for-expression should not return nil")
	assert.True(t, containsString(v, "data.aws_security_group.ec2"),
		"result should reference data.aws_security_group.ec2, got: %#v", v)
}

// TestGetCtyValue_ForExpr_Object verifies that object-form for-expressions
// like `{ for k in coll : k => f(k) }` return a map with the references they
// contain.
func TestGetCtyValue_ForExpr_Object(t *testing.T) {
	attrs := parseAttrs(t, `
subnet_id_by_az_suffix = {
  for zone in ["a", "b"] :
  zone => data.aws_subnet.ec2[zone].id
}
`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["subnet_id_by_az_suffix"]
	require.NotNil(t, v, "object for-expression should not return nil")
	assert.True(t, containsString(v, "data.aws_subnet.ec2"),
		"result should reference data.aws_subnet.ec2, got: %#v", v)
}

// TestGetCtyValue_JsonencodeList is a regression test for #9079: a top-level
// `jsonencode([...])` list argument decoded into a map[string]any, which fails
// for a JSON array, leaving the argument empty so a check iterating the encoded
// list passed vacuously. The encoded list must surface as an iterable list.
func TestGetCtyValue_JsonencodeList(t *testing.T) {
	attrs := parseAttrs(t, `container_definitions = jsonencode([{ name = "app", image = "x", privileged = true }])`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	list, ok := got["container_definitions"].([]any)
	require.True(t, ok, "expected a list, got: %#v", got["container_definitions"])
	require.Len(t, list, 1)
	elem, ok := list[0].(map[string]any)
	require.True(t, ok, "expected a map element, got: %#v", list[0])
	assert.Equal(t, "app", elem["name"])
	assert.Equal(t, true, elem["privileged"])
}

// TestGetCtyValue_JsonencodeMap verifies the object form still resolves
// (list-wrapped, indexable via `.first`) after the list fix.
func TestGetCtyValue_JsonencodeMap(t *testing.T) {
	attrs := parseAttrs(t, `policy = jsonencode({ Version = "2012-10-17", Effect = "Allow" })`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	list, ok := got["policy"].([]any)
	require.True(t, ok, "expected a list-wrapped map, got: %#v", got["policy"])
	require.Len(t, list, 1)
	elem, ok := list[0].(map[string]any)
	require.True(t, ok, "expected a map element, got: %#v", list[0])
	assert.Equal(t, "Allow", elem["Effect"])
}

// TestGetCtyValue_ConditionalExpr_UnboundVars verifies that ternaries
// involving unbound variables return the references in the branches instead
// of an empty list.
func TestGetCtyValue_ConditionalExpr_UnboundVars(t *testing.T) {
	attrs := parseAttrs(t, `ami_id = var.disaster_recovery_mode ? var.disaster_recovery_ami_id : data.aws_ami.shared_image.id`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["ami_id"]
	require.NotNil(t, v, "conditional should not return nil")
	assert.True(t, containsString(v, "var.disaster_recovery_mode"),
		"result should reference var.disaster_recovery_mode, got: %#v", v)
	assert.True(t, containsString(v, "var.disaster_recovery_ami_id"),
		"result should reference var.disaster_recovery_ami_id, got: %#v", v)
	assert.True(t, containsString(v, "data.aws_ami.shared_image.id"),
		"result should reference data.aws_ami.shared_image.id, got: %#v", v)
}

// TestGetCtyValue_NegativeNumber is a regression test for #9080: a negative
// numeric literal parses as a unary-negate op wrapping a number literal, and
// must retain its sign instead of collapsing to the positive magnitude (which
// broke checks comparing against a negative sentinel, e.g. Lambda's `-1`
// "unreserved" value or a security-group protocol of `-1`).
func TestGetCtyValue_NegativeNumber(t *testing.T) {
	attrs := parseAttrs(t, `reserved_concurrent_executions = -1`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	assert.Equal(t, float64(-1), got["reserved_concurrent_executions"])
}

// TestGetCtyValue_LogicalNot verifies the other unary operator (`!`) is applied
// rather than dropped.
func TestGetCtyValue_LogicalNot(t *testing.T) {
	attrs := parseAttrs(t, `disabled = !true`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	assert.Equal(t, false, got["disabled"])
}

// TestGetCtyValue_UnaryOp_UnboundOperand verifies a unary op over an unbound
// operand (e.g. `-var.x`) still surfaces the operand's references instead of
// failing, preserving the reference-surfacing fallback.
func TestGetCtyValue_UnaryOp_UnboundOperand(t *testing.T) {
	attrs := parseAttrs(t, `capacity = -var.desired_capacity`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	assert.True(t, containsString(got["capacity"], "var.desired_capacity"),
		"result should reference var.desired_capacity, got: %#v", got["capacity"])
}

// resolvingCtx builds an eval context with resolved var.*/local.* values,
// mimicking what Connection.VariableEvalContext produces for an HCL asset.
func resolvingCtx(vars, locals map[string]cty.Value) *hcl.EvalContext {
	ctx := &hcl.EvalContext{Functions: hclFunctions(), Variables: map[string]cty.Value{}}
	if len(vars) > 0 {
		ctx.Variables["var"] = cty.ObjectVal(vars)
	}
	if len(locals) > 0 {
		ctx.Variables["local"] = cty.ObjectVal(locals)
	}
	return ctx
}

// TestResolveVariables_Scalar verifies that a var.* reference resolves to the
// variable's effective value when the resolving context is supplied.
func TestResolveVariables_Scalar(t *testing.T) {
	attrs := parseAttrs(t, `acl = var.bucket_acl`)
	ctx := resolvingCtx(map[string]cty.Value{"bucket_acl": cty.StringVal("public-read")}, nil)
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)
	assert.Equal(t, "public-read", got["acl"])
}

// TestResolveVariables_Local verifies local.* references resolve too.
func TestResolveVariables_Local(t *testing.T) {
	attrs := parseAttrs(t, `acl = local.acl`)
	ctx := resolvingCtx(nil, map[string]cty.Value{"acl": cty.StringVal("private")})
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)
	assert.Equal(t, "private", got["acl"])
}

// TestResolveVariables_Types verifies non-string cty values convert to the
// expected Go types (bool, number, list).
func TestResolveVariables_Types(t *testing.T) {
	ctx := resolvingCtx(map[string]cty.Value{
		"enabled": cty.False,
		"port":    cty.NumberIntVal(22),
		"cidrs":   cty.ListVal([]cty.Value{cty.StringVal("0.0.0.0/0")}),
		"tags":    cty.ObjectVal(map[string]cty.Value{"env": cty.StringVal("prod")}),
	}, nil)
	attrs := parseAttrs(t, `
encrypted   = var.enabled
from_port   = var.port
cidr_blocks = var.cidrs
env         = var.tags.env
`)
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)
	assert.Equal(t, false, got["encrypted"])
	assert.Equal(t, float64(22), got["from_port"])
	assert.Equal(t, []any{"0.0.0.0/0"}, got["cidr_blocks"])
	assert.Equal(t, "prod", got["env"], "nested attribute access should resolve")
}

// TestResolveVariables_Fallback verifies that an unresolvable reference (no
// such variable, or a data/resource ref) still falls back to the reference
// string even when a resolving context is supplied.
func TestResolveVariables_Fallback(t *testing.T) {
	ctx := resolvingCtx(map[string]cty.Value{"bucket_acl": cty.StringVal("public-read")}, nil)

	missing := parseAttrs(t, `acl = var.missing`)
	got, err := hclResolvedAttributesToDict(missing, ctx)
	require.NoError(t, err)
	assert.Equal(t, "var.missing", got["acl"], "unknown var should fall back to reference string")

	dataRef := parseAttrs(t, `ami = data.aws_ami.x.id`)
	got, err = hclResolvedAttributesToDict(dataRef, ctx)
	require.NoError(t, err)
	assert.True(t, containsString(got["ami"], "data.aws_ami.x.id"),
		"data references must still surface as a reference string, got: %#v", got["ami"])
}

// TestResolveVariables_TemplateInterpolation verifies a var embedded in a
// string template resolves the whole string.
func TestResolveVariables_TemplateInterpolation(t *testing.T) {
	ctx := resolvingCtx(map[string]cty.Value{"env": cty.StringVal("prod")}, nil)
	attrs := parseAttrs(t, `name = "app-${var.env}-bucket"`)
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)
	assert.Equal(t, "app-prod-bucket", got["name"])
}

// TestGetCtyValue_IndexExpr verifies that index expressions
// like `m[k]` traverse into both the collection and the key.
func TestGetCtyValue_IndexExpr(t *testing.T) {
	attrs := parseAttrs(t, `subnet_id = local.subnet_id_by_az_suffix[local.az_suffix]`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["subnet_id"]
	require.NotNil(t, v, "index expression should not return nil")
	assert.True(t, containsString(v, "local.subnet_id_by_az_suffix"),
		"result should reference local.subnet_id_by_az_suffix, got: %#v", v)
}

// TestGetCtyValue_BinaryOp verifies binary comparisons
// like `var.x == "y"` surface their operand references.
func TestGetCtyValue_BinaryOp(t *testing.T) {
	attrs := parseAttrs(t, `match = var.availability_zone == "account_based"`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["match"]
	require.NotNil(t, v, "binary op expression should not return nil")
	assert.True(t, containsString(v, "var.availability_zone"),
		"result should reference var.availability_zone, got: %#v", v)
}

// TestGetCtyValue_RelativeTraversal verifies that relative traversals
// (e.g. result of an index/splat followed by `.field`) flow through.
func TestGetCtyValue_RelativeTraversal(t *testing.T) {
	attrs := parseAttrs(t, `first_id = random_shuffle.ec2.result[0]`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["first_id"]
	require.NotNil(t, v, "relative traversal should not return nil")
	assert.True(t, containsString(v, "random_shuffle.ec2.result"),
		"result should reference random_shuffle.ec2.result, got: %#v", v)
}

// TestGetCtyValue_SplatExpr verifies that splat expressions like
// `data.aws_instances.all[*].id` surface the source reference.
func TestGetCtyValue_SplatExpr(t *testing.T) {
	attrs := parseAttrs(t, `instance_ids = data.aws_instances.all[*].id`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	v := got["instance_ids"]
	require.NotNil(t, v, "splat expression should not return nil")
	assert.True(t, containsString(v, "data.aws_instances.all"),
		"result should reference data.aws_instances.all, got: %#v", v)
}

// TestGetCtyValue_StaticTernaryStillEvaluates verifies that conditionals
// that *can* be evaluated to a string still resolve the same way as before
// — we only fall back to reference collection when evaluation fails.
func TestGetCtyValue_StaticTernaryStillEvaluates(t *testing.T) {
	attrs := parseAttrs(t, `pick = true ? "yes" : "no"`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	assert.True(t, containsString(got["pick"], "yes"),
		"static ternary should evaluate to 'yes', got: %#v", got["pick"])
}

// TestGetCtyValue_BoolTernary_Resolved is a regression test for #9078: a
// ternary that resolves to a non-string (the natural `... ? true : false`
// output) used to fall through to reference-surfacing and return the branch
// list instead of the scalar, so a `!= true` scalar-equality check never
// matched. With var defaults in the context it must resolve to the scalar.
func TestGetCtyValue_BoolTernary_Resolved(t *testing.T) {
	attrs := parseAttrs(t, `privileged_mode = var.privileged ? true : false`)
	ctx := resolvingCtx(map[string]cty.Value{"privileged": cty.True}, nil)
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, got["privileged_mode"])
}

// TestGetCtyValue_StaticBoolTernary verifies a statically-knowable bool ternary
// resolves to the scalar even without any variable context.
func TestGetCtyValue_StaticBoolTernary(t *testing.T) {
	attrs := parseAttrs(t, `enabled = true ? false : true`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)
	assert.Equal(t, false, got["enabled"])
}

// TestHclAttributesToDict_NoUnknownTypeWarning regression-tests the customer
// case: parsing a file with for-expressions, conditionals and index
// expressions must not panic, must not return nil for any attribute, and
// must surface the references inside.
func TestHclAttributesToDict_CustomerFile(t *testing.T) {
	src := `
locals {
  subnet_id_by_az_suffix = {
    for zone in ["a", "b"] :
    zone => one([for subnet_id in data.aws_subnets.ec2.ids : subnet_id if endswith(data.aws_subnet.ec2[subnet_id].availability_zone, zone)])
  }
  ami_id = var.disaster_recovery_mode ? var.disaster_recovery_ami_id : data.aws_ami.shared_image.id
}
`
	f, diags := hclsyntax.ParseConfig([]byte(src), "customer.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), diags.Error())

	body, ok := f.Body.(*hclsyntax.Body)
	require.True(t, ok)
	require.Len(t, body.Blocks, 1)
	localsBlock := body.Blocks[0]

	hclAttrs := map[string]*hcl.Attribute{}
	for name, a := range localsBlock.Body.Attributes {
		hclAttrs[name] = a.AsHCLAttribute()
	}
	dict, err := hclAttributesToDict(hclAttrs, nil)
	require.NoError(t, err)

	require.NotNil(t, dict["subnet_id_by_az_suffix"])
	require.NotNil(t, dict["ami_id"])

	amiVal := dict["ami_id"].(map[string]any)["value"]
	assert.True(t, containsString(amiVal, "var.disaster_recovery_mode"),
		"ami_id should reference var.disaster_recovery_mode, got: %#v", amiVal)
}

// resourceBody parses an HCL snippet containing a single resource block and
// returns that block's body, so tests can exercise nested-block flattening.
func resourceBody(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	f, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "parse errors: %s", diags.Error())
	body, ok := f.Body.(*hclsyntax.Body)
	require.True(t, ok)
	require.Len(t, body.Blocks, 1, "snippet must contain exactly one top-level block")
	return body.Blocks[0].Body
}

// TestHclBodyToValuesDict_FlattensNestedBlocksToPlanStateShape verifies that
// values() folds child blocks into the arguments dict as lists-of-maps keyed
// by block type — the same shape Terraform plan (change.after) and state
// (values) expose — so a single MQL body can run against all three backends.
func TestHclBodyToValuesDict_FlattensNestedBlocksToPlanStateShape(t *testing.T) {
	// resource "aws_eks_cluster" "example" { ... }
	body := resourceBody(t, `
resource "aws_eks_cluster" "example" {
  name = "example"

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = "arn:aws:kms:us-east-1:111:key/abc"
    }
  }

  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
`)

	values, err := hclBodyToValuesDict(body, nil)
	require.NoError(t, err)

	// Scalar arguments stay as direct values.
	assert.Equal(t, "example", values["name"])

	// A nested block becomes a []any of maps keyed by the block type — even
	// when it appears once — matching the plan/state JSON representation.
	encList, ok := values["encryption_config"].([]any)
	require.True(t, ok, "encryption_config should be []any, got %#v", values["encryption_config"])
	require.Len(t, encList, 1)
	enc := encList[0].(map[string]any)

	// Nested-within-nested blocks flatten recursively the same way.
	provList, ok := enc["provider"].([]any)
	require.True(t, ok, "provider should be []any, got %#v", enc["provider"])
	require.Len(t, provList, 1)
	assert.Equal(t, "arn:aws:kms:us-east-1:111:key/abc", provList[0].(map[string]any)["key_arn"])

	// Booleans round-trip as bools so `_['endpoint_public_access'] == false` works.
	vpcList, ok := values["vpc_config"].([]any)
	require.True(t, ok, "vpc_config should be []any, got %#v", values["vpc_config"])
	require.Len(t, vpcList, 1)
	assert.Equal(t, true, vpcList[0].(map[string]any)["endpoint_private_access"])
	assert.Equal(t, false, vpcList[0].(map[string]any)["endpoint_public_access"])
}

// TestHclBodyToValuesDict_RepeatedBlocksBecomeList verifies that repeated
// nested blocks of the same type (e.g. multiple database_flags) collect into
// a single list, matching how plan/state represent them.
func TestHclBodyToValuesDict_RepeatedBlocksBecomeList(t *testing.T) {
	body := resourceBody(t, `
resource "google_sql_database_instance" "example" {
  settings {
    database_flags {
      name  = "skip_show_database"
      value = "on"
    }
    database_flags {
      name  = "local_infile"
      value = "off"
    }
  }
}
`)

	values, err := hclBodyToValuesDict(body, nil)
	require.NoError(t, err)

	settings, ok := values["settings"].([]any)
	require.True(t, ok)
	require.Len(t, settings, 1)

	flags, ok := settings[0].(map[string]any)["database_flags"].([]any)
	require.True(t, ok, "database_flags should be []any, got %#v", settings[0].(map[string]any)["database_flags"])
	require.Len(t, flags, 2)
	assert.Equal(t, "skip_show_database", flags[0].(map[string]any)["name"])
	assert.Equal(t, "local_infile", flags[1].(map[string]any)["name"])
}

// TestKeyScalarToString covers every scalar kind an evaluated object key can
// take. A number/bool/null key used to reach a bare `key.(string)` assertion in
// GetKeyString and panic; each kind must now stringify (or empty) instead.
func TestKeyScalarToString(t *testing.T) {
	assert.Equal(t, "http", keyScalarToString("http"))
	assert.Equal(t, "8080", keyScalarToString(float64(8080)))
	assert.Equal(t, "8080.5", keyScalarToString(float64(8080.5)))
	assert.Equal(t, "42", keyScalarToString(int64(42)))
	assert.Equal(t, "true", keyScalarToString(true))
	assert.Equal(t, "false", keyScalarToString(false))
	assert.Equal(t, "", keyScalarToString(nil))
}

// TestGetKeyString covers the container branches of GetKeyString, including a
// []any that holds non-string scalars (which previously panicked on the
// v[i].(string) assertion).
func TestGetKeyString(t *testing.T) {
	assert.Equal(t, "keytest", GetKeyString("keytest"))
	assert.Equal(t, "key,thing", GetKeyString([]string{"key", "thing"}))
	assert.Equal(t, "keything", GetKeyString([]any{"key", "thing"}))
	assert.Equal(t, "a8080true", GetKeyString([]any{"a", float64(8080), true}))
	assert.Equal(t, "8080", GetKeyString(float64(8080)))
	assert.Equal(t, "", GetKeyString(nil))
}

// TestGetCtyValue_ObjectNumericKey is a regression test: a map literal with a
// numeric key (e.g. `{ 8080 = "http" }`, common in port/priority maps) is valid
// HCL whose key evaluates to a number. GetKeyString used to assert it as a
// string and panic, and because query blocks run in goroutines that panic
// crashes the whole scan. The key must stringify and the object must resolve.
func TestGetCtyValue_ObjectNumericKey(t *testing.T) {
	attrs := parseAttrs(t, `ports = { 8080 = "http", 443 = "https" }`)
	got, err := hclResolvedAttributesToDict(attrs, nil)
	require.NoError(t, err)

	m, ok := got["ports"].(map[string]any)
	require.True(t, ok, "ports should be a map, got %#v", got["ports"])
	assert.Equal(t, "http", m["8080"])
	assert.Equal(t, "https", m["443"])
}

// TestGetCtyValue_ObjectResolvedScalarKey verifies the same panic path is safe
// when variable resolution turns a `{ (var.x) = ... }` key into a real scalar.
func TestGetCtyValue_ObjectResolvedScalarKey(t *testing.T) {
	attrs := parseAttrs(t, `m = { (var.port) = "http" }`)
	ctx := resolvingCtx(map[string]cty.Value{
		"port": cty.NumberIntVal(8080),
	}, nil)
	got, err := hclResolvedAttributesToDict(attrs, ctx)
	require.NoError(t, err)

	m, ok := got["m"].(map[string]any)
	require.True(t, ok, "m should be a map, got %#v", got["m"])
	assert.Equal(t, "http", m["8080"])
}

// TestHclBodyToValuesDict_DynamicBlockExpanded verifies that values() expands a
// `dynamic "X"` block into the `X` blocks it generates, matching how Terraform
// plan/state expose the already-expanded blocks. Without this a policy written
// as values["ingress"] silently sees nothing on an HCL asset while matching on
// the plan/state asset.
func TestHclBodyToValuesDict_DynamicBlockExpanded(t *testing.T) {
	body := resourceBody(t, `
resource "aws_security_group" "example" {
  name = "example"

  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port = ingress.value.port
      protocol  = "tcp"
    }
  }
}
`)

	values, err := hclBodyToValuesDict(body, nil)
	require.NoError(t, err)

	// The dynamic wrapper must not leak through as a "dynamic" key.
	_, hasDynamic := values["dynamic"]
	assert.False(t, hasDynamic, "dynamic wrapper should be expanded, got keys %#v", values)

	ingress, ok := values["ingress"].([]any)
	require.True(t, ok, "ingress should be []any, got %#v", values["ingress"])
	require.Len(t, ingress, 1)
	assert.Equal(t, "tcp", ingress[0].(map[string]any)["protocol"])
}

// TestHclBodyToValuesDict_DynamicBlockNested verifies a dynamic block nested
// inside a static block also expands to its real type.
func TestHclBodyToValuesDict_DynamicBlockNested(t *testing.T) {
	body := resourceBody(t, `
resource "aws_appautoscaling_policy" "example" {
  step_scaling_policy_configuration {
    dynamic "step_adjustment" {
      for_each = var.steps
      content {
        scaling_adjustment = step_adjustment.value.adjustment
      }
    }
  }
}
`)

	values, err := hclBodyToValuesDict(body, nil)
	require.NoError(t, err)

	cfg, ok := values["step_scaling_policy_configuration"].([]any)
	require.True(t, ok)
	require.Len(t, cfg, 1)

	inner := cfg[0].(map[string]any)
	_, hasDynamic := inner["dynamic"]
	assert.False(t, hasDynamic, "nested dynamic wrapper should be expanded, got %#v", inner)
	steps, ok := inner["step_adjustment"].([]any)
	require.True(t, ok, "step_adjustment should be []any, got %#v", inner["step_adjustment"])
	require.Len(t, steps, 1)
}

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

// TestTerraformResources_SelectorArgsAreKeyQualified is a regression test for
// terraform.resources(resource: X) and terraform.resources(name: X) computing
// the same __id.
//
// The checksum was built from the argument VALUE only, and RawData.String()
// renders a string identically whichever key it came from, so the two selector
// forms aliased in the resource cache and the second query silently returned
// the first one's list. Shared literals like "main", "default" and "this" make
// that collision an everyday occurrence.
func TestTerraformResources_SelectorArgsAreKeyQualified(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "web" "app" {}
resource "aws_instance" "web" {}
`,
	})
	rt := newRuntimeForDir(t, dir)

	byResource, _, err := initTerraformResources(rt, map[string]*llx.RawData{
		"resource": llx.StringData("web"),
	})
	require.NoError(t, err)
	byName, _, err := initTerraformResources(rt, map[string]*llx.RawData{
		"name": llx.StringData("web"),
	})
	require.NoError(t, err)

	assert.NotEqual(t, byResource["__id"].Value.(string), byName["__id"].Value.(string),
		`terraform.resources(resource: "web") and (name: "web") must not share a cache key`)

	// And the lists themselves must differ, which is what the collision hid.
	resList := byResource["list"].Value.([]any)
	nameList := byName["list"].Value.([]any)
	require.Len(t, resList, 1)
	require.Len(t, nameList, 1)
	assert.Equal(t, "web", resList[0].(*mqlTerraformBlock).Labels.Data[0])
	assert.Equal(t, "aws_instance", nameList[0].(*mqlTerraformBlock).Labels.Data[0])

	// A combined selector must be distinct from either single-key form.
	both, _, err := initTerraformResources(rt, map[string]*llx.RawData{
		"resource": llx.StringData("web"),
		"name":     llx.StringData("web"),
	})
	require.NoError(t, err)
	assert.NotEqual(t, byResource["__id"].Value.(string), both["__id"].Value.(string))
	assert.NotEqual(t, byName["__id"].Value.(string), both["__id"].Value.(string))
}

// blockInDir returns the single block from the cache whose declaring file lives
// in <root>/<sub> and whose labels match.
func blockInDir(t *testing.T, blocks []any, root, sub string, labels ...string) *mqlTerraformBlock {
	t.Helper()
	want := filepath.Join(root, filepath.FromSlash(sub))
	var found *mqlTerraformBlock
	for i := range blocks {
		b := blocks[i].(*mqlTerraformBlock)
		if b.block.Data == nil {
			continue
		}
		if filepath.Dir(b.block.Data.DefRange.Filename) != want {
			continue
		}
		if len(b.Labels.Data) != len(labels) {
			continue
		}
		match := true
		for j := range labels {
			if b.Labels.Data[j] != labels[j] {
				match = false
				break
			}
		}
		if match {
			require.Nil(t, found, "more than one block matched %v in %s", labels, sub)
			found = b
		}
	}
	require.NotNil(t, found, "no block %v found in %s", labels, sub)
	return found
}

// TestTerraformBlock_RelatedDoesNotCrossModules is a regression test for
// terraformID() colliding across files.
//
// The connection walks the whole directory tree, so a root `main.tf` and a
// `modules/vpc/main.tf` that both declare `resource "aws_s3_bucket" "this"`
// shared one blocksByName key. Both buckets then reported the same related
// list containing BOTH policies, so a check like "every bucket has a policy
// denying insecure transport" passed for the module bucket on the strength of
// the root bucket's policy.
func TestTerraformBlock_RelatedDoesNotCrossModules(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "this" {}

resource "aws_s3_bucket_policy" "root" {
  bucket = aws_s3_bucket.this.id
  policy = "root-policy"
}
`,
		"modules/vpc/main.tf": `
resource "aws_s3_bucket" "this" {}

resource "aws_s3_bucket_policy" "module" {
  bucket = aws_s3_bucket.this.id
  policy = "module-policy"
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)

	rootBucket := blockInDir(t, blocks, dir, ".", "aws_s3_bucket", "this")
	moduleBucket := blockInDir(t, blocks, dir, "modules/vpc", "aws_s3_bucket", "this")
	require.NotSame(t, rootBucket, moduleBucket, "the two buckets must be distinct block instances")

	rootRelated, err := rootBucket.related()
	require.NoError(t, err)
	require.Len(t, rootRelated, 1, "the root bucket must only relate to the policy in its own directory")
	assert.Equal(t, "root", rootRelated[0].(*mqlTerraformBlock).Labels.Data[1])

	moduleRelated, err := moduleBucket.related()
	require.NoError(t, err)
	require.Len(t, moduleRelated, 1, "the module bucket must only relate to the policy in its own directory")
	assert.Equal(t, "module", moduleRelated[0].(*mqlTerraformBlock).Labels.Data[1])
}

// TestTerraformBlock_LabellessBlocksAreNotConflated is a regression test for
// every label-less block (`terraform {}`, `locals {}`, `moved {}`) mapping to
// the same empty terraformID key, which made related() report unrelated blocks.
func TestTerraformBlock_LabellessBlocksAreNotConflated(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
terraform {}

locals {
  env = "prod"
}

moved {
  from = aws_s3_bucket.old
  to   = aws_s3_bucket.new
}

resource "aws_s3_bucket" "new" {}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	require.Len(t, blocks, 4)

	for i := range blocks {
		b := blocks[i].(*mqlTerraformBlock)
		if b.Type.Data != "terraform" && b.Type.Data != "locals" {
			continue
		}
		related, err := b.related()
		require.NoError(t, err)
		assert.Emptyf(t, related,
			"label-less %q block must not inherit the `moved` block's edges through a shared empty id",
			b.Type.Data)
	}
}

// TestTerraformSettings_BackendIsDeterministic is a regression test for
// terraform.settings.backend flapping between runs.
//
// ensureCache built its block list by ranging over parser.Files(), a Go map
// whose iteration order is randomized per process, and initTerraformSettings
// took a last-writer-wins backend while iterating those blocks. With two
// `terraform {}` blocks carrying a backend, a policy asserting
// backend["type"] == "s3" passed or failed depending on the run.
func TestTerraformSettings_BackendIsDeterministic(t *testing.T) {
	files := map[string]string{
		"a_backend.tf": "terraform {\n  backend \"s3\" {\n    bucket = \"tf-state\"\n  }\n}\n",
		"z_backend.tf": "terraform {\n  backend \"local\" {\n    path = \"terraform.tfstate\"\n  }\n}\n",
	}

	var first string
	for i := 0; i < 40; i++ {
		rt := newRuntimeForDir(t, writeTfDir(t, files))
		args, _, err := initTerraformSettings(rt, map[string]*llx.RawData{})
		require.NoError(t, err)
		backend, ok := args["backend"].Value.(map[string]any)
		require.True(t, ok, "backend must be a dict, got %#v", args["backend"].Value)
		typ, _ := backend["type"].(string)
		require.NotEmpty(t, typ)
		if i == 0 {
			first = typ
			continue
		}
		require.Equalf(t, first, typ,
			"terraform.settings.backend must be deterministic across runs (iteration %d)", i)
	}
}

// TestTerraformSettings_RequiredProvidersDoNotCollideAcrossFiles is a
// regression test for terraform.settings.requiredProvider ids keyed on the
// provider name alone.
//
// initTerraformSettings deliberately collects the required_providers of EVERY
// `terraform {}` block in the tree. When the root pins `aws = "~> 3.0"` and
// modules/vpc pins `aws = "~> 5.0"`, both entries hashed to the same cache key,
// so the list contained the first entry twice and the module's constraint was
// invisible to a supply-chain pin check.
func TestTerraformSettings_RequiredProvidersDoNotCollideAcrossFiles(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf":             "terraform {\n  required_providers {\n    aws = \"~> 3.0\"\n  }\n}\n",
		"modules/vpc/main.tf": "terraform {\n  required_providers {\n    aws = \"~> 5.0\"\n  }\n}\n",
	})
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformSettings(rt, map[string]*llx.RawData{})
	require.NoError(t, err)

	list := args["requiredProviders"].Value.([]any)
	require.Len(t, list, 2)

	versions := map[string]bool{}
	for i := range list {
		rp := list[i].(*mqlTerraformSettingsRequiredProvider)
		assert.Equal(t, "aws", rp.Name.Data, "the user-facing name must stay the bare provider name")
		versions[rp.Version.Data] = true
	}
	assert.Equal(t, map[string]bool{"~> 3.0": true, "~> 5.0": true}, versions,
		"both version constraints must be visible, not the first one twice")
}

// writeTfDir writes the given relative paths into a fresh temp dir and returns
// it. Nested paths (e.g. "modules/vpc/main.tf") create their parent dirs.
func writeTfDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}
	return dir
}

// newTerraformSingleton returns the terraform singleton for a runtime.
func newTerraformSingleton(t *testing.T, rt *plugin.Runtime) *mqlTerraform {
	t.Helper()
	tfraw, err := CreateResource(rt, "terraform", map[string]*llx.RawData{})
	require.NoError(t, err)
	return tfraw.(*mqlTerraform)
}

// TestTerraformAccessors_JSONFileDoesNotPoisonEveryAccessor is a regression
// test for a single `.tf.json` file breaking every terraform.* accessor.
//
// hclparse.ParseJSON produces a plain hcl.Body (not *hclsyntax.Body), and
// listRelatedBlocks returned a hard error for that case. That error propagated
// out of ensureCache, which is the single entry point behind blocks(),
// providers(), datasources(), variables(), outputs(), terraform.resources and
// terraform.settings. So one JSON file — the default CDKTF output layout, and a
// format the schema advertises support for — made all of them fail, including
// for the native .tf files sitting beside it.
func TestTerraformAccessors_JSONFileDoesNotPoisonEveryAccessor(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
variable "env" { default = "prod" }
output "bucket" { value = aws_s3_bucket.native.id }
provider "aws" { region = "us-east-1" }
data "aws_ami" "ubuntu" { most_recent = true }
resource "aws_s3_bucket" "native" {}
`,
		"cdk.tf.json": `{"resource":{"aws_security_group":{"sg":{"name":"allow-ssh"}}}}`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err, "a .tf.json file must not break terraform.blocks")
	require.NotEmpty(t, blocks)

	providers, err := tf.providers()
	require.NoError(t, err, "a .tf.json file must not break terraform.providers")
	assert.Len(t, providers, 1)

	datasources, err := tf.datasources()
	require.NoError(t, err, "a .tf.json file must not break terraform.datasources")
	assert.Len(t, datasources, 1)

	variables, err := tf.variables()
	require.NoError(t, err, "a .tf.json file must not break terraform.variables")
	assert.Len(t, variables, 1)

	outputs, err := tf.outputs()
	require.NoError(t, err, "a .tf.json file must not break terraform.outputs")
	assert.Len(t, outputs, 1)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err, "a .tf.json file must not break terraform.resources")
	list := args["list"].Value.([]any)
	require.NotEmpty(t, list, "the native .tf resource must still be listed")

	// The related() graph must resolve too, rather than erroring out.
	native := list[0].(*mqlTerraformBlock)
	_, err = native.related()
	require.NoError(t, err, "a .tf.json file must not break terraform.block.related")
}

// TestTerraformSettings_JSONFileDoesNotPoisonInit covers the settings init,
// which shares the same ensureCache entry point.
func TestTerraformSettings_JSONFileDoesNotPoisonInit(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf":     "terraform {\n  required_providers {\n    aws = \"~> 3.0\"\n  }\n}\n",
		"cdk.tf.json": `{"resource":{"aws_security_group":{"sg":{"name":"allow-ssh"}}}}`,
	})
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformSettings(rt, map[string]*llx.RawData{})
	require.NoError(t, err, "a .tf.json file must not break terraform.settings")
	require.NotNil(t, args)
	require.Len(t, args["requiredProviders"].Value.([]any), 1)
}

// relatedLabels returns the label tuples of a block's related() list, so tests
// can assert on the graph without caring about ordering.
func relatedLabels(t *testing.T, b *mqlTerraformBlock) map[string]bool {
	t.Helper()
	related, err := b.related()
	require.NoError(t, err)
	out := map[string]bool{}
	for i := range related {
		rb := related[i].(*mqlTerraformBlock)
		key := rb.Type.Data
		for _, l := range rb.Labels.Data {
			key += "." + l.(string)
		}
		out[key] = true
	}
	return out
}

// TestRelated_ResolvesPrefixedReferences is a regression test for related()
// only ever resolving managed-resource references.
//
// The lookup joined refs[0:2], which forms a valid key only for
// `<type>.<name>`. A `data.aws_ami.ubuntu.id` reference produced the key
// `data\x00aws_ami` while the data block's own id is `aws_ami\x00ubuntu`, so
// data sources, modules and variables never appeared in the graph at all.
func TestRelated_ResolvesPrefixedReferences(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
variable "instance_type" { default = "t3.micro" }

data "aws_ami" "ubuntu" { most_recent = true }

module "vpc" { source = "./modules/vpc" }

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id     = module.vpc.subnet_id
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	web := blockInDir(t, blocks, dir, ".", "aws_instance", "web")

	got := relatedLabels(t, web)
	assert.True(t, got["data.aws_ami.ubuntu"], "data.* reference must resolve, got: %v", got)
	assert.True(t, got["variable.instance_type"], "var.* reference must resolve, got: %v", got)
	assert.True(t, got["module.vpc"], "module.* reference must resolve, got: %v", got)

	// The inverse edges must be there too.
	ami := blockInDir(t, blocks, dir, ".", "aws_ami", "ubuntu")
	assert.True(t, relatedLabels(t, ami)["resource.aws_instance.web"],
		"the data source must relate back to the resource that uses it")
}

// TestRelated_ResolvesReferencesInsideNestedBlocks is a regression test for
// related() walking only body.Attributes. A reference written inside a nested
// block — the standard shape for a security-group rule — was never seen.
func TestRelated_ResolvesReferencesInsideNestedBlocks(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_security_group" "bastion" {
  name = "bastion"
}

resource "aws_security_group" "app" {
  name = "app"

  ingress {
    from_port       = 22
    to_port         = 22
    security_groups = [aws_security_group.bastion.id]
  }
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	app := blockInDir(t, blocks, dir, ".", "aws_security_group", "app")

	assert.True(t, relatedLabels(t, app)["resource.aws_security_group.bastion"],
		"a reference inside a nested block must be part of the related graph")
}

// TestRelated_ResolvesReferencesInsideExpressions is a regression test for
// getReferences() handling only bare ScopeTraversalExpr. References buried in a
// template, a list, a conditional or a function call were invisible.
func TestRelated_ResolvesReferencesInsideExpressions(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}

resource "aws_s3_bucket" "data" {
  bucket = "data"
}

resource "aws_s3_bucket_policy" "p" {
  bucket    = "x-${aws_s3_bucket.logs.id}"
  targets   = [aws_s3_bucket.data.arn]
  encoded   = jsonencode({ b = aws_s3_bucket.logs.arn })
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	policy := blockInDir(t, blocks, dir, ".", "aws_s3_bucket_policy", "p")

	got := relatedLabels(t, policy)
	assert.True(t, got["resource.aws_s3_bucket.logs"],
		"a reference inside a template/function must resolve, got: %v", got)
	assert.True(t, got["resource.aws_s3_bucket.data"],
		"a reference inside a list must resolve, got: %v", got)
}

// TestRelated_DeduplicatesRepeatedReferences keeps the graph free of duplicate
// edges now that every traversal in an expression tree is walked: a block
// referenced twice must appear once.
func TestRelated_DeduplicatesRepeatedReferences(t *testing.T) {
	dir := writeTfDir(t, map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.b.id
  policy = aws_s3_bucket.b.arn
}
`,
	})
	rt := newRuntimeForDir(t, dir)
	tf := newTerraformSingleton(t, rt)

	blocks, err := tf.blocks()
	require.NoError(t, err)
	policy := blockInDir(t, blocks, dir, ".", "aws_s3_bucket_policy", "p")

	related, err := policy.related()
	require.NoError(t, err)
	assert.Len(t, related, 1, "a block referenced twice must produce one related edge")
}
