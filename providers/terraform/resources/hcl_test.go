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

// The dynamic-block normalization in #9077 retypes `dynamic "X"` to a type-X
// block, but left the iterator unbound. A content body almost always references
// it — `source = ingress.value` — and an unresolved reference makes every
// value-matching predicate miss, so a check like
//
//	blocks.where(type == "ingress" && arguments.source == "0.0.0.0/0").none(...)
//
// selects nothing and passes vacuously on a genuinely open rule. These tests
// cover the binding.

// TestDynamicBlock_IteratorValueResolved is the core case: a for_each over a
// literal list must bind <label>.value in the generated block's arguments.
func TestDynamicBlock_IteratorValueResolved(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  dynamic "ingress" {
    for_each = ["0.0.0.0/0"]
    content {
      from_port = 22
      to_port   = 22
      cidr      = ingress.value
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	sg := args["list"].Value.([]any)[0].(*mqlTerraformBlock)

	children, err := sg.blocks()
	require.NoError(t, err)
	require.Len(t, children, 1, "one for_each element yields one block")

	a, err := children[0].(*mqlTerraformBlock).arguments()
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0/0", a["cidr"],
		"ingress.value must resolve to the for_each element")
}

// TestDynamicBlock_ExpandsPerForEachElement checks that a multi-element for_each
// produces one block per element, each carrying its own iterator value. A single
// merged block would let a violating element hide behind a compliant one.
func TestDynamicBlock_ExpandsPerForEachElement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  dynamic "ingress" {
    for_each = ["10.0.0.0/8", "0.0.0.0/0"]
    content {
      cidr = ingress.value
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	sg := args["list"].Value.([]any)[0].(*mqlTerraformBlock)

	children, err := sg.blocks()
	require.NoError(t, err)
	require.Len(t, children, 2)

	var cidrs []any
	for _, c := range children {
		a, err := c.(*mqlTerraformBlock).arguments()
		require.NoError(t, err)
		cidrs = append(cidrs, a["cidr"])
	}
	require.ElementsMatch(t, []any{"10.0.0.0/8", "0.0.0.0/0"}, cidrs)
}

// TestDynamicBlock_IteratorRenamed covers the `iterator = other` override, which
// parses as a naked keyword rather than a string.
func TestDynamicBlock_IteratorRenamed(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  dynamic "ingress" {
    for_each = ["0.0.0.0/0"]
    iterator = rule
    content {
      cidr = rule.value
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	sg := args["list"].Value.([]any)[0].(*mqlTerraformBlock)

	children, err := sg.blocks()
	require.NoError(t, err)
	require.Len(t, children, 1)

	a, err := children[0].(*mqlTerraformBlock).arguments()
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0/0", a["cidr"])
}

// TestDynamicBlock_ForEachOverVariable is the shape the reported policy failures
// actually take: for_each iterates a variable, so binding the iterator depends
// on variable resolution having already happened.
func TestDynamicBlock_ForEachOverVariable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
variable "ssh_cidrs" {
  default = ["0.0.0.0/0"]
}

resource "oci_core_security_list" "ex" {
  dynamic "ingress_security_rules" {
    for_each = var.ssh_cidrs
    content {
      protocol = "6"
      source   = ingress_security_rules.value
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	sl := args["list"].Value.([]any)[0].(*mqlTerraformBlock)

	children, err := sl.blocks()
	require.NoError(t, err)
	require.Len(t, children, 1)

	a, err := children[0].(*mqlTerraformBlock).arguments()
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0/0", a["source"],
		"for_each over a variable must still bind the iterator")
}

// TestDynamicBlock_UnresolvableForEachStillSurfaces guards the fallback: when
// for_each cannot be evaluated statically the block must still appear, unbound,
// rather than disappearing and taking its structure with it.
func TestDynamicBlock_UnresolvableForEachStillSurfaces(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  dynamic "ingress" {
    for_each = data.external.whatever.result
    content {
      from_port = 22
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	sg := args["list"].Value.([]any)[0].(*mqlTerraformBlock)

	children, err := sg.blocks()
	require.NoError(t, err)
	require.Len(t, children, 1)
	ingress := children[0].(*mqlTerraformBlock)
	require.Equal(t, "ingress", ingress.Type.Data)

	a, err := ingress.arguments()
	require.NoError(t, err)
	require.Equal(t, float64(22), a["from_port"])
}
