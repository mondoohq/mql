// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

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
