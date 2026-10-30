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

// TestTerraformBlocks_DynamicBlockUnwrapped is a regression test for #9077: a
// `dynamic "ingress" { content { ... } }` block must surface as a
// type == "ingress" block whose arguments are the content{} fields, so
// blocks.where(type == "ingress") is not blind to the dynamic form.
func TestTerraformBlocks_DynamicBlockUnwrapped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  name = "allow-ssh"
  dynamic "ingress" {
    for_each = ["0.0.0.0/0"]
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }
}
`), 0o600))
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	list := args["list"].Value.([]any)
	require.Len(t, list, 1)
	sg := list[0].(*mqlTerraformBlock)

	children, err := sg.blocks()
	require.NoError(t, err)

	var ingress *mqlTerraformBlock
	for _, c := range children {
		b := c.(*mqlTerraformBlock)
		// The dynamic block is retyped to its label, so match on the block
		// type (labels are cleared to mirror a statically written block).
		if b.Type.Data == "ingress" {
			ingress = b
		}
		require.NotEqual(t, "dynamic", b.Type.Data,
			"the dynamic wrapper must not surface as a type==dynamic block")
	}
	require.NotNil(t, ingress, `dynamic "ingress" must appear as a type==ingress block`)

	a, err := ingress.arguments()
	require.NoError(t, err)
	require.Equal(t, float64(22), a["from_port"])
	require.Equal(t, float64(22), a["to_port"])
	require.Equal(t, "tcp", a["protocol"])
}

// TestTerraformBlocks_StaticBlockUnaffected verifies a statically written block
// still surfaces normally alongside the dynamic-block normalization.
func TestTerraformBlocks_StaticBlockUnaffected(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "aws_security_group" "ex" {
  ingress {
    from_port = 443
    to_port   = 443
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
	require.Equal(t, float64(443), a["from_port"])
}
