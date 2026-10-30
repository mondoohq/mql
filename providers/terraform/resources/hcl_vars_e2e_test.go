// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/terraform/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// writeVarFixture writes the reviewer's mondoohq/mql#8966 repro to a temp dir: a
// security-group-rule whose cidr_blocks reference a variable overridden by
// terraform.tfvars to 0.0.0.0/0.
func writeVarFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"main.tf":          "resource \"aws_security_group_rule\" \"example\" {\n  cidr_blocks = [var.ingress_cidr]\n}\n",
		"variables.tf":     "variable \"ingress_cidr\" { default = \"10.0.0.0/8\" }\n",
		"terraform.tfvars": "ingress_cidr = \"0.0.0.0/0\"\n",
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	return dir
}

func newRuntimeForDir(t *testing.T, dir string) *plugin.Runtime {
	t.Helper()
	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "hcl", Options: map[string]string{"path": dir}},
		},
	}
	conn, err := connection.NewHclConnection(1, asset)
	require.NoError(t, err)
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// TestTerraformResources_VarResolution exercises the full reported scenario end
// to end: terraform.resources must return the resource block (the fix for the
// intermittently-empty list, mondoohq/mql#8966), and arguments() must resolve
// var.ingress_cidr to the .tfvars override 0.0.0.0/0 — so the security check is
// non-vacuous.
func TestTerraformResources_VarResolution(t *testing.T) {
	dir := writeVarFixture(t)
	rt := newRuntimeForDir(t, dir)

	// terraform.resources init -> the list must contain the resource block.
	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	list := args["list"].Value.([]any)
	require.Len(t, list, 1, "terraform.resources must not be empty")

	block := list[0].(*mqlTerraformBlock)
	name, err := block.nameLabel()
	require.NoError(t, err)
	require.Equal(t, "aws_security_group_rule", name)

	// arguments() must resolve the variable to its .tfvars override.
	arguments, err := block.arguments()
	require.NoError(t, err)
	require.Equal(t, []any{"0.0.0.0/0"}, arguments["cidr_blocks"],
		"var.ingress_cidr must resolve to the .tfvars override")
}

// TestTerraformResources_ArgumentReferences documents the unresolved view:
// argumentReferences() surfaces the raw reference string even though
// arguments() resolves it, so a policy can still tell that a value is
// parameterized.
func TestTerraformResources_ArgumentReferences(t *testing.T) {
	dir := writeVarFixture(t)
	rt := newRuntimeForDir(t, dir)

	args, _, err := initTerraformResources(rt, map[string]*llx.RawData{})
	require.NoError(t, err)
	list := args["list"].Value.([]any)
	require.Len(t, list, 1, "terraform.resources must not be empty")

	block := list[0].(*mqlTerraformBlock)
	refs, err := block.argumentReferences()
	require.NoError(t, err)
	require.Equal(t, []any{"var.ingress_cidr"}, refs["cidr_blocks"],
		"argumentReferences must surface the reference string verbatim")
}
