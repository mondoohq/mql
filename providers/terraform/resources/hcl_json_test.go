// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

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
