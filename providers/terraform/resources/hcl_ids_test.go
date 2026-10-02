// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

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
