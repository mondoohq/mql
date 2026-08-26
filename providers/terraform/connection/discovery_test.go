// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// hclAsset builds the single-connection asset every HCL connection expects.
func hclAsset(path string) *inventory.Asset {
	return &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{"path": path},
				Type:    "hcl",
			},
		},
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// A scan root whose own path contains ".terraform" as a substring must still be
// scanned. The skip is meant for the vendored `.terraform/` module cache, but a
// substring match over the full walk path also swallows directories like
// `.terraform-configs/`, silently reporting an empty configuration.
func TestScanRootContainingDotTerraformSubstring(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".terraform-configs")
	writeFile(t, filepath.Join(root, "main.tf"), `resource "aws_s3_bucket" "b" {}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 1, "a directory merely containing '.terraform' in its name must still be scanned")
}

// A file named `foo.terraform.tf` is a normal configuration file, not part of
// the vendored module cache.
func TestFileWithDotTerraformInNameIsParsed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.terraform.tf"), `resource "aws_s3_bucket" "b" {}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 1)
}

// The vendored module cache must still be skipped — the fix must not widen the
// scan to `.terraform/`.
func TestVendoredDotTerraformIsStillSkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `resource "aws_s3_bucket" "b" {}`)
	writeFile(t, filepath.Join(root, ".terraform", "modules", "vpc", "main.tf"), `resource "aws_s3_bucket" "vendored" {}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 1, "files under .terraform/ must not be parsed")
}

// A single unparseable .tf file must not silently truncate the walk. Before the
// fix the walk aborted at the broken file and its error was discarded, so every
// file ordered after it vanished from a scan that reported success.
func TestBrokenFileDoesNotTruncateScan(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a_first.tf"), `resource "aws_s3_bucket" "a" {}`)
	writeFile(t, filepath.Join(root, "m_broken.tf"), `resource "aws_s3_bucket" {{{`)
	writeFile(t, filepath.Join(root, "z_last.tf"), `resource "aws_s3_bucket" "z" {}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)

	var names []string
	for name := range conn.Parser().Files() {
		names = append(names, filepath.Base(name))
	}
	assert.Contains(t, names, "a_first.tf")
	assert.Contains(t, names, "z_last.tf", "files ordered after a broken file must still be parsed")
}

// hclparse.Parser.ParseJSONFile stores its result in the parser's file map even
// when that result is nil (an unreadable file yields (nil, diags)). A nil entry
// then panics every consumer that ranges over Files() and touches file.Body.
func TestUnreadableJSONFileDoesNotPoisonParser(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.tf"), `variable "acl" { default = "private" }`)
	// A dangling symlink is reported by WalkDir as a non-directory entry, so it
	// reaches ParseHclFile and fails to open.
	require.NoError(t, os.Symlink(filepath.Join(root, "does-not-exist"), filepath.Join(root, "b.tf.json")))

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)

	for name, f := range conn.Parser().Files() {
		require.NotNil(t, f, "parser holds a nil *hcl.File for %s; every Files() consumer will nil-deref", name)
	}

	// The panic surfaces here in production: buildVariableEvalContext ranges
	// over Files() and asserts file.Body.
	require.NotPanics(t, func() { conn.VariableEvalContext() })
}

// Terraform parses *.tfvars.json as JSON. Parsing it with the native HCL
// syntax parser yields zero attributes, so the override never applies and every
// var.* reference silently falls back to the variable block's default.
func TestReadTfVarsFromJSONFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "terraform.tfvars.json")
	writeFile(t, path, `{"image_id":"ami-json","acl":"public-read"}`)

	vars := map[string]*hcl.Attribute{}
	require.NoError(t, ReadTfVarsFromFile(path, vars))
	require.Len(t, vars, 2, "*.tfvars.json must be parsed as JSON")
	assert.Contains(t, vars, "image_id")
	assert.Contains(t, vars, "acl")
}

// The security-relevant consequence of the above: a JSON tfvars override of a
// variable default must win, exactly as it does for a native .tfvars file.
func TestJSONTfVarsOverridesVariableDefault(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `variable "acl" { default = "private" }`)
	writeFile(t, filepath.Join(root, "terraform.tfvars.json"), `{"acl":"public-read"}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)

	ctx := conn.VariableEvalContext()
	require.NotNil(t, ctx)
	v, ok := ctx.Variables["var"]
	require.True(t, ok, "no var scope built")
	assert.Equal(t, "public-read", v.GetAttr("acl").AsString(),
		"a terraform.tfvars.json override must beat the variable default")
}

// os.Stat fails with more than ENOENT. A path whose ancestor is a regular file
// returns ENOTDIR with a nil FileInfo, which the ENOENT-only guard let through
// into a nil dereference.
func TestNonExistErrorFromStatIsNotAPanic(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "main.tf")
	writeFile(t, file, `resource "aws_s3_bucket" "b" {}`)

	// ENOTDIR: `main.tf` is a file, so `main.tf/sub` cannot be stat'd.
	require.NotPanics(t, func() {
		_, err := NewHclConnection(0, hclAsset(filepath.Join(file, "sub")))
		assert.Error(t, err)
	})
}

// `modules/<name>/examples/<case>/` is the canonical layout of a first-party
// Terraform module repository. Only examples vendored under `.terraform/` are
// meant to be skipped.
func TestFirstPartyModuleExamplesAreScanned(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `resource "aws_s3_bucket" "root" {}`)
	writeFile(t, filepath.Join(root, "modules", "vpc", "examples", "complete", "main.tf"),
		`resource "aws_s3_bucket" "ex" { acl = "public-read" }`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 2, "a repository's own modules/*/examples/* is first-party code")
}

// Examples inside the vendored module cache stay skipped.
func TestVendoredModuleExamplesAreSkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `resource "aws_s3_bucket" "root" {}`)
	writeFile(t, filepath.Join(root, ".terraform", "modules", "vpc", "examples", "complete", "main.tf"),
		`resource "aws_s3_bucket" "ex" {}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 1)
}

// A monorepo with one module cache per stack must not report only the last
// manifest the walk happened to reach.
func TestMultipleModuleManifestsAreMerged(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `resource "aws_s3_bucket" "b" {}`)
	writeFile(t, filepath.Join(root, "stacks", "a", ".terraform", "modules", "modules.json"),
		`{"Modules":[{"Key":"a-vpc","Source":"./mods/vpc","Dir":"mods/vpc"}]}`)
	writeFile(t, filepath.Join(root, "stacks", "b", ".terraform", "modules", "modules.json"),
		`{"Modules":[{"Key":"b-vpc","Source":"./mods/vpc","Dir":"mods/vpc"}]}`)

	conn, err := NewHclConnection(0, hclAsset(root))
	require.NoError(t, err)

	manifest := conn.ModulesManifest()
	require.NotNil(t, manifest)
	var keys []string
	for _, r := range manifest.Records {
		keys = append(keys, r.Key)
	}
	assert.ElementsMatch(t, []string{"a-vpc", "b-vpc"}, keys,
		"every stack's module manifest must be reported, not just the last one walked")
}
