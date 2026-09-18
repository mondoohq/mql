// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseDialect(t *testing.T) {
	tests := map[string]Dialect{
		"opentofu":  DialectOpenTofu,
		"tofu":      DialectOpenTofu,
		"OpenTofu":  DialectOpenTofu,
		"  tofu  ":  DialectOpenTofu,
		"terraform": DialectTerraform,
		"":          DialectTerraform,
		"nonsense":  DialectTerraform,
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, ParseDialect(in))
		})
	}
}

func TestDialectForConnector(t *testing.T) {
	// The connector name is now the whole choice of tool, so a name this
	// provider does not serve has to stay distinguishable from "terraform" --
	// otherwise an unrecognized caller would silently force a tool it never
	// named, instead of letting the files decide.
	tests := []struct {
		connector string
		want      Dialect
		wantOK    bool
	}{
		{"terraform", DialectTerraform, true},
		{"opentofu", DialectOpenTofu, true},
		{"tofu", DialectOpenTofu, true},
		{"OpenTofu", DialectOpenTofu, true},
		{"", "", false},
		{"k8s", "", false},
	}
	for _, tc := range tests {
		t.Run("connector="+tc.connector, func(t *testing.T) {
			got, ok := DialectForConnector(tc.connector)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClassifyConfigFile(t *testing.T) {
	tests := []struct {
		path        string
		wantOK      bool
		wantClass   fileClass
		wantDialect Dialect
		wantStem    string
	}{
		{"main.tf", true, classConfig, DialectTerraform, "main"},
		{"main.tf.json", true, classConfigJSON, DialectTerraform, "main"},
		{"prod.tfvars", true, classVars, DialectTerraform, "prod"},
		{"prod.tfvars.json", true, classVarsJSON, DialectTerraform, "prod"},

		{"main.tofu", true, classConfig, DialectOpenTofu, "main"},
		{"main.tofu.json", true, classConfigJSON, DialectOpenTofu, "main"},
		{"prod.tofuvars", true, classVars, DialectOpenTofu, "prod"},
		{"prod.tofuvars.json", true, classVarsJSON, DialectOpenTofu, "prod"},

		// The stem is what a .tofu file overrides, so it must survive a path.
		{"/repo/env/main.tofu", true, classConfig, DialectOpenTofu, "main"},
		// Override files keep their _override suffix in the stem, so
		// main_override.tofu replaces main_override.tf and not main.tf.
		{"main_override.tf", true, classConfig, DialectTerraform, "main_override"},
		{"main_override.tofu", true, classConfig, DialectOpenTofu, "main_override"},

		// Not configuration files.
		{"README.md", false, 0, "", ""},
		{"main.go", false, 0, "", ""},
		{"main.tofutest.hcl", false, 0, "", ""},
		{"main.tftest.hcl", false, 0, "", ""},
		// no name left to match an override against
		{".tf", false, 0, "", ""},
		{".tofu", false, 0, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := classifyConfigFile(tc.path)
			require.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
				return
			}
			assert.Equal(t, tc.wantClass, got.class, "class")
			assert.Equal(t, tc.wantDialect, got.dialect, "dialect")
			assert.Equal(t, tc.wantStem, got.stem, "stem")
		})
	}
}

func TestResolveConfigFilesDetectsTheDialect(t *testing.T) {
	t.Run("terraform only", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/main.tf", "a/vars.tf", "a/prod.tfvars"}, "")
		assert.Equal(t, DialectTerraform, got.Dialect)
		assert.Equal(t, []string{"a/main.tf", "a/vars.tf"}, got.Configs)
		assert.Equal(t, []string{"a/prod.tfvars"}, got.Vars)
		assert.Empty(t, got.Overridden)
	})

	t.Run("opentofu file overrides the matching terraform file", func(t *testing.T) {
		// OpenTofu loads main.tofu *instead of* main.tf. Reading main.tf here
		// would report configuration that OpenTofu never applies.
		got := resolveConfigFiles([]string{"a/main.tf", "a/main.tofu"}, "")
		assert.Equal(t, DialectOpenTofu, got.Dialect)
		assert.Equal(t, []string{"a/main.tofu"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf"}, got.Overridden)
	})

	t.Run("override does not depend on walk order", func(t *testing.T) {
		// The same set in the opposite order must resolve identically.
		got := resolveConfigFiles([]string{"a/main.tofu", "a/main.tf"}, "")
		assert.Equal(t, []string{"a/main.tofu"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf"}, got.Overridden)
	})

	t.Run("only the matching name is overridden", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/main.tf", "a/main.tofu", "a/other.tf"}, "")
		assert.Equal(t, []string{"a/main.tofu", "a/other.tf"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf"}, got.Overridden)
	})

	t.Run("precedence is per directory", func(t *testing.T) {
		// b/main.tf has no b/main.tofu next to it, so it survives even though
		// a/main.tofu exists elsewhere in the tree.
		got := resolveConfigFiles([]string{"a/main.tf", "a/main.tofu", "b/main.tf"}, "")
		assert.Equal(t, []string{"a/main.tofu", "b/main.tf"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf"}, got.Overridden)
	})

	t.Run("classes do not override each other", func(t *testing.T) {
		// main.tofu overrides main.tf but must leave main.tf.json alone: they
		// are different kinds of file and both are loaded.
		got := resolveConfigFiles([]string{"a/main.tf", "a/main.tf.json", "a/main.tofu"}, "")
		assert.Equal(t, []string{"a/main.tf.json", "a/main.tofu"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf"}, got.Overridden)
	})

	t.Run("tofuvars overrides tfvars", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/prod.tfvars", "a/prod.tofuvars"}, "")
		assert.Equal(t, DialectOpenTofu, got.Dialect)
		assert.Equal(t, []string{"a/prod.tofuvars"}, got.Vars)
		assert.Equal(t, []string{"a/prod.tfvars"}, got.Overridden)
	})

	t.Run("json variants override each other", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/main.tf.json", "a/main.tofu.json"}, "")
		assert.Equal(t, []string{"a/main.tofu.json"}, got.Configs)
		assert.Equal(t, []string{"a/main.tf.json"}, got.Overridden)
	})

	t.Run("a lone tofu file still marks the configuration as opentofu", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/main.tf", "a/extra.tofu"}, "")
		assert.Equal(t, DialectOpenTofu, got.Dialect)
		assert.Equal(t, []string{"a/extra.tofu", "a/main.tf"}, got.Configs)
		assert.Empty(t, got.Overridden)
	})

	t.Run("non-configuration files are ignored", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/README.md", "a/main.go", "a/.terraform.lock.hcl"}, "")
		assert.Empty(t, got.Configs)
		assert.Empty(t, got.Vars)
		assert.Equal(t, DialectTerraform, got.Dialect)
	})

	t.Run("output is sorted regardless of input order", func(t *testing.T) {
		got := resolveConfigFiles([]string{"a/z.tf", "a/a.tf", "a/m.tf"}, "")
		assert.Equal(t, []string{"a/a.tf", "a/m.tf", "a/z.tf"}, got.Configs)
	})
}

func TestResolveConfigFilesForcedDialect(t *testing.T) {
	files := []string{"a/main.tf", "a/main.tofu", "a/prod.tfvars", "a/prod.tofuvars"}

	t.Run("forced terraform ignores tofu files entirely", func(t *testing.T) {
		// This is how Terraform itself reads a directory shared between the two
		// tools: the .tofu files are invisible to it, so they override nothing.
		got := resolveConfigFiles(files, DialectTerraform)
		assert.Equal(t, DialectTerraform, got.Dialect)
		assert.Equal(t, []string{"a/main.tf"}, got.Configs)
		assert.Equal(t, []string{"a/prod.tfvars"}, got.Vars)
		assert.Empty(t, got.Overridden)
		// Reported, not just dropped: it is what lets the connection explain a
		// directory it read nothing out of.
		assert.Equal(t, []string{"a/main.tofu", "a/prod.tofuvars"}, got.Ignored)
	})

	t.Run("forced opentofu applies precedence", func(t *testing.T) {
		got := resolveConfigFiles(files, DialectOpenTofu)
		assert.Equal(t, DialectOpenTofu, got.Dialect)
		assert.Equal(t, []string{"a/main.tofu"}, got.Configs)
		assert.Equal(t, []string{"a/prod.tofuvars"}, got.Vars)
		assert.Empty(t, got.Ignored, "OpenTofu reads both flavors, so nothing is ignored")
	})

	t.Run("forced opentofu on a pure terraform tree", func(t *testing.T) {
		// The user asserted the tool; there is nothing to override, but the
		// asset is still labelled OpenTofu.
		got := resolveConfigFiles([]string{"a/main.tf"}, DialectOpenTofu)
		assert.Equal(t, DialectOpenTofu, got.Dialect)
		assert.Equal(t, []string{"a/main.tf"}, got.Configs)
	})
}

func TestHclConnectionReadsOpenTofuFiles(t *testing.T) {
	t.Run("a .tofu directory parses and reports the opentofu dialect", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"main.tofu":      validResource,
			"variables.tofu": `variable "region" { default = "us-east-1" }`,
			"prod.tofuvars":  `region = "eu-west-1"`,
		})

		conn, err := hclConnectionFor(dir)
		require.NoError(t, err)
		assert.Equal(t, DialectOpenTofu, conn.Dialect())
		assert.Len(t, conn.Parser().Files(), 2)
		assert.Len(t, conn.TfVars(), 1)
	})

	t.Run("a single .tofu file given directly", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tofu": validResource})

		conn, err := hclConnectionFor(filepath.Join(dir, "main.tofu"))
		require.NoError(t, err)
		assert.Equal(t, DialectOpenTofu, conn.Dialect())
		assert.Len(t, conn.Parser().Files(), 1)
	})

	t.Run("the .tofu file wins over the .tf file it shadows", func(t *testing.T) {
		// The regression this guards: reporting on main.tf here would describe
		// a bucket that is private, when OpenTofu deploys the public one.
		dir := writeFiles(t, map[string]string{
			"main.tf":   `resource "aws_s3_bucket" "b" { acl = "private" }`,
			"main.tofu": `resource "aws_s3_bucket" "b" { acl = "public-read" }`,
		})

		conn, err := hclConnectionFor(dir)
		require.NoError(t, err)
		assert.Equal(t, DialectOpenTofu, conn.Dialect())

		files := conn.Parser().Files()
		require.Len(t, files, 1)
		_, readTheTofuFile := files[filepath.Join(dir, "main.tofu")]
		assert.True(t, readTheTofuFile, "expected main.tofu to be the file parsed, got %v", keysOf(files))
	})

	t.Run("the terraform connector ignores the .tofu file", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"main.tf":   `resource "aws_s3_bucket" "b" { acl = "private" }`,
			"main.tofu": `resource "aws_s3_bucket" "b" { acl = "public-read" }`,
		})

		conn, err := hclConnectionAs(dir, DialectTerraform)
		require.NoError(t, err)
		assert.Equal(t, DialectTerraform, conn.Dialect())

		files := conn.Parser().Files()
		require.Len(t, files, 1)
		_, readTheTfFile := files[filepath.Join(dir, "main.tf")]
		assert.True(t, readTheTfFile, "expected main.tf to be the file parsed, got %v", keysOf(files))
	})

	t.Run("a terraform-only tree still reports the terraform dialect", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tf": validResource})

		conn, err := hclConnectionFor(dir)
		require.NoError(t, err)
		assert.Equal(t, DialectTerraform, conn.Dialect())
	})
}

func TestTerraformConnectorRejectsAnOpenTofuOnlyTree(t *testing.T) {
	// The regression this guards: connecting anyway would produce a
	// configuration holding zero resources, and every policy would pass on a
	// project not one line of which was read.
	t.Run("a directory of only .tofu files", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"main.tofu":     validResource,
			"prod.tofuvars": `region = "eu-west-1"`,
		})

		_, err := hclConnectionAs(dir, DialectTerraform)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opentofu connector")
		assert.Contains(t, err.Error(), "main.tofu")
	})

	t.Run("a single .tofu file given directly", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tofu": validResource})

		_, err := hclConnectionAs(filepath.Join(dir, "main.tofu"), DialectTerraform)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opentofu connector")
	})

	t.Run("a mixed directory connects, because Terraform reads part of it", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"main.tf":  validResource,
			"api.tofu": validResource,
		})

		conn, err := hclConnectionAs(dir, DialectTerraform)
		require.NoError(t, err)
		assert.Len(t, conn.Parser().Files(), 1)
	})

	t.Run("an empty directory is not blamed on OpenTofu", func(t *testing.T) {
		// Nothing was skipped here, so there is nothing to point the user at.
		// The folder is still refused -- connecting an empty configuration
		// would pass every policy on a project nothing was read from -- but
		// with the plain message rather than the one naming a connector that
		// would not help either.
		dir := writeFiles(t, map[string]string{"README.md": "nothing to see"})

		_, err := hclConnectionAs(dir, DialectTerraform)
		require.Error(t, err)
		assert.True(t, plugin.IsNoMatchError(err), err)
		assert.NotContains(t, err.Error(), "opentofu connector")
	})

	t.Run("the opentofu connector reads the same tree", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tofu": validResource})

		conn, err := hclConnectionAs(dir, DialectOpenTofu)
		require.NoError(t, err)
		assert.Len(t, conn.Parser().Files(), 1)
	})
}

func TestStateConnectionDialect(t *testing.T) {
	// State JSON is identical between the two tools, so the dialect can only
	// come from the connector the user invoked.
	const showJSON = `{"format_version":"1.0","terraform_version":"1.9.0","values":{"root_module":{}}}`

	for _, tc := range []struct {
		option string
		want   Dialect
	}{
		{"", DialectTerraform},
		{"terraform", DialectTerraform},
		{"opentofu", DialectOpenTofu},
		{"tofu", DialectOpenTofu},
	} {
		t.Run("option="+tc.option, func(t *testing.T) {
			dir := writeFiles(t, map[string]string{"state.json": showJSON})
			conn, err := NewStateConnection(0, &inventory.Asset{
				Connections: []*inventory.Config{{
					Options: map[string]string{
						"path":        filepath.Join(dir, "state.json"),
						OptionDialect: tc.option,
					},
					Type: "state",
				}},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, conn.Dialect())
		})
	}
}

func TestConnectionRuntimeTracksDialect(t *testing.T) {
	// The platform catalog's opentofu-* entries declare a runtime of
	// "opentofu"; a connection that kept reporting "terraform" would contradict
	// the platform built from it.
	t.Run("opentofu", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tofu": validResource})
		conn, err := hclConnectionFor(dir)
		require.NoError(t, err)
		assert.Equal(t, "opentofu", conn.Runtime())
	})

	t.Run("terraform", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"main.tf": validResource})
		conn, err := hclConnectionFor(dir)
		require.NoError(t, err)
		assert.Equal(t, "terraform", conn.Runtime())
	})
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
