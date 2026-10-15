// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestLoadHclBlocks(t *testing.T) {
	path := "./testdata/"
	cc := &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					"path": path,
				},
				Type: "hcl",
			},
		},
	}
	tf, err := NewHclConnection(0, cc)
	require.NoError(t, err)
	parser := tf.Parser()
	require.NotNil(t, parser)
	tfVars := tf.TfVars()
	assert.Equal(t, 2, len(tfVars))
	assert.Equal(t, 6, len(parser.Files()))
}

func TestLoadTfvars(t *testing.T) {
	path := "./testdata/hcl/sample.tfvars"
	variables := make(map[string]*hcl.Attribute)
	err := ReadTfVarsFromFile(path, variables)
	require.NoError(t, err)
	assert.Equal(t, 2, len(variables))
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
