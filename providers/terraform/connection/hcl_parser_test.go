// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
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
