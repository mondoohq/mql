// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPermissionManifest = `{
  "provider": "aws",
  "permissions": ["ec2:DescribeInstances", "ec2:DescribeTags", "iam:GetAccountPasswordPolicy"],
  "details": [
    {"permission": "ec2:DescribeInstances", "service": "ec2", "action": "DescribeInstances", "source_file": "aws_ec2.go"},
    {"permission": "ec2:DescribeTags", "service": "ec2", "action": "DescribeTags", "source_file": "aws_ec2.go"},
    {"permission": "ec2:DescribeTags", "service": "ec2", "action": "DescribeTagsV2", "source_file": "aws_ec2.go"},
    {"permission": "apigateway:GET", "service": "apigateway", "action": "GetApiKeys", "source_file": "aws_apigateway.go"},
    {"permission": "apigateway:GET", "service": "apigateway", "action": "GetApis", "source_file": "aws_apigateway.go"},
    {"permission": "iam:GetAccountPasswordPolicy", "service": "iam", "action": "GetAccountPasswordPolicy", "source_file": "permissions_test.go"},
    {"permission": "", "service": "iam", "action": "Broken", "source_file": "aws_iam.go"}
  ]
}`

func TestPermissionIndexLookup(t *testing.T) {
	idx := NewPermissionIndex([]byte(testPermissionManifest))
	require.NoError(t, idx.Err())

	t.Run("operation narrows to its call", func(t *testing.T) {
		assert.Equal(t, []string{"ec2:DescribeInstances"}, idx.Lookup("aws_ec2.go", "DescribeInstances"))
	})
	t.Run("unknown operation falls back to the whole file", func(t *testing.T) {
		assert.Equal(t, []string{"ec2:DescribeInstances", "ec2:DescribeTags"}, idx.Lookup("aws_ec2.go", "DescribeVolumes"))
	})
	t.Run("no operation returns the whole file without duplicates", func(t *testing.T) {
		assert.Equal(t, []string{"ec2:DescribeInstances", "ec2:DescribeTags"}, idx.Lookup("aws_ec2.go", ""))
		assert.Equal(t, []string{"apigateway:GET"}, idx.Lookup("aws_apigateway.go", ""))
	})
	t.Run("file matches by base name", func(t *testing.T) {
		assert.Equal(t, []string{"ec2:DescribeInstances"},
			idx.Lookup("go.mondoo.com/mql/providers/aws/resources/aws_ec2.go", "DescribeInstances"))
	})
	t.Run("unknown file", func(t *testing.T) {
		assert.Nil(t, idx.Lookup("aws_s3.go", "GetBucketPolicy"))
	})
	t.Run("entries without a permission are skipped", func(t *testing.T) {
		assert.Nil(t, idx.Lookup("aws_iam.go", ""))
	})
	t.Run("results do not share storage", func(t *testing.T) {
		first := idx.Lookup("aws_ec2.go", "")
		first[0] = "changed"
		assert.Equal(t, []string{"ec2:DescribeInstances", "ec2:DescribeTags"}, idx.Lookup("aws_ec2.go", ""))
	})
}

func TestPermissionIndexLookupCaller(t *testing.T) {
	idx := NewPermissionIndex([]byte(testPermissionManifest))

	assert.Equal(t, []string{"iam:GetAccountPasswordPolicy"}, idx.LookupCaller(0, ""))

	// A classifier passes 1 to name its caller's file, not its own.
	classify := func() []string { return idx.LookupCaller(1, "") }
	assert.Equal(t, []string{"iam:GetAccountPasswordPolicy"}, classify())
}

func TestPermissionIndexBrokenManifest(t *testing.T) {
	idx := NewPermissionIndex([]byte(`{"details": [`))
	assert.Error(t, idx.Err())
	assert.Nil(t, idx.Lookup("aws_ec2.go", "DescribeInstances"))

	var none *PermissionIndex
	assert.NoError(t, none.Err())
	assert.Nil(t, none.Lookup("aws_ec2.go", ""))
	assert.Nil(t, none.LookupCaller(0, ""))
}

// The manifests the providers ship are what the index reads, so a change to
// the generator's output format has to keep them readable.
func TestPermissionIndexReadsShippedManifests(t *testing.T) {
	files := map[string]string{
		"aws":   "aws_ec2.go",
		"gcp":   "compute.go",
		"azure": "network.go",
	}
	for provider, file := range files {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "providers", provider, "resources", provider+".permissions.json"))
			require.NoError(t, err)
			idx := NewPermissionIndex(raw)
			require.NoError(t, idx.Err())
			assert.NotEmpty(t, idx.Lookup(file, ""))
		})
	}
}
