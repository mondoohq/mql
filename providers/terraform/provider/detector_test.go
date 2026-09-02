// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/urlx"
)

// TestDetectAssetName pins the asset name to the kind of terraform artifact that was
// actually connected to. A plan and a state file each have their own platform, so
// naming all three after HCL mislabels two of them.
func TestDetectAssetName(t *testing.T) {
	tests := []struct {
		title        string
		connType     string
		path         string
		expectedName string
		platform     string
	}{
		{
			title:        "plan file",
			connType:     PlanConnectionType,
			path:         "./testdata/tfplan/plan_gcp_simple.json",
			expectedName: "Terraform Plan plan_gcp_simple",
			platform:     "terraform-plan",
		},
		{
			title:        "state file",
			connType:     StateConnectionType,
			path:         "./testdata/nested/terraform.tfstate",
			expectedName: "Terraform State terraform",
			platform:     "terraform-state",
		},
		{
			title:        "hcl directory",
			connType:     HclConnectionType,
			path:         "./testdata/terraform",
			expectedName: "Terraform HCL directory terraform",
			platform:     "terraform-hcl",
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			s := &Service{}
			asset := &inventory.Asset{
				Connections: []*inventory.Config{{
					Type:    test.connType,
					Options: map[string]string{"path": test.path},
				}},
			}

			require.NoError(t, s.detect(asset, nil))

			assert.Equal(t, test.expectedName, asset.Name)
			assert.Equal(t, test.platform, asset.Platform.Name)
		})
	}
}

// TestDetectAssetNameFromGitUrl covers the branch that prefers the git remote over the
// path on disk. Repositories are checked out as HCL, so the HCL title is correct here.
func TestDetectAssetNameFromGitUrl(t *testing.T) {
	s := &Service{}
	asset := &inventory.Asset{
		Connections: []*inventory.Config{{
			Type:    HclGitConnectionType,
			Options: map[string]string{"ssh-url": "git@gitlab.com:exampleorg/example-gitlab.git"},
		}},
	}

	require.NoError(t, s.detect(asset, nil))

	assert.Equal(t, "Terraform HCL exampleorg/example-gitlab", asset.Name)
	assert.Equal(t, "terraform-hcl", asset.Platform.Name)
}

func TestDetectNameFromFile_Directory(t *testing.T) {
	name := parseNameFromPath("./testdata/nested")
	assert.Equal(t, "directory nested", name)
}

func TestDetectNameFromFile_File(t *testing.T) {
	name := parseNameFromPath("./testdata/nested/terraform.tfstate")
	assert.Equal(t, "terraform", name)
}

func TestDetectNameFromSsh(t *testing.T) {
	url := "git@gitlab.com:exampleorg/example-gitlab.git"
	domain, org, repo, err := urlx.ParseGitSshUrl(url)
	require.NoError(t, err)
	assert.Equal(t, "gitlab.com", domain)
	assert.Equal(t, "exampleorg", org)
	assert.Equal(t, "example-gitlab", repo)
}

func TestDetectNameFromSsh_GitlabSubgroups(t *testing.T) {
	url := "git@gitlab.example.com:exampleorg/group/example-gitlab.git"
	domain, org, repo, err := urlx.ParseGitSshUrl(url)
	require.NoError(t, err)
	assert.Equal(t, "gitlab.example.com", domain)
	assert.Equal(t, "exampleorg", org)
	assert.Equal(t, "example-gitlab", repo)
}
