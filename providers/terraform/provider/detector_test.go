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

// A caller who passed --asset-name has already named the asset; detection runs
// afterwards and must leave that name alone. Dropping either `asset.Name == ""`
// guard in detect() fails the "keeps a caller-supplied name" cases.
func TestDetect_AssetName(t *testing.T) {
	pathConn := func() *inventory.Config {
		return &inventory.Config{
			Type:    PlanConnectionType,
			Options: map[string]string{"path": "./testdata/tfplan/plan_gcp_simple.json"},
		}
	}
	gitConn := func() *inventory.Config {
		return &inventory.Config{
			Type:    HclConnectionType,
			Options: map[string]string{"ssh-url": "git@gitlab.com:exampleorg/example-gitlab.git"},
		}
	}

	t.Run("names an unnamed path asset after its platform", func(t *testing.T) {
		asset := &inventory.Asset{Connections: []*inventory.Config{pathConn()}}
		require.NoError(t, (&Service{}).detect(asset, nil))
		assert.Equal(t, "Terraform Plan plan_gcp_simple", asset.Name)
	})

	t.Run("keeps a caller-supplied name on a path asset", func(t *testing.T) {
		asset := &inventory.Asset{Name: "test-local", Connections: []*inventory.Config{pathConn()}}
		require.NoError(t, (&Service{}).detect(asset, nil))
		assert.Equal(t, "test-local", asset.Name)
		// The name is display only; identity still comes from detection.
		assert.Len(t, asset.PlatformIds, 1)
		assert.Equal(t, "terraform-plan", asset.Platform.Name)
	})

	t.Run("names an unnamed git asset after its repository", func(t *testing.T) {
		asset := &inventory.Asset{Connections: []*inventory.Config{gitConn()}}
		require.NoError(t, (&Service{}).detect(asset, nil))
		assert.Equal(t, "Terraform HCL exampleorg/example-gitlab", asset.Name)
	})

	t.Run("keeps a caller-supplied name on a git asset", func(t *testing.T) {
		asset := &inventory.Asset{Name: "test-local", Connections: []*inventory.Config{gitConn()}}
		require.NoError(t, (&Service{}).detect(asset, nil))
		assert.Equal(t, "test-local", asset.Name)
	})
}

// A parent provider that discovers repositories presets each child's Name and
// PlatformIds before the Terraform provider sees it. detect() must keep both:
// an Azure DevOps ssh URL does not carry the organization where
// ParseGitSshUrl looks for it, so the derived id cannot tell two same-named
// repositories in different organizations apart.
func TestDetect_KeepsAPresetChildIdentity(t *testing.T) {
	newChild := func(org string) *inventory.Asset {
		const project, repo = "scan-test", "ado-scan-test-iac"
		return &inventory.Asset{
			Name: project + "/" + repo,
			PlatformIds: []string{
				"//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/" + org + "/project/" + project + "/repo/" + repo,
			},
			Connections: []*inventory.Config{{
				Type: HclConnectionType,
				Options: map[string]string{
					"ssh-url":  "git@ssh.dev.azure.com:v3/" + org + "/" + project + "/" + repo,
					"http-url": "https://dev.azure.com/" + org + "/" + project + "/_git/" + repo,
				},
			}},
		}
	}

	var ids []string
	for _, org := range []string{"fabrikam-fixture-org", "fabrikam-other-fixture-org"} {
		child := newChild(org)
		preset := child.PlatformIds[0]

		require.NoError(t, (&Service{}).detect(child, nil))

		assert.Equal(t, "scan-test/ado-scan-test-iac", child.Name, "a preset name is kept")
		assert.Equal(t, []string{preset}, child.PlatformIds, "a preset platform id is kept, not replaced by the derived one")
		assert.Equal(t, preset, child.Connections[0].PlatformId)
		assert.Equal(t, "terraform-hcl", child.Platform.Name, "detection still fills in the platform")
		ids = append(ids, child.PlatformIds[0])
	}
	assert.NotEqual(t, ids[0], ids[1], "same-named repositories in two organizations stay distinct")
}
