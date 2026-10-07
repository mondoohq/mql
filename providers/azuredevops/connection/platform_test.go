// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The repository id is minted by the server and by this provider from the
// decoded names xgrep sends (the xgrep side pins the same string), so the golden value
// must not change without changing every side.
func TestRepoIdentifierGolden(t *testing.T) {
	got := NewRepoIdentifier("mondoo-ado-scan-test", "scan test", "ado-scan-test-iac")
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/azuredevops/organization/mondoo-ado-scan-test/project/scan%20test/repository/ado-scan-test-iac",
		got)
}

func TestOrgIdentifierGolden(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/azuredevops/organization/mondoo-ado-scan-test",
		NewOrgIdentifier("mondoo-ado-scan-test"))
}

// Repository names are unique only within a project, so the project has to be
// part of the id.
func TestRepoIdentifierDiffersAcrossProjects(t *testing.T) {
	a := NewRepoIdentifier("mondoo-ado-scan-test", "scan-test", "shared-name")
	b := NewRepoIdentifier("mondoo-ado-scan-test", "scan-test-two", "shared-name")
	assert.NotEqual(t, a, b)
}

func TestTerraformRepoIdentifierGolden(t *testing.T) {
	got := NewTerraformRepoIdentifier("mondoo-ado-scan-test", "scan test", "ado-scan-test-iac")
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/mondoo-ado-scan-test/project/scan%20test/repo/ado-scan-test-iac",
		got)
}

// Azure DevOps treats organization, project and repository names as
// case-insensitive, so one repository typed two ways must be one asset. The
// golden value is shared with the server's etl/etlinventory tests.
func TestIdentifiersLowerCaseEveryName(t *testing.T) {
	assert.Equal(t, NewOrgIdentifier("mondoo-ado-scan-test"), NewOrgIdentifier("Mondoo-ADO-Scan-Test"))
	assert.Equal(t,
		NewRepoIdentifier("mondoo-ado-scan-test", "scan test", "ado-scan-test-iac"),
		NewRepoIdentifier("MONDOO-ado-scan-test", "scan test", "ado-scan-test-iac"))
	assert.Equal(t,
		NewTerraformRepoIdentifier("mondoo-ado-scan-test", "scan test", "ado-scan-test-iac"),
		NewTerraformRepoIdentifier("Mondoo-Ado-Scan-Test", "scan test", "ado-scan-test-iac"))
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/azuredevops/organization/mondoo-ado-scan-test/project/scan%20test/repository/ado-scan-test-iac",
		NewRepoIdentifier("Mondoo-ADO-Scan-Test", "Scan Test", "ADO-Scan-Test-IaC"))
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/terraform/domain/dev.azure.com/org/mondoo-ado-scan-test/project/scan%20test/repo/ado-scan-test-iac",
		NewTerraformRepoIdentifier("Mondoo-ADO-Scan-Test", "Scan Test", "ADO-Scan-Test-IaC"))
}

func TestPlatformCatalog(t *testing.T) {
	require.Len(t, Platforms, 2)
	for _, name := range []string{PlatformOrg, PlatformRepo} {
		pf := PlatformByName(name)
		require.NotNil(t, pf, name)
		assert.Equal(t, []string{"azuredevops"}, pf.Family)
		assert.Equal(t, []string{"api"}, pf.Kind)
		assert.Equal(t, []string{"azuredevops"}, pf.Runtime)
	}
	assert.Nil(t, PlatformByName("azuredevops-user"))
}

func TestPlatformBuilders(t *testing.T) {
	org := NewOrgPlatform("mondoo-ado-scan-test")
	assert.Equal(t, PlatformOrg, org.Name)
	assert.Equal(t, "Azure DevOps Organization", org.Title)
	assert.Equal(t, "api", org.Kind)
	assert.Equal(t, "azuredevops", org.Runtime)
	assert.Equal(t, []string{"saas", "azuredevops", "organization", "mondoo-ado-scan-test", "organization"},
		org.TechnologyUrlSegments)

	repo := NewRepoPlatform("mondoo-ado-scan-test", "scan test")
	assert.Equal(t, PlatformRepo, repo.Name)
	assert.Equal(t, "Azure DevOps Repository", repo.Title)
	// the technology url keeps the raw project name: the validator rejects "%"
	assert.Equal(t,
		[]string{"saas", "azuredevops", "organization", "mondoo-ado-scan-test", "project", "scan test", "repository"},
		repo.TechnologyUrlSegments)
}

func TestURLSegment(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "scan-test", want: "scan-test"},
		{name: "space is kept", in: "scan test", want: "scan test"},
		{name: "dot and underscore are kept", in: "team_a.v2", want: "team_a.v2"},
		{name: "percent is replaced", in: "scan%20test", want: "scan_20test"},
		{name: "parentheses are replaced", in: "Team (EU)", want: "Team _EU_"},
		{name: "an accented letter is one underscore", in: "Équipe", want: "_quipe"},
		{name: "empty", in: "", want: "_"},
		{name: "long names are cut", in: strings.Repeat("a", 300), want: strings.Repeat("a", maxURLSegmentLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, urlSegment(tc.in))
		})
	}
}

func TestPlatformSegmentsStayValidForOddProjectNames(t *testing.T) {
	repo := NewRepoPlatform("mondoo-ado-scan-test", "Équipe (EU)")
	assert.Equal(t, "_quipe _EU_", repo.TechnologyUrlSegments[5])
	// the platform id still tells such a project apart from a look-alike
	assert.NotEqual(t,
		NewRepoIdentifier("mondoo-ado-scan-test", "Équipe (EU)", "r"),
		NewRepoIdentifier("mondoo-ado-scan-test", "_quipe _EU_", "r"))
}
