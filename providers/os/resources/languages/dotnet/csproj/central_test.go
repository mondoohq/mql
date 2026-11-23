// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package csproj

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubCentral struct {
	got      string
	versions map[string]string
}

func (s *stubCentral) CentralPackageVersions(projectFile string) map[string]string {
	s.got = projectFile
	return s.versions
}

const centralProject = `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="serilog" />
    <PackageReference Include="Polly" VersionOverride="8.4.0" />
    <PackageReference Include="Dapper" Version="2.1.35" />
    <PackageReference Include="Unmanaged" />
    <PackageReference Include="xunit" PrivateAssets="all" />
  </ItemGroup>
</Project>`

func TestCsprojCentralPackageVersions(t *testing.T) {
	central := &stubCentral{versions: map[string]string{
		"Newtonsoft.Json": "13.0.3",
		"Serilog":         "3.1.1", // ids are case-insensitive
		"Polly":           "8.2.0", // overridden by the project
		"Dapper":          "2.0.0", // the project's own Version wins
		"xunit":           "2.9.0",
	}}
	info, err := (&Extractor{CentralVersions: central}).Parse(strings.NewReader(centralProject), "src/Api/Api.csproj")
	require.NoError(t, err)
	assert.Equal(t, "src/Api/Api.csproj", central.got, "the resolver is asked for the project being parsed")

	for name, want := range map[string]string{
		"Newtonsoft.Json": "13.0.3",
		"serilog":         "3.1.1",
		"Polly":           "8.4.0",
		"Dapper":          "2.1.35",
		"Unmanaged":       "",
		"xunit":           "2.9.0",
	} {
		p := info.Transitive().Find(name)
		require.NotNil(t, p, name)
		assert.Equal(t, want, p.Version, name)
	}
	assert.Equal(t, "pkg:nuget/Newtonsoft.Json@13.0.3", info.Direct().Find("Newtonsoft.Json").Purl)
	assert.Nil(t, info.Direct().Find("xunit"), "a centrally versioned dev package is still dev")
}

func TestCsprojWithoutCentralResolverIsUnchanged(t *testing.T) {
	info, err := (&Extractor{}).Parse(strings.NewReader(centralProject), "Api.csproj")
	require.NoError(t, err)
	assert.Equal(t, "", info.Transitive().Find("Newtonsoft.Json").Version)
	assert.Equal(t, "8.4.0", info.Transitive().Find("Polly").Version, "VersionOverride is read on its own too")
}

func TestParsePackageVersions(t *testing.T) {
	versions, enabled, err := ParsePackageVersions(strings.NewReader(`<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Serilog"><Version>3.1.1</Version></PackageVersion>
    <PackageVersion Include="FromProperty" Version="$(FromPropertyVersion)" />
  </ItemGroup>
</Project>`))
	require.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, map[string]string{"Newtonsoft.Json": "13.0.3", "Serilog": "3.1.1"}, versions)

	_, enabled, err = ParsePackageVersions(strings.NewReader(`<Project><ItemGroup><PackageVersion Include="A" Version="1.0.0" /></ItemGroup></Project>`))
	require.NoError(t, err)
	assert.False(t, enabled, "without ManagePackageVersionsCentrally the file does not turn it on")
}
