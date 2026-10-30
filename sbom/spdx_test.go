// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
	"go.mondoo.com/mql/sbom/generator"
)

func TestSpdxOutput(t *testing.T) {
	report, err := generator.LoadReport("./testdata/alpine.json")
	require.NoError(t, err)

	sboms := generator.GenerateBom(report)

	// store bom in different formats
	selectedBom := sboms[0]

	formatHandler := &sbom.Spdx{
		Version: "2.3",
		Format:  sbom.FormatSpdxJSON,
	}

	output := bytes.Buffer{}
	err = formatHandler.Render(&output, selectedBom)
	require.NoError(t, err)

	data := output.String()
	assert.Contains(t, data, "SPDX-2.3")

	// ensure os package is included
	assert.Contains(t, data, "alpine-baselayout")
	assert.Contains(t, data, "cpe:2.3:a:alpine-baselayout:alpine-baselayout:1695795276:aarch64:*:*:*:*:*:*")

	// ensure python package is included
	assert.Contains(t, data, "pip")
	assert.Contains(t, data, "cpe:2.3:a:pip_project:pip:21.2.4:*:*:*:*:*:*:*")
	assert.Contains(t, data, "pkg:pypi/pip@21.2.4")

	// ensure npm package is included
	assert.Contains(t, data, "npm")
	assert.Contains(t, data, "cpe:2.3:a:npm:npm:10.2.4:*:*:*:*:*:*:*")
	assert.Contains(t, data, "pkg:npm/npm@10.2.4")
}

func TestSpdxTagValueDecoder(t *testing.T) {
	f, err := os.Open("testdata/alpine-319.spdx")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxTagValue)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, sbomReport)
}

func TestSpdxJsonDecoder(t *testing.T) {
	f, err := os.Open("testdata/alpine-319.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, sbomReport)
	assert.Equal(t, "alpine-3.19.1", sbomReport.Asset.Name)
	assert.Equal(t, "alpine", sbomReport.Asset.Platform.Name)
	assert.Equal(t, "3.19.1", sbomReport.Asset.Platform.Version)
}

func TestSpdxJsonDecoder_GitHub_DependencyGraph(t *testing.T) {
	f, err := os.Open("testdata/vercel_next.js_937412.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, sbomReport)
	assert.Equal(t, "com.github.vercel/next.js", sbomReport.Asset.Name)
	assert.Equal(t, "spdx", sbomReport.Asset.Platform.Name)
	assert.Equal(t, "SPDX-2.3", sbomReport.Asset.Platform.Version)
}

// A rolling release has no version, so its distro qualifier carries the build
// id, or nothing at all when there is no build either.
func TestSpdxJsonDecoder_RollingRelease(t *testing.T) {
	f, err := os.Open("testdata/arch-rolling.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	require.NotNil(t, sbomReport)
	assert.Equal(t, "arch", sbomReport.Asset.Platform.Name)
	assert.Equal(t, "rolling", sbomReport.Asset.Platform.Version)
	assert.Equal(t, "x86_64", sbomReport.Asset.Platform.Arch)
}

func TestSpdxJsonDecoder_DistroWithoutVersion(t *testing.T) {
	f, err := os.Open("testdata/arch-noversion.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	require.NotNil(t, sbomReport)
	assert.Equal(t, "arch", sbomReport.Asset.Platform.Name)
	assert.Empty(t, sbomReport.Asset.Platform.Version)
}

func TestSpdxJsonDecoder_PurlWithoutDistro(t *testing.T) {
	f, err := os.Open("testdata/purl-without-distro.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	require.NotNil(t, sbomReport)
	// nothing identifies the platform, so the document's own one stands
	assert.Equal(t, "spdx", sbomReport.Asset.Platform.Name)
}

func TestSpdxJsonDecoder_Alpine_syft(t *testing.T) {
	f, err := os.Open("testdata/alpine-3.19.syft.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, sbomReport)
	assert.Equal(t, "alpine-3.19.9", sbomReport.Asset.Name)
	assert.Equal(t, "alpine", sbomReport.Asset.Platform.Name)
	assert.Equal(t, "3.19.9", sbomReport.Asset.Platform.Version)
}

// TestSpdxJsonDecoder_DistroNameWithDash pins that a platform name containing a
// dash survives the round trip. The distro qualifier is the platform name and
// version joined with a dash, and the openSUSE family puts dashes in the name
// itself, so splitting on the first dash reported "opensuse-leap-15.6" as name
// "opensuse" version "leap" — both fields wrong.
func TestSpdxJsonDecoder_DistroNameWithDash(t *testing.T) {
	f, err := os.Open("testdata/opensuse-leap.spdx.json")
	require.NoError(t, err)

	decoder := sbom.NewSPDX(sbom.FormatSpdxJSON)

	sbomReport, err := decoder.Parse(f)
	require.NoError(t, err)
	require.NotNil(t, sbomReport)
	assert.Equal(t, "opensuse-leap", sbomReport.Asset.Platform.Name)
	assert.Equal(t, "15.6", sbomReport.Asset.Platform.Version)
	assert.Equal(t, "x86_64", sbomReport.Asset.Platform.Arch)
}
