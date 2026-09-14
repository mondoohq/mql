// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
	"go.mondoo.com/mql/sbom/generator"
)

func TestCycloneDxOutput(t *testing.T) {
	report, err := generator.LoadReport("./testdata/alpine.json")
	require.NoError(t, err)

	sboms := generator.GenerateBom(report)

	// store bom in different formats
	selectedBom := sboms[0]

	exporter := sbom.New(sbom.FormatCycloneDxJSON)
	exporter.ApplyOptions(sbom.WithCPE(), sbom.WithEvidence())

	output := bytes.Buffer{}
	err = exporter.Render(&output, selectedBom)
	require.NoError(t, err)
	data := output.String()

	// os.WriteFile("./testdata/bom_cyclone.json", output.Bytes(), 0700)
	assert.Contains(t, data, "cyclonedx")

	// ensure os package is included
	assert.Contains(t, data, "alpine-baselayout")
	assert.Contains(t, data, "cpe:2.3:a:alpine-baselayout:alpine-baselayout:1695795276:aarch64:*:*:*:*:*:*")
	// check that package files are included
	assert.Contains(t, data, "etc/profile.d/color_prompt.sh.disabled")

	// ensure python package is included
	assert.Contains(t, data, "pip")
	assert.Contains(t, data, "cpe:2.3:a:pip_project:pip:21.2.4:*:*:*:*:*:*:*")
	assert.Contains(t, data, "pkg:pypi/pip@21.2.4")

	// ensure npm package is included
	assert.Contains(t, data, "npm")
	assert.Contains(t, data, "cpe:2.3:a:npm:npm:10.2.4:*:*:*:*:*:*:*")
	assert.Contains(t, data, "pkg:npm/npm@10.2.4")
}

func TestCycloneDxJsonDecoding(t *testing.T) {
	t.Run("alpine 3.19", func(t *testing.T) {
		f, err := os.Open("./testdata/alpine-319.cyclone.json")
		require.NoError(t, err)

		formatHandler := &sbom.CycloneDX{
			Format: cyclonedx.BOMFileFormatJSON,
		}

		bom, err := formatHandler.Parse(f)
		require.NoError(t, err)
		assert.NotNil(t, bom)
		assert.Equal(t, "alpine:3.19", bom.Asset.Name)
		assert.Equal(t, "alpine", bom.Asset.Platform.Name)
		assert.Equal(t, "3.19.1", bom.Asset.Platform.Version)
		// FIXME: support the bomRef property
		// assert.Equal(t, "//platformid.api.mondoo.app/runtime/docker/images/alpine:3.19", bom.Asset.PlatformIds[0])
	})

	t.Run("ubuntu 20.04 container", func(t *testing.T) {
		f, err := os.Open("./testdata/ubuntu-20.04-cyclonedx.json")
		require.NoError(t, err)

		formatHandler := &sbom.CycloneDX{
			Format: cyclonedx.BOMFileFormatJSON,
		}

		bom, err := formatHandler.Parse(f)
		require.NoError(t, err)
		assert.NotNil(t, bom)

		// verify we have the right asset and platform information.
		assert.Equal(t, "ubuntu", bom.Asset.Platform.Name)
		assert.Equal(t, "20.04", bom.Asset.Platform.Version)
		assert.Equal(t, []string{"linux", "unix", "os"}, bom.Asset.Platform.Family)
		assert.Equal(t, "Ubuntu 20.04.6 LTS", bom.Asset.Platform.Title)
		// this is the bom-ref
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/docker/images/e3cf4bf83104fade"}, bom.Asset.PlatformIds)
		// 1 library components + 1 os component
		assert.Len(t, bom.Packages, 2)

		// verify the generator is correct
		assert.Equal(t, "syft", bom.Generator.Name)
		assert.Equal(t, "1.38.2", bom.Generator.Version)
		assert.Equal(t, "anchore", bom.Generator.Vendor)
	})

	t.Run("ubuntu 22.04 container", func(t *testing.T) {
		f, err := os.Open("./testdata/ubuntu-22.04-cyclonedx.json")
		require.NoError(t, err)

		formatHandler := &sbom.CycloneDX{
			Format: cyclonedx.BOMFileFormatJSON,
		}

		bom, err := formatHandler.Parse(f)
		require.NoError(t, err)
		assert.NotNil(t, bom)

		// verify we have the right asset and platform information.
		assert.Equal(t, "ubuntu", bom.Asset.Platform.Name)
		assert.Equal(t, "22.04", bom.Asset.Platform.Version)
		assert.Equal(t, []string{"linux", "unix", "os"}, bom.Asset.Platform.Family)
		assert.Equal(t, "Ubuntu 22.04.5 LTS", bom.Asset.Platform.Title)
		// this is the bom-ref
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/docker/images/2e194621f3c81dfe"}, bom.Asset.PlatformIds)
		// 1 library components + 1 os component
		assert.Len(t, bom.Packages, 2)

		// verify the generator is correct
		assert.Equal(t, "syft", bom.Generator.Name)
		assert.Equal(t, "1.38.2", bom.Generator.Version)
		assert.Equal(t, "anchore", bom.Generator.Vendor)
	})
}

func TestCycloneDxXmlDecoding(t *testing.T) {
	f, err := os.Open("./testdata/alpine-319.cyclone.xml")
	require.NoError(t, err)

	formatHandler := &sbom.CycloneDX{
		Format: cyclonedx.BOMFileFormatXML,
	}

	bom, err := formatHandler.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, bom)
}

// syft dir:./next.js --source-name next.js_v15.4.1 -o cyclonedx-json > nextjs_v15_4_1.cyclonedx.json
func TestCycloneDxJsonDecoding_repo(t *testing.T) {
	f, err := os.Open("./testdata/nextjs_v15_4_1.cyclonedx.json")
	require.NoError(t, err)

	formatHandler := &sbom.CycloneDX{
		Format: cyclonedx.BOMFileFormatJSON,
	}

	bom, err := formatHandler.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, bom)
	assert.Equal(t, "next.js_v15.4.1", bom.Asset.Name)
	assert.Equal(t, "cyclonedx", bom.Asset.Platform.Name)
	assert.Equal(t, "1.6", bom.Asset.Platform.Version)
	assert.Equal(t, "CycloneDX", bom.Asset.Platform.Title)
}

func TestCycloneDxJsonDecoding_Alpine_syft(t *testing.T) {
	f, err := os.Open("./testdata/alpine-3.19.cyclonedx.syft.json")
	require.NoError(t, err)

	formatHandler := &sbom.CycloneDX{
		Format: cyclonedx.BOMFileFormatJSON,
	}

	bom, err := formatHandler.Parse(f)
	require.NoError(t, err)
	assert.NotNil(t, bom)
	assert.Equal(t, "alpine", bom.Asset.Name)
	assert.Equal(t, "alpine", bom.Asset.Platform.Name)
	assert.Equal(t, "3.19.9", bom.Asset.Platform.Version)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/docker/images/cd03a8ea6f29f815", bom.Asset.PlatformIds[0])
}

// TestCycloneDXRoundTripPreservesDependencyGraph pins the edge graph across a
// render/parse cycle.
//
// The renderer always wrote `dependencies`/`dependsOn`; the reader discarded
// it, so Parse returned an Sbom with no edges at all and the round-trip was
// silently lossy in the one field that distinguishes a transitive dependency
// something reaches from one nothing reaches.
// TestCycloneDxJsonDecoding_CentosStreamFamily covers the ingest fallback for a
// document written by another tool, which carries no mondoo:platform:* property
// for the reader to take the family from. The platform name is then the only
// thing left to derive it from, and CentOS Stream is named in full there rather
// than as centos.
//
// The expected chain is spelled out rather than read back from familyMap: an
// expectation taken from the same map the implementation reads agrees with it
// by construction and cannot fail.
func TestCycloneDxJsonDecoding_CentosStreamFamily(t *testing.T) {
	doc := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "version": 1,
	  "metadata": {
	    "component": {
	      "type": "operating-system",
	      "name": "centos-stream",
	      "version": "9",
	      "description": "CentOS Stream 9"
	    }
	  },
	  "components": [
	    {
	      "type": "operating-system",
	      "name": "centos-stream",
	      "version": "9",
	      "description": "CentOS Stream 9"
	    }
	  ]
	}`

	formatHandler := &sbom.CycloneDX{Format: cyclonedx.BOMFileFormatJSON}
	bom, err := formatHandler.Parse(bytes.NewReader([]byte(doc)))
	require.NoError(t, err)
	require.NotNil(t, bom)

	assert.Equal(t, "centos-stream", bom.Asset.Platform.Name)
	assert.Equal(t, "9", bom.Asset.Platform.Version)
	assert.Equal(t, []string{"linux", "unix", "os"}, bom.Asset.Platform.Family)
}

func TestCycloneDXRoundTripPreservesDependencyGraph(t *testing.T) {
	in := &sbom.Sbom{
		Asset: &sbom.Asset{Name: "app", Platform: &sbom.Platform{Name: "alpine", Version: "3.19"}},
		Packages: []*sbom.Package{
			{Name: "a", Version: "1", Purl: "pkg:maven/g/a@1", Type: "maven"},
			{Name: "b", Version: "2", Purl: "pkg:maven/g/b@2", Type: "maven"},
		},
		Dependencies: []*sbom.Dependency{
			{Ref: "pkg:maven/g/a@1", DependencyRefs: []string{"pkg:maven/g/b@2"}},
		},
	}

	var buf bytes.Buffer
	cdx := sbom.NewCycloneDX("json")
	require.NoError(t, cdx.Render(&buf, in))

	out, err := cdx.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	require.Len(t, out.Dependencies, 1, "the edge graph must survive the round-trip")
	assert.Equal(t, "pkg:maven/g/a@1", out.Dependencies[0].Ref)
	assert.Equal(t, []string{"pkg:maven/g/b@2"}, out.Dependencies[0].DependencyRefs)
}

// TestCycloneDXImportDropsSelfAndEmptyEdges — a self-edge is a no-op that
// invites a consumer's traversal to loop, and an entry with no targets states
// the ABSENCE of edges rather than an edge.
func TestCycloneDXImportDropsSelfAndEmptyEdges(t *testing.T) {
	doc := `{
      "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
      "metadata": {"component": {"bom-ref": "root:app", "type": "application", "name": "app"}},
      "components": [
        {"bom-ref": "pkg:maven/g/a@1", "type": "library", "name": "a", "version": "1", "purl": "pkg:maven/g/a@1"},
        {"bom-ref": "pkg:maven/g/b@2", "type": "library", "name": "b", "version": "2", "purl": "pkg:maven/g/b@2"}
      ],
      "dependencies": [
        {"ref": "pkg:maven/g/a@1", "dependsOn": ["pkg:maven/g/a@1", "pkg:maven/g/b@2"]},
        {"ref": "pkg:maven/g/b@2", "dependsOn": []}
      ]
    }`

	out, err := sbom.NewCycloneDX("json").Parse(bytes.NewReader([]byte(doc)))
	require.NoError(t, err)

	require.Len(t, out.Dependencies, 1, "the targetless entry must not become an edge")
	assert.Equal(t, []string{"pkg:maven/g/b@2"}, out.Dependencies[0].DependencyRefs,
		"the self-edge must be dropped")
}
