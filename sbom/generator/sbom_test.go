// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"strings"
	"testing"

	"go.mondoo.com/mql/cli/reporter"
	"go.mondoo.com/mql/sbom"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSbomGeneration(t *testing.T) {
	t.Run("generate sbom from a full report", func(t *testing.T) {
		report, err := LoadReport("../testdata/alpine.json")
		require.NoError(t, err)

		sboms := GenerateBom(report)

		// store bom in different formats
		selectedBom := sboms[0]

		assert.Equal(t, "alpine:latest", selectedBom.Asset.Name)
		assert.Equal(t, "trace-alpine", selectedBom.Asset.TraceId)
		assert.Equal(t, "aarch64", selectedBom.Asset.Platform.Arch)
		assert.Equal(t, "alpine", selectedBom.Asset.Platform.Name)
		assert.Equal(t, "3.19.0", selectedBom.Asset.Platform.Version)
		assert.Equal(t, []string{"//platformid.api.mondoo.app/runtime/docker/images/1dc785547989b0db1c3cd9949c57574393e69bea98bfe044b0588e24721aa402"}, selectedBom.Asset.PlatformIds)

		// search os package
		pkg := findProtoPkg(selectedBom.Packages, "alpine-baselayout")
		assert.Equal(t, "alpine-baselayout", pkg.Name)
		assert.Contains(t, pkg.EvidenceList, &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: "etc/profile.d/color_prompt.sh.disabled",
		})

		// search python package
		pkg = findProtoPkg(selectedBom.Packages, "pip")
		assert.Equal(t, "pip", pkg.Name)
		assert.Contains(t, pkg.EvidenceList, &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: "/opt/lib/python3.9/site-packages/pip-21.2.4.dist-info/METADATA",
		})

		// search npm package
		pkg = findProtoPkg(selectedBom.Packages, "npm")
		assert.Equal(t, "npm", pkg.Name)
		assert.Contains(t, pkg.EvidenceList, &sbom.Evidence{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: "/opt/lib/node_modules/npm/package.json",
		})
	})

	t.Run("generate sbom from a report with a sbom package error", func(t *testing.T) {
		report, err := LoadReport("testdata/alpine-failed-sbom-package.json")
		require.NoError(t, err)

		sboms := GenerateBom(report)

		selectedBom := sboms[0]
		assert.Equal(t, sbom.Status_STATUS_PARTIALLY_SUCCEEDED, selectedBom.Status)
		assert.Contains(t, selectedBom.ErrorMessage, "failed to parse bom fields json data")
		assert.Len(t, selectedBom.Packages, 2)

		pkg := findProtoPkg(selectedBom.Packages, "npm")
		require.Equal(t, &sbom.Package{
			Name: "npm",
			Type: "npm",
			Cpes: []string{
				"cpe:2.3:a:npm:npm:10.2.4:*:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "/opt/lib/node_modules/npm/package.json",
				},
			},
			Purl:    "pkg:npm/npm@10.2.4",
			BomRef:  "pkg:npm/npm@10.2.4",
			Version: "10.2.4",
		}, pkg)

		pkg = findProtoPkg(selectedBom.Packages, "pip")
		require.Equal(t, &sbom.Package{
			Name: "pip",
			Type: "pypi",
			Cpes: []string{
				"cpe:2.3:a:pip_project:pip:21.2.4:*:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "/opt/lib/python3.9/site-packages/pip-21.2.4.dist-info/METADATA",
				},
			},
			Purl:    "pkg:pypi/pip@21.2.4",
			BomRef:  "pkg:pypi/pip@21.2.4",
			Version: "21.2.4",
		}, pkg)
	})

	t.Run("generate sbom from a report with a npm package error", func(t *testing.T) {
		report, err := LoadReport("testdata/alpine-failed-npm-package.json")
		require.NoError(t, err)

		sboms := GenerateBom(report)

		selectedBom := sboms[0]
		assert.Equal(t, sbom.Status_STATUS_PARTIALLY_SUCCEEDED, selectedBom.Status)
		assert.Contains(t, selectedBom.ErrorMessage, "failed to parse bom fields json data")
		assert.Len(t, selectedBom.Packages, 2)

		pkg := findProtoPkg(selectedBom.Packages, "apk-tools")
		require.Equal(t, &sbom.Package{
			Name: "apk-tools",
			Type: "apk",
			Cpes: []string{
				"cpe:2.3:a:apk-tools:apk-tools:1684120357:aarch64:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "lib/libapk.so.2.14.0",
				},
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "sbin/apk",
				},
			},
			Purl:    "pkg:apk/alpine/apk-tools@1684120357%3A2.14.0-r5?arch=aarch64\u0026distro=alpine-3.19.0\u0026epoch=1684120357",
			BomRef:  "pkg:apk/alpine/apk-tools@1684120357%3A2.14.0-r5?arch=aarch64\u0026distro=alpine-3.19.0\u0026epoch=1684120357",
			Version: "1684120357:2.14.0-r5",
		}, pkg)

		pkg = findProtoPkg(selectedBom.Packages, "pip")
		require.Equal(t, &sbom.Package{
			Name: "pip",
			Type: "pypi",
			Cpes: []string{
				"cpe:2.3:a:pip_project:pip:21.2.4:*:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "/opt/lib/python3.9/site-packages/pip-21.2.4.dist-info/METADATA",
				},
			},
			Purl:    "pkg:pypi/pip@21.2.4",
			BomRef:  "pkg:pypi/pip@21.2.4",
			Version: "21.2.4",
		}, pkg)
	})

	t.Run("generate sbom from a report with a python package error", func(t *testing.T) {
		report, err := LoadReport("testdata/alpine-failed-python-package.json")
		require.NoError(t, err)

		sboms := GenerateBom(report)

		selectedBom := sboms[0]
		assert.Equal(t, sbom.Status_STATUS_PARTIALLY_SUCCEEDED, selectedBom.Status)
		assert.Contains(t, selectedBom.ErrorMessage, "failed to parse bom fields json data")
		assert.Len(t, selectedBom.Packages, 2)

		pkg := findProtoPkg(selectedBom.Packages, "apk-tools")
		require.Equal(t, &sbom.Package{
			Name: "apk-tools",
			Type: "apk",
			Cpes: []string{
				"cpe:2.3:a:apk-tools:apk-tools:1684120357:aarch64:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "lib/libapk.so.2.14.0",
				},
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "sbin/apk",
				},
			},
			Purl:    "pkg:apk/alpine/apk-tools@1684120357%3A2.14.0-r5?arch=aarch64\u0026distro=alpine-3.19.0\u0026epoch=1684120357",
			BomRef:  "pkg:apk/alpine/apk-tools@1684120357%3A2.14.0-r5?arch=aarch64\u0026distro=alpine-3.19.0\u0026epoch=1684120357",
			Version: "1684120357:2.14.0-r5",
		}, pkg)

		pkg = findProtoPkg(selectedBom.Packages, "npm")
		require.Equal(t, &sbom.Package{
			Name: "npm",
			Type: "npm",
			Cpes: []string{
				"cpe:2.3:a:npm:npm:10.2.4:*:*:*:*:*:*:*",
			},
			EvidenceList: []*sbom.Evidence{
				{
					Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
					Value: "/opt/lib/node_modules/npm/package.json",
				},
			},
			Purl:    "pkg:npm/npm@10.2.4",
			BomRef:  "pkg:npm/npm@10.2.4",
			Version: "10.2.4",
		}, pkg)
	})

	// STATUS_FAILED semantics are unchanged by the PARTIALLY_SUCCEEDED work
	// above: an asset with no data points at all produced nothing to build a
	// BOM from, which is still a failure, not a partial result.
	t.Run("no data points at all is still STATUS_FAILED", func(t *testing.T) {
		report := &reporter.Report{
			Assets: map[string]*reporter.Asset{
				"asset-1": {Mrn: "asset-1", Name: "no-data-asset"},
			},
			Data: map[string]*reporter.DataValues{},
		}

		sboms := GenerateBom(report)
		require.Len(t, sboms, 1)
		assert.Equal(t, sbom.Status_STATUS_FAILED, sboms[0].Status)
		assert.Equal(t, "no data points found", sboms[0].ErrorMessage)
		assert.Empty(t, sboms[0].Packages)
	})

	// Two data points that each fail to decode must both show up in
	// ErrorMessage, not just whichever one happened to be handled last -- the
	// previous implementation overwrote ErrorMessage per failing data point
	// instead of accumulating. And since every data point that exists failed
	// to decode, nothing usable was produced for this asset: STATUS_FAILED,
	// not STATUS_PARTIALLY_SUCCEEDED with zero packages.
	t.Run("all data points failing to decode is STATUS_FAILED and ErrorMessage accumulates", func(t *testing.T) {
		report := &reporter.Report{
			Assets: map[string]*reporter.Asset{
				"asset-1": {Mrn: "asset-1", Name: "multi-error-asset"},
			},
			Data: map[string]*reporter.DataValues{
				"asset-1": {
					Values: map[string]*reporter.DataValue{
						"query-a": {Content: structpb.NewStringValue("the 'os' provider crashed: connection refused")},
						"query-b": {Content: structpb.NewStringValue("the 'os' provider crashed: connection refused")},
					},
				},
			},
		}

		sboms := GenerateBom(report)
		require.Len(t, sboms, 1)
		selectedBom := sboms[0]
		assert.Equal(t, sbom.Status_STATUS_FAILED, selectedBom.Status)
		assert.Empty(t, selectedBom.Packages)
		assert.Contains(t, selectedBom.ErrorMessage, "query-a: ")
		assert.Contains(t, selectedBom.ErrorMessage, "query-b: ")
		// Two independent messages, not one overwriting the other.
		assert.Equal(t, 2, strings.Count(selectedBom.ErrorMessage, "failed to parse bom fields json data"))
	})

	// A data point that decodes cleanly but legitimately yields zero
	// packages (e.g. it only carries asset info) sits alongside one that
	// fails to decode. "Nothing usable" must be judged by decode success,
	// not by the resulting package count -- so this is a partial success,
	// not a failure, even though bom.Packages ends up empty.
	t.Run("one decoded data point with no packages plus one failure is PARTIALLY_SUCCEEDED", func(t *testing.T) {
		// A real successful data point arrives as a structured value (what
		// protojson renders as a JSON object), not a JSON-encoded string --
		// the failure fixtures above use NewStringValue specifically because
		// unmarshaling a JSON string into the BomFields struct is how they
		// induce a decode failure. Building this one from a Go map instead
		// makes it decode successfully, the way real query data does.
		assetOnly, err := structpb.NewValue(map[string]any{
			"asset": map[string]any{"name": "asset-only-asset"},
		})
		require.NoError(t, err)

		report := &reporter.Report{
			Assets: map[string]*reporter.Asset{
				"asset-1": {Mrn: "asset-1", Name: "asset-only-asset"},
			},
			Data: map[string]*reporter.DataValues{
				"asset-1": {
					Values: map[string]*reporter.DataValue{
						"query-asset": {Content: assetOnly},
						"query-bad":   {Content: structpb.NewStringValue("the 'os' provider crashed: connection refused")},
					},
				},
			},
		}

		sboms := GenerateBom(report)
		require.Len(t, sboms, 1)
		selectedBom := sboms[0]
		assert.Equal(t, sbom.Status_STATUS_PARTIALLY_SUCCEEDED, selectedBom.Status)
		assert.Empty(t, selectedBom.Packages)
		assert.Contains(t, selectedBom.ErrorMessage, "query-bad: ")
	})

	// Baseline: when nothing fails to decode, status stays SUCCEEDED and
	// carries no ErrorMessage -- the FAILED/PARTIALLY_SUCCEEDED work above
	// doesn't touch this path.
	t.Run("no decode failures leaves status SUCCEEDED", func(t *testing.T) {
		report, err := LoadReport("../testdata/alpine.json")
		require.NoError(t, err)

		sboms := GenerateBom(report)
		require.NotEmpty(t, sboms)
		assert.Equal(t, sbom.Status_STATUS_SUCCEEDED, sboms[0].Status)
		assert.Empty(t, sboms[0].ErrorMessage)
		assert.NotEmpty(t, sboms[0].Packages)
	})
}

func findProtoPkg(pkgs []*sbom.Package, name string) *sbom.Package {
	for i := range pkgs {
		if pkgs[i].Name == name {
			return pkgs[i]
		}
	}
	panic("package not found: " + name)
}

func TestArnGeneration(t *testing.T) {
	platformID := "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/12345678910/regions/us-east-1/instances/i-1234567890abcdef0"
	ids := enrichPlatformIds([]string{platformID})
	assert.Equal(t, 2, len(ids))
	assert.Contains(t, ids, platformID)
	assert.Contains(t, ids, "arn:aws:ec2:us-east-1:12345678910:instance/i-1234567890abcdef0")
}
