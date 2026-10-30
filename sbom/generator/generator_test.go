// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestPurlType(t *testing.T) {
	assert.Equal(t, "terraform", purlType("pkg:terraform/hashicorp/aws@5.31.0", "terraform"))
	assert.Equal(t, "opentofu", purlType("pkg:opentofu/hashicorp/aws@5.31.0", "terraform"))
	assert.Equal(t, "terraform-module", purlType("pkg:terraform-module/acme/vpc@1.0.0?target_system=aws", "terraform"))
	assert.Equal(t, "generic", purlType("pkg:generic/github.com/acme/mods@v1", "terraform"))
	// A package with no purl keeps the ecosystem's own label.
	assert.Equal(t, "terraform", purlType("", "terraform"))
	assert.Equal(t, "terraform", purlType("not-a-purl", "terraform"))
}

// TestRunningBinariesInSbom covers the executables of running processes that
// no installed package owns reaching the SBOM.
//
// The node, php8.3-cli and environment-manager rows, digests included, are
// the values a scan of an Ubuntu 24.04 host returned. The second
// environment-manager row, a different file of the same name at another
// path, is synthetic.
//
// The fixture carries the verbatim datapoint label. The query filters with
// where(), so the label is "runningBinaries.where.list"; a mismatch with the
// BomFields tag leaves the binaries out of the SBOM without any error.
func TestRunningBinariesInSbom(t *testing.T) {
	report, err := LoadReport("../testdata/linux-running-binaries.json")
	require.NoError(t, err)

	boms := GenerateBom(report)
	require.Len(t, boms, 1)
	bom := boms[0]
	assert.Equal(t, sbom.Status_STATUS_SUCCEEDED, bom.Status)

	// a binary is reported by name, version, path and digest; the purl is
	// derived downstream
	node := findProtoPkg(bom.Packages, "node")
	require.NotNil(t, node, "the running binary did not reach the SBOM")
	assert.Equal(t, &sbom.Package{
		Name:    "node",
		Version: "22.22.0",
		Type:    "binary",
		BomRef:  "binary:/opt/node22/bin/node",
		EvidenceList: []*sbom.Evidence{{
			Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
			Value: "/opt/node22/bin/node",
		}},
		Hashes: []*sbom.Hash{{Alg: "SHA-256", Value: "1f3d442a8d6faa2a9e11fd39f7c1344a590f61d2394dec1f4034a7930592f933"}},
	}, node)

	// a binary without a version is listed, and two files of one name stay
	// two components, told apart by path and digest
	var unversioned []string
	for _, pkg := range bom.Packages {
		if pkg.Name == "environment-manager" {
			assert.Empty(t, pkg.Version)
			require.Len(t, pkg.Hashes, 1)
			unversioned = append(unversioned, pkg.BomRef+" "+pkg.Hashes[0].Value)
		}
	}
	assert.Equal(t, []string{
		"binary:/opt/env-runner/environment-manager dac1cfd088ae9c97b58b87e8a09d3f60432c9fa294581f1bc32ad0589db89241",
		"binary:/srv/other/environment-manager 0f5c5b0e9a3d4c7b8e2f1a6d9c3b7e4a1f8d2c6b9e3a7d4c1b8f2e6a9d3c7b4e",
	}, unversioned)

	// the package inventory is untouched
	assert.NotNil(t, findProtoPkg(bom.Packages, "php8.3-cli"))
}

func TestRunningBinaryPackagesSupplier(t *testing.T) {
	// the vendor a binary names is its supplier, which both formats render
	pkgs := runningBinaryPackages([]BomPackage{{
		Name:    "cnspec",
		Version: "14.4.0",
		Vendor:  "Mondoo, Inc.",
		Path:    `C:\Program Files\Mondoo\cnspec.exe`,
	}})
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Mondoo, Inc.", pkgs[0].Supplier)
	assert.Equal(t, "Mondoo, Inc.", pkgs[0].Vendor)
}

func TestRunningBinaryPackagesEvidenceAndSignature(t *testing.T) {
	// one row of runningBinaries.where.list, labeled as the query's fields
	// are: signer.subject.organization is a list
	var bins []BomPackage
	require.NoError(t, json.Unmarshal([]byte(`[
  {
    "name": "cnspec",
    "version": "14.4.0",
    "vendor": "Mondoo, Inc.",
    "path": "C:\\Program Files\\Mondoo\\cnspec.exe",
    "sha256": "1f3d442a8d6faa2a9e11fd39f7c1344a590f61d2394dec1f4034a7930592f933",
    "versionSource": "peVersionInfo",
    "signatureStatus": "valid",
    "signer.subject.organization": ["Mondoo, Inc."],
    "signer.subject.commonName": "Mondoo, Inc."
  },
  {
    "name": "environment-manager",
    "version": "",
    "path": "/opt/env-runner/environment-manager",
    "versionSource": "",
    "signatureStatus": null,
    "signer.subject.organization": null,
    "signer.subject.commonName": null
  }
]`), &bins))

	pkgs := runningBinaryPackages(bins)
	require.Len(t, pkgs, 2)

	assert.Equal(t, []*sbom.IdentityEvidence{{
		Field:          "version",
		ConcludedValue: "14.4.0",
		Technique:      "binary-analysis",
		Confidence:     0.9,
		Value:          "peVersionInfo",
	}}, pkgs[0].IdentityEvidence)
	assert.Equal(t, &sbom.CodeSignature{
		Status:             "valid",
		SignerOrganization: "Mondoo, Inc.",
		SignerCommonName:   "Mondoo, Inc.",
	}, pkgs[0].Signature)

	// no version and no signature check (Linux): neither is stated
	assert.Nil(t, pkgs[1].IdentityEvidence)
	assert.Nil(t, pkgs[1].Signature)
}
