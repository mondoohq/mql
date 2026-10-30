// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryBom is a BOM with one running binary, as the generator reports it.
func binaryBom() *Sbom {
	return &Sbom{
		Asset: &Asset{Name: "win-host", Platform: &Platform{Name: "windows", Version: "11"}},
		Packages: []*Package{{
			Name:     "cnspec",
			Version:  "14.4.0",
			Type:     "binary",
			Supplier: "Mondoo, Inc.",
			BomRef:   `binary:C:\Program Files\Mondoo\cnspec.exe`,
			EvidenceList: []*Evidence{{
				Type:  EvidenceType_EVIDENCE_TYPE_FILE,
				Value: `C:\Program Files\Mondoo\cnspec.exe`,
			}},
			Hashes: []*Hash{{Alg: "SHA-256", Value: "1f3d442a8d6faa2a9e11fd39f7c1344a590f61d2394dec1f4034a7930592f933"}},
			IdentityEvidence: []*IdentityEvidence{{
				Field:          "version",
				ConcludedValue: "14.4.0",
				Technique:      "binary-analysis",
				Confidence:     0.9,
				Value:          "peVersionInfo",
			}},
			Signature: &CodeSignature{
				Status:             "valid",
				SignerOrganization: "Mondoo, Inc.",
				SignerCommonName:   "Mondoo, Inc.",
			},
		}},
	}
}

func renderBinaryBom(t *testing.T, format string, opts ...renderOption) []byte {
	t.Helper()
	h := New(format)
	h.ApplyOptions(opts...)
	buf := bytes.Buffer{}
	require.NoError(t, h.Render(&buf, binaryBom()))
	return buf.Bytes()
}

// binaryComponent is the part of a rendered CycloneDX component these tests read.
type binaryComponent struct {
	Name     string `json:"name"`
	Evidence struct {
		Identity []struct {
			Field          string  `json:"field"`
			Confidence     float64 `json:"confidence"`
			ConcludedValue string  `json:"concludedValue"`
			Methods        []struct {
				Technique  string  `json:"technique"`
				Confidence float64 `json:"confidence"`
				Value      string  `json:"value"`
			} `json:"methods"`
		} `json:"identity"`
		Occurrences []struct {
			Location string `json:"location"`
		} `json:"occurrences"`
	} `json:"evidence"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

func TestCycloneDXBinaryEvidence(t *testing.T) {
	var doc struct {
		Components []binaryComponent `json:"components"`
	}
	require.NoError(t, json.Unmarshal(renderBinaryBom(t, FormatCycloneDxJSON, WithEvidence()), &doc))

	var c *binaryComponent
	for i := range doc.Components {
		if doc.Components[i].Name == "cnspec" {
			c = &doc.Components[i]
		}
	}
	require.NotNil(t, c)

	// where the file is, and how its version was concluded
	require.Len(t, c.Evidence.Occurrences, 1)
	assert.Equal(t, `C:\Program Files\Mondoo\cnspec.exe`, c.Evidence.Occurrences[0].Location)
	require.Len(t, c.Evidence.Identity, 1)
	id := c.Evidence.Identity[0]
	assert.Equal(t, "version", id.Field)
	assert.Equal(t, "14.4.0", id.ConcludedValue)
	assert.InDelta(t, 0.9, id.Confidence, 0.001)
	require.Len(t, id.Methods, 1)
	assert.Equal(t, "binary-analysis", id.Methods[0].Technique)
	assert.Equal(t, "peVersionInfo", id.Methods[0].Value)

	// the signature, which evidence has no place for
	props := map[string]string{}
	for _, p := range c.Properties {
		props[p.Name] = p.Value
	}
	assert.Equal(t, map[string]string{
		"mondoo:signature:status":              "valid",
		"mondoo:signature:signer:organization": "Mondoo, Inc.",
		"mondoo:signature:signer:commonName":   "Mondoo, Inc.",
	}, props)
}

func TestCycloneDXBinaryRoundTrip(t *testing.T) {
	h := New(FormatCycloneDxJSON)
	h.ApplyOptions(WithEvidence())
	buf := bytes.Buffer{}
	require.NoError(t, h.Render(&buf, binaryBom()))
	out, err := h.Parse(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	pkg := findPkg(t, out, "cnspec")
	want := binaryBom().Packages[0]
	assert.Equal(t, want.Signature.Status, pkg.GetSignature().GetStatus())
	assert.Equal(t, want.Signature.SignerOrganization, pkg.GetSignature().GetSignerOrganization())
	assert.Equal(t, want.Signature.SignerCommonName, pkg.GetSignature().GetSignerCommonName())
	require.Len(t, pkg.GetIdentityEvidence(), 1)
	got := pkg.GetIdentityEvidence()[0]
	assert.Equal(t, "version", got.Field)
	assert.Equal(t, "14.4.0", got.ConcludedValue)
	assert.Equal(t, "binary-analysis", got.Technique)
	assert.Equal(t, "peVersionInfo", got.Value)
	assert.InDelta(t, 0.9, got.Confidence, 0.001)
}

func TestCycloneDXBinaryWithoutEvidenceOption(t *testing.T) {
	// identity evidence follows the evidence opt-in; the signature is not
	// evidence and is always rendered
	out := string(renderBinaryBom(t, FormatCycloneDxJSON))
	assert.NotContains(t, out, `"identity"`)
	assert.Contains(t, out, "mondoo:signature:status")
}

func TestSpdxBinary(t *testing.T) {
	var doc struct {
		Packages []struct {
			Name            string `json:"name"`
			PackageFileName string `json:"packageFileName"`
			Comment         string `json:"comment"`
		} `json:"packages"`
	}
	require.NoError(t, json.Unmarshal(renderBinaryBom(t, FormatSpdxJSON), &doc))
	require.Len(t, doc.Packages, 1)
	p := doc.Packages[0]

	// the binary is the file: its path is the package's file name
	assert.Equal(t, `C:\Program Files\Mondoo\cnspec.exe`, p.PackageFileName)
	assert.Equal(t, "mondoo:identity:version: 14.4.0 by binary-analysis from peVersionInfo (confidence 0.9)\n"+
		"mondoo:signature:status: valid\n"+
		"mondoo:signature:signer:organization: Mondoo, Inc.\n"+
		"mondoo:signature:signer:commonName: Mondoo, Inc.", p.Comment)

	// and is read back as the package's location
	h := New(FormatSpdxJSON)
	out, err := h.Parse(bytes.NewReader(renderBinaryBom(t, FormatSpdxJSON)))
	require.NoError(t, err)
	assert.Equal(t, `C:\Program Files\Mondoo\cnspec.exe`, findPkg(t, out, "cnspec").Location)
}

func TestSpdxPackageFileNameOnlyForBinaries(t *testing.T) {
	// an OS package's file evidence is its database entry, not the package
	pkg := &Package{
		Name: "bash",
		Type: "deb",
		EvidenceList: []*Evidence{{
			Type:  EvidenceType_EVIDENCE_TYPE_FILE,
			Value: "/var/lib/dpkg/info/bash.list",
		}},
	}
	assert.Equal(t, "", spdxPackageFileName(pkg))
	assert.Equal(t, "", spdxPackageComment(pkg))
}
