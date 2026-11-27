// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
	"go.mondoo.com/mql/sbom"
	"go.mondoo.com/mql/sbom/generator"
)

// The schemas in testdata/schema are the official ones, unchanged:
//
//   - CycloneDX 1.7: bom-1.7.schema.json and the three files it refers to, from
//     https://github.com/CycloneDX/specification/tree/1.7/schema
//   - SPDX 2.3: spdx-2.3.schema.json, from
//     https://github.com/spdx/spdx-spec/blob/support/2.3/schemas/spdx-schema.json

// schemaBoms returns the documents the schema tests render: scan reports of
// real systems, and one document of license values that package metadata holds
// and that a strict consumer has rejected before.
func schemaBoms(t *testing.T) map[string]*sbom.Sbom {
	t.Helper()
	boms := map[string]*sbom.Sbom{}
	for _, name := range []string{"alpine", "linux-running-binaries", "windows-print-drivers"} {
		report, err := generator.LoadReport("./testdata/" + name + ".json")
		require.NoError(t, err)
		boms[name] = generator.GenerateBom(report)[0]
	}

	declared := func(name, license string) *sbom.Package {
		return &sbom.Package{
			Name: name, Version: "1.0", Purl: "pkg:npm/" + name + "@1.0",
			Licenses: sbom.DeclaredLicenses(license),
		}
	}
	boms["licenses"] = &sbom.Sbom{
		Asset:     &sbom.Asset{Name: "licenses", Platform: &sbom.Platform{Name: "macos", Version: "15.1"}},
		Generator: &sbom.Generator{Vendor: "Mondoo, Inc.", Name: "test", Version: "1.0.0"},
		Packages: []*sbom.Package{
			declared("listed", "MIT"),
			declared("lower-case", "mit"),
			declared("or-later", "Apache-2.0+"),
			declared("expression", "(MIT OR Apache-2.0) AND BSD-3-Clause"),
			declared("exception", "GPL-2.0-only WITH Classpath-exception-2.0"),
			declared("unlicensed", "UNLICENSED"),
			declared("unknown", "UNKNOWN"),
			declared("unlisted-operand", "MIT AND UNKNOWN"),
			declared("free-text", "BSD-like, see LICENSE"),
			declared("license-ref", "LicenseRef-Acme"),
			declared("none", "NONE"),
			declared("noassertion", "NOASSERTION"),
			{Name: "scalar-unknown", Version: "1.0", Purl: "pkg:npm/scalar-unknown@1.0", License: "UNKNOWN"},
			{Name: "scalar-free-text", Version: "1.0", Purl: "pkg:npm/scalar-free-text@1.0", License: "GPLv2+ and MIT"},
			{Name: "undeclared", Version: "1.0", Purl: "pkg:npm/undeclared@1.0"},
		},
	}
	return boms
}

func renderForSchema(t *testing.T, format string, bom *sbom.Sbom) []byte {
	t.Helper()
	handler := sbom.New(format)
	handler.ApplyOptions(sbom.WithEvidence(), sbom.WithCPE())
	var out strings.Builder
	require.NoError(t, handler.Render(&out, bom))
	return []byte(out.String())
}

// requireSchemaValid validates doc against a schema in testdata/schema. The
// schemas in refs are loaded from the same directory first: a schema refers to
// them by a URL under its "$id", and a test must not fetch them.
func requireSchemaValid(t *testing.T, doc []byte, schemaFile string, refs ...string) {
	t.Helper()
	read := func(name string) gojsonschema.JSONLoader {
		raw, err := os.ReadFile(filepath.Join("testdata", "schema", name))
		require.NoError(t, err)
		return gojsonschema.NewBytesLoader(raw)
	}
	loader := gojsonschema.NewSchemaLoader()
	for _, ref := range refs {
		require.NoError(t, loader.AddSchemas(read(ref)))
	}
	schema, err := loader.Compile(read(schemaFile))
	require.NoError(t, err)
	result, err := schema.Validate(gojsonschema.NewBytesLoader(doc))
	require.NoError(t, err)
	for _, e := range result.Errors() {
		t.Errorf("%s: %s", schemaFile, e)
	}
}

// TestCycloneDXIsSchemaValid validates rendered documents against the official
// CycloneDX 1.7 schema. The schema restricts license.id to the SPDX license
// list, which a value such as "UNLICENSED" is not on.
func TestCycloneDXIsSchemaValid(t *testing.T) {
	for name, bom := range schemaBoms(t) {
		t.Run(name, func(t *testing.T) {
			requireSchemaValid(t, renderForSchema(t, sbom.FormatCycloneDxJSON, bom), "bom-1.7.schema.json",
				"spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json")
		})
	}
}

// TestSPDXIsSchemaValid validates rendered documents against the official SPDX
// 2.3 schema, and then checks what the schema cannot.
//
// The schema types a license field as a string, so it accepts any value. The
// specification does not: each operand of the expression must be an identifier
// on the SPDX license list or a LicenseRef-* that the document defines.
func TestSPDXIsSchemaValid(t *testing.T) {
	var listed struct {
		Enum []string `json:"enum"`
	}
	list, err := os.ReadFile(filepath.Join("testdata", "schema", "spdx.schema.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(list, &listed))
	onList := map[string]bool{}
	for _, id := range listed.Enum {
		onList[strings.ToLower(id)] = true
	}

	for name, bom := range schemaBoms(t) {
		t.Run(name, func(t *testing.T) {
			raw := renderForSchema(t, sbom.FormatSpdxJSON, bom)
			requireSchemaValid(t, raw, "spdx-2.3.schema.json")

			var doc struct {
				Packages []struct {
					Name             string `json:"name"`
					LicenseDeclared  string `json:"licenseDeclared"`
					LicenseConcluded string `json:"licenseConcluded"`
				} `json:"packages"`
				HasExtractedLicensingInfos []struct {
					LicenseID string `json:"licenseId"`
				} `json:"hasExtractedLicensingInfos"`
			}
			require.NoError(t, json.Unmarshal(raw, &doc))
			defined := map[string]bool{}
			for _, e := range doc.HasExtractedLicensingInfos {
				defined[e.LicenseID] = true
			}

			for _, p := range doc.Packages {
				for field, value := range map[string]string{
					"licenseDeclared": p.LicenseDeclared, "licenseConcluded": p.LicenseConcluded,
				} {
					if value == "NONE" || value == "NOASSERTION" {
						continue
					}
					exception := false
					for _, operand := range strings.FieldsFunc(value, func(r rune) bool {
						return r == ' ' || r == '(' || r == ')'
					}) {
						switch {
						case operand == "AND" || operand == "OR":
						case operand == "WITH":
							exception = true
						case exception:
							exception = false
						case strings.HasPrefix(operand, "LicenseRef-"):
							if !defined[operand] {
								t.Errorf("%s %s = %q: %s is not in hasExtractedLicensingInfos", p.Name, field, value, operand)
							}
						case !onList[strings.ToLower(strings.TrimSuffix(operand, "+"))]:
							t.Errorf("%s %s = %q: %s is not on the SPDX license list", p.Name, field, value, operand)
						}
					}
				}
			}
		})
	}
}
