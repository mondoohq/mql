// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/carabiner-dev/spdx3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func renderSpdx3(t *testing.T, bom *Sbom) []byte {
	t.Helper()
	handler := New(FormatSpdx3JSON)
	require.IsType(t, &Spdx3{}, handler)
	var buf bytes.Buffer
	require.NoError(t, handler.Render(&buf, bom))
	return buf.Bytes()
}

func TestSpdx3Render_RoundTrip(t *testing.T) {
	bom := &Sbom{
		Generator: &Generator{Name: "cnspec", Version: "14.4.0", Vendor: "Mondoo, Inc."},
		Asset:     &Asset{Name: "alpine-3.19", Platform: &Platform{Name: "alpine", Version: "3.19.1"}},
		Packages: []*Package{
			{
				Name:     "musl",
				Version:  "1.2.4-r2",
				Purl:     "pkg:apk/alpine/musl@1.2.4-r2?arch=aarch64&distro=alpine-3.19.1",
				Cpes:     []string{"cpe:2.3:a:musl-libc:musl:1.2.4:*:*:*:*:*:*:*", "cpe:2.3:a:musl:musl:1.2.4:*:*:*:*:*:*:*"},
				Hashes:   []*Hash{{Alg: "SHA-256", Value: "a3f1"}, {Alg: "SHA3-512", Value: "b4e2"}, {Alg: "CRC32", Value: "dropped"}},
				Licenses: []*License{DeclaredLicense("MIT")},
				License:  "MIT",
				Supplier: "Alpine Linux",
			},
			{
				Name:     "busybox",
				Version:  "1.36.1-r15",
				Purl:     "pkg:apk/alpine/busybox@1.36.1-r15?arch=aarch64&distro=alpine-3.19.1",
				Licenses: []*License{DeclaredLicense("GPL-2.0-only"), ConcludedLicense("GPL-2.0-or-later", "", 0)},
				License:  "GPL-2.0-only",
				Supplier: "Alpine Linux",
			},
		},
	}
	bom.Dependencies = []*Dependency{{Ref: BomRefFor(bom.Packages[1]), DependencyRefs: []string{BomRefFor(bom.Packages[0])}}}

	out := renderSpdx3(t, bom)

	env, err := spdx3.NewParser().Parse(bytes.NewReader(out))
	require.NoError(t, err)
	assert.Empty(t, spdx3.Validate(env), "every vocabulary value is one SPDX 3.0.1 defines")
	assert.Equal(t, spdx3.ContextURL301, env.Context.String())

	back, err := NewSPDX3().Parse(bytes.NewReader(out))
	require.NoError(t, err)

	assert.Equal(t, "alpine-3.19.1", back.Asset.Name)
	assert.Equal(t, "alpine", back.Asset.Platform.Name)
	assert.Equal(t, "3.19.1", back.Asset.Platform.Version)
	assert.Equal(t, "cnspec", back.Generator.Name)
	assert.Equal(t, "14.4.0", back.Generator.Version)
	assert.Equal(t, "Mondoo, Inc.", back.Generator.Vendor)

	require.Len(t, back.Packages, 2)
	byName := map[string]*Package{}
	for _, p := range back.Packages {
		byName[p.Name] = p
	}
	for _, want := range bom.Packages {
		got := byName[want.Name]
		require.NotNil(t, got, want.Name)
		assert.Equal(t, want.Version, got.Version)
		assert.Equal(t, want.Purl, got.Purl)
		assert.ElementsMatch(t, want.Cpes, got.Cpes, "every CPE is kept")
		assert.Equal(t, want.Supplier, got.Supplier)
		assert.Equal(t, licenseList(want), licenseList(got))
	}

	// Concluded is written only where one was concluded: musl declared MIT and
	// nothing more, so the round trip must not invent a conclusion for it.
	assert.Empty(t, concludedLicenses(byName["musl"]))

	require.Len(t, back.Dependencies, 1)
	assert.Equal(t, BomRefFor(byName["busybox"]), back.Dependencies[0].Ref)
	assert.Equal(t, []string{BomRefFor(byName["musl"])}, back.Dependencies[0].DependencyRefs)

	// Hashes are not read back by the importers, so check the document itself.
	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	var algorithms []string
	for _, node := range doc.Graph {
		if node["name"] != "musl" {
			continue
		}
		for _, h := range node["verifiedUsing"].([]any) {
			algorithms = append(algorithms, h.(map[string]any)["algorithm"].(string))
		}
	}
	assert.ElementsMatch(t, []string{"sha256", "sha3_512"}, algorithms, "an algorithm SPDX 3 cannot name is left out")
}

// licenseList summarizes a package's licenses with how each was acquired.
func licenseList(p *Package) []string {
	var out []string
	for _, l := range p.Licenses {
		out = append(out, l.Acquisition.String()+"|"+licenseValueOf(l))
	}
	slices.Sort(out)
	return out
}

func TestSpdx3Render_SharedElements(t *testing.T) {
	bom := &Sbom{
		Asset: &Asset{Name: "app", Platform: &Platform{}},
		Packages: []*Package{
			{Name: "a", Version: "1", Purl: "pkg:npm/a@1", Licenses: []*License{DeclaredLicense("MIT")}, Supplier: "Acme"},
			{Name: "b", Version: "1", Purl: "pkg:npm/b@1", Licenses: []*License{DeclaredLicense("MIT")}, Supplier: "Acme"},
			// The same package at a second install location shares a bom_ref
			// and is written once.
			{Name: "a", Version: "1", Purl: "pkg:npm/a@1", Location: "/other/node_modules/a"},
		},
	}
	out := string(renderSpdx3(t, bom))

	assert.Equal(t, 1, strings.Count(out, `"simplelicensing_licenseExpression": "MIT"`), "one license element per expression")
	assert.Equal(t, 1, strings.Count(out, `"name": "Acme"`), "one agent per supplier")
	assert.Equal(t, 2, strings.Count(out, `"type": "software_Package"`), "a package is written once per bom_ref")
}

func TestSpdx3Render_Creator(t *testing.T) {
	for name, tc := range map[string]struct {
		generator *Generator
		creator   string
		tool      bool
	}{
		"vendor and tool": {&Generator{Name: "cnspec", Version: "14.4.0", Vendor: "Mondoo, Inc."}, `"name": "Mondoo, Inc."`, true},
		"tool only":       {&Generator{Name: "cnspec", Version: "14.4.0"}, `"type": "SoftwareAgent"`, true},
		"nothing":         {nil, `"name": "anonymous"`, false},
	} {
		t.Run(name, func(t *testing.T) {
			out := string(renderSpdx3(t, &Sbom{Generator: tc.generator, Asset: &Asset{Platform: &Platform{}}}))
			assert.Contains(t, out, tc.creator)
			assert.Equal(t, tc.tool, strings.Contains(out, `"type": "Tool"`))
			// The subject has to be named, as in the SPDX 2.3 rendering.
			assert.Contains(t, out, `"name": "`+unnamedSubject+`"`)
		})
	}
}

func TestSpdx3HashAlgorithm(t *testing.T) {
	for in, want := range map[string]string{
		"SHA-1":       "sha1",
		"SHA-256":     "sha256",
		"SHA-512":     "sha512",
		"SHA3-256":    "sha3_256",
		"BLAKE2b-512": "blake2b512",
		"BLAKE3":      "blake3",
		"MD5":         "md5",
	} {
		got, ok := spdx3HashAlgorithm(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, string(got), in)
	}
	_, ok := spdx3HashAlgorithm("CRC32")
	assert.False(t, ok)
}
