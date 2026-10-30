// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
	"go.mondoo.com/mql/sbom/generator"
)

func TestSimpleBomOutput(t *testing.T) {
	report, err := generator.LoadReport("./testdata/alpine.json")
	require.NoError(t, err)

	sboms := generator.GenerateBom(report)

	// store bom in different formats
	selectedBom := sboms[0]

	var exporter sbom.FormatSpecificationHandler

	output := bytes.Buffer{}
	exporter = sbom.New(sbom.FormatJson)
	exporter.ApplyOptions(sbom.WithCPE(), sbom.WithEvidence())
	err = exporter.Render(&output, selectedBom)
	require.NoError(t, err)

	data := output.String()

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
