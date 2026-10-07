// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func parseFixture(t *testing.T, path string) languages.Bom {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, path)
	require.NoError(t, err)
	return bom
}

func TestTerraformConfigExtractor(t *testing.T) {
	bom := parseFixture(t, "./testdata/main.tf")

	assert.Nil(t, bom.Root())
	// A configuration states what it calls, not what those modules call.
	assert.Nil(t, bom.Transitive())

	direct := bom.Direct()

	// Two modules carry a coordinate; the local path, the variable-built
	// source and the s3:: fetcher deliberately contribute nothing.
	vpc := direct.Find("terraform-aws-modules/vpc/aws")
	require.NotNil(t, vpc)
	assert.Equal(t, "5.1.2", vpc.Version)
	assert.Equal(t, "pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws", vpc.Purl)

	factory := direct.Find("github.com/verily-src/verily-health-iac")
	require.NotNil(t, factory)
	assert.Equal(t,
		"pkg:generic/github.com/verily-src/verily-health-iac@v0.6.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fverily-src%2Fverily-health-iac.git#modules/base-project-factory",
		factory.Purl)

	assert.Nil(t, direct.Find("./modules/networking"))

	// Providers are recorded with no version: required_providers states a
	// constraint, and a constraint in a version field cannot be matched and
	// reads as an exact version to anything that does not check.
	aws := direct.Find("hashicorp/aws")
	require.NotNil(t, aws)
	assert.Equal(t, "", aws.Version)
	assert.Equal(t, "pkg:terraform/hashicorp/aws", aws.Purl)

	docker := direct.Find("kreuzwerker/docker")
	require.NotNil(t, docker)
	assert.Equal(t, "pkg:terraform/kreuzwerker/docker", docker.Purl)

	// The legacy shorthand still yields a provider, via Terraform's implied
	// source rule.
	random := direct.Find("hashicorp/random")
	require.NotNil(t, random)
	assert.Equal(t, "pkg:terraform/hashicorp/random", random.Purl)

	assert.Equal(t, 5, len(direct), "two modules and three providers")
}

func TestTerraformConfigExtractorToleratesBrokenFiles(t *testing.T) {
	// A file that does not parse must not fail the walk that reaches it.
	bom, err := (&Extractor{}).Parse(brokenReader{}, "broken.tf")
	require.NoError(t, err)
	require.NotNil(t, bom)
	assert.Empty(t, bom.Direct())
}

type brokenReader struct{}

func (b brokenReader) Read(p []byte) (int, error) {
	n := copy(p, []byte("module \"x\" { source = \n"))
	return n, io.EOF
}
