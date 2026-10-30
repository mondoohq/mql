// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lockfile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/sbom"
)

func TestTerraformLockExtractor(t *testing.T) {
	f, err := os.Open("./testdata/simple.terraform.lock.hcl")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, ".terraform.lock.hcl")
	require.NoError(t, err)

	assert.Nil(t, info.Root())
	assert.Nil(t, info.Direct())

	transitive := info.Transitive()
	assert.Equal(t, 3, len(transitive))

	p := transitive.Find("hashicorp/aws")
	require.NotNil(t, p)
	assert.Equal(t, "5.31.0", p.Version)
	assert.Equal(t, "pkg:terraform/hashicorp/aws@5.31.0", p.Purl)
	assert.Equal(t, []*sbom.Evidence{{Type: sbom.EvidenceType_EVIDENCE_TYPE_FILE, Value: ".terraform.lock.hcl"}}, p.EvidenceList)

	p = transitive.Find("hashicorp/random")
	require.NotNil(t, p)
	assert.Equal(t, "3.6.0", p.Version)
	assert.Equal(t, "pkg:terraform/hashicorp/random@3.6.0", p.Purl)

	// Non-hashicorp provider
	p = transitive.Find("integrations/github")
	require.NotNil(t, p)
	assert.Equal(t, "5.42.0", p.Version)
	assert.Equal(t, "pkg:terraform/integrations/github@5.42.0", p.Purl)
}

func TestTerraformLockHashesAndConstraints(t *testing.T) {
	f, err := os.Open("./testdata/mixed.terraform.lock.hcl")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, ".terraform.lock.hcl")
	require.NoError(t, err)

	transitive := info.Transitive()
	require.Equal(t, 4, len(transitive))

	// Only the zh: entries become checksums, one per platform zip. The h1:
	// dirhash is base64 over a different preimage and must not be reported
	// alongside them as if it were another SHA-256.
	aws := transitive.Find("hashicorp/aws")
	require.NotNil(t, aws)
	assert.Equal(t, "pkg:terraform/hashicorp/aws@5.31.0", aws.Purl)
	require.Equal(t, 2, len(aws.Hashes))
	assert.Equal(t, "SHA-256", aws.Hashes[0].Alg)
	assert.Equal(t, "0cd0b11e5cafd84e05be4088ccf28a01a3dbae8e1ce71e3b91f7b27aca633b7b", aws.Hashes[0].Value)
	assert.Equal(t, "1a2b3c4d5e6f708192a3b4c5d6e7f80911223344556677889900aabbccddeeff", aws.Hashes[1].Value)
	assert.Equal(t, "registry.terraform.io/hashicorp/aws", aws.Origin)

	// An OpenTofu provider no longer collapses onto the HashiCorp coordinate.
	random := transitive.Find("hashicorp/random")
	require.NotNil(t, random)
	assert.Equal(t, "pkg:opentofu/hashicorp/random@3.6.0", random.Purl)
	assert.Empty(t, random.Hashes, "an h1:-only entry yields no checksum")

	// A four-segment private registry address used to produce a junk purl with
	// an empty namespace and a slash-bearing type.
	docker := transitive.Find("tf/acme/docker")
	require.NotNil(t, docker)
	assert.Equal(t, "pkg:terraform/tf/acme/docker@1.4.2", docker.Purl)
	assert.Equal(t, "artifactory.acme.com/tf/acme/docker", docker.Origin)
	require.Equal(t, 1, len(docker.Hashes))

	// A provider with no constraints line still parses; the absence means "not
	// recorded", which is why it is not turned into a directness signal.
	gh := transitive.Find("integrations/github")
	require.NotNil(t, gh)
	assert.Equal(t, "5.42.0", gh.Version)
}

func TestTerraformLockSingleLineBlocks(t *testing.T) {
	f, err := os.Open("./testdata/singleline.terraform.lock.hcl")
	require.NoError(t, err)
	defer f.Close()

	info, err := (&Extractor{}).Parse(f, ".terraform.lock.hcl")
	require.NoError(t, err)

	// The line scanner required the block-open line to end with "{", so a
	// single-line block never closed and swallowed the one after it: this
	// file reported one provider instead of two.
	transitive := info.Transitive()
	require.Equal(t, 2, len(transitive))

	aws := transitive.Find("hashicorp/aws")
	require.NotNil(t, aws)
	assert.Equal(t, "5.31.0", aws.Version)

	null := transitive.Find("hashicorp/null")
	require.NotNil(t, null)
	assert.Equal(t, "3.2.1", null.Version)
}
