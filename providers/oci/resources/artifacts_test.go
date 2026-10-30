// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- selecting a collection's members by owner -----
//
// An image's repository and a signature's image are both resolved by scanning
// a tenancy-wide listing rather than by a call per item. That makes the match
// itself the thing that can be wrong, and neither way of being wrong looks
// like an error: matching the wrong field returns nothing, and matching too
// loosely returns everything.

func TestOciArtifactsSelectByOwner(t *testing.T) {
	image := func(repositoryID string) *mqlOciArtifactsContainerImage {
		img := &mqlOciArtifactsContainerImage{}
		img.cacheRepositoryID = repositoryID
		return img
	}

	t.Run("only the owner's members are selected", func(t *testing.T) {
		mine, theirs := image("repo-a"), image("repo-b")
		got := ociArtifactsSelectByOwner([]any{mine, theirs, image("repo-a")}, "repo-a", ociArtifactsImageRepositoryID)
		require.Len(t, got, 2)
		assert.Same(t, mine, got[0])
		assert.NotContains(t, got, theirs)
	})

	t.Run("collection order is preserved", func(t *testing.T) {
		first, second := image("repo-a"), image("repo-a")
		got := ociArtifactsSelectByOwner([]any{first, image("repo-b"), second}, "repo-a", ociArtifactsImageRepositoryID)
		require.Len(t, got, 2)
		assert.Same(t, first, got[0])
		assert.Same(t, second, got[1])
	})

	t.Run("an owner with no members is an empty list, not null", func(t *testing.T) {
		assert.Equal(t, []any{}, ociArtifactsSelectByOwner([]any{image("repo-a")}, "repo-z", ociArtifactsImageRepositoryID))
	})

	t.Run("an empty owner id matches nothing", func(t *testing.T) {
		// Members whose owner the listing did not report also carry "", so
		// matching on an empty id would pair every orphan with every owner
		// whose id failed to load.
		orphan := image("")
		assert.Empty(t, ociArtifactsSelectByOwner([]any{orphan}, "", ociArtifactsImageRepositoryID))
	})

	t.Run("members of an unexpected type are skipped, not asserted on", func(t *testing.T) {
		// A bare type assertion here would panic inside an accessor, and a
		// panic in an accessor takes down the whole scan.
		assert.NotPanics(t, func() {
			ociArtifactsSelectByOwner([]any{"not a resource", image("repo-a")}, "repo-a", ociArtifactsImageRepositoryID)
		})
	})

	t.Run("the two owner readers read different fields", func(t *testing.T) {
		// The failure this guards against is one accessor being handed the
		// other's reader, which compiles and returns an empty list.
		signature := &mqlOciArtifactsContainerImageSignature{}
		signature.cacheImageID = "image-a"

		_, ok := ociArtifactsImageRepositoryID(signature)
		assert.False(t, ok, "the image reader must not accept a signature")

		_, ok = ociArtifactsSignatureImageID(image("repo-a"))
		assert.False(t, ok, "the signature reader must not accept an image")

		owner, ok := ociArtifactsSignatureImageID(signature)
		require.True(t, ok)
		assert.Equal(t, "image-a", owner)
	})
}

// ----- generic artifact repositories -----

func TestOciArtifactRepositoryFields(t *testing.T) {
	t.Run("a generic repository is flattened", func(t *testing.T) {
		fields, err := ociArtifactRepositoryFields(artifacts.GenericRepositorySummary{
			Id:             new("ocid1.artifactrepository.oc1..aaa"),
			DisplayName:    new("release-artifacts"),
			CompartmentId:  new("ocid1.compartment.oc1..bbb"),
			Description:    new("signed release bundles"),
			IsImmutable:    new(true),
			LifecycleState: artifacts.RepositoryLifecycleStateAvailable,
		})
		require.NoError(t, err)

		assert.Equal(t, "ocid1.artifactrepository.oc1..aaa", fields["id"].Value)
		assert.Equal(t, "release-artifacts", fields["name"].Value)
		assert.Equal(t, "signed release bundles", fields["description"].Value)
		assert.Equal(t, true, fields["isImmutable"].Value)
		assert.Equal(t, "GENERIC", fields["repositoryType"].Value)
		assert.Equal(t, "AVAILABLE", fields["state"].Value)
	})

	t.Run("a mutable repository reads as mutable", func(t *testing.T) {
		// isImmutable is the tamper control, so it has to survive the
		// flattening in both directions rather than only when set.
		fields, err := ociArtifactRepositoryFields(artifacts.GenericRepositorySummary{
			Id:          new("ocid1.artifactrepository.oc1..aaa"),
			IsImmutable: new(false),
		})
		require.NoError(t, err)
		assert.Equal(t, false, fields["isImmutable"].Value)
	})

	t.Run("an unhandled repository type is an error, not a skip", func(t *testing.T) {
		// Dropping one would leave its artifacts unreachable and the tenancy
		// looking like it stores less than it does.
		_, err := ociArtifactRepositoryFields(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unhandled repository type")
	})
}

func TestOciArtifactRepositoryTypeCoverage(t *testing.T) {
	// ociArtifactRepositoryFields asserts GenericRepositorySummary and hardcodes
	// the repositoryType string, so a second kind needs both changed. Driven
	// from the SDK enum so it fails the build rather than at scan time.
	handled := map[string]bool{"GENERIC": true}

	values := artifacts.GetRepositoryRepositoryTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"artifacts.RepositoryRepositoryType %q is not handled by ociArtifactRepositoryFields", value)
	}
}

func TestOciContainerImageSigningAlgorithmCoverage(t *testing.T) {
	// The signing algorithm is passed through verbatim and the schema
	// enumerates the four the service offers, so a fifth would make the
	// documented list wrong and any query comparing against it incomplete.
	documented := map[string]bool{
		"SHA_224_RSA_PKCS_PSS": true,
		"SHA_256_RSA_PKCS_PSS": true,
		"SHA_384_RSA_PKCS_PSS": true,
		"SHA_512_RSA_PKCS_PSS": true,
	}

	values := artifacts.GetContainerImageSignatureSummarySigningAlgorithmEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, documented[value],
			"artifacts.ContainerImageSignatureSummarySigningAlgorithm %q is missing from the "+
				"signingAlgorithm documentation in oci.lr", value)
	}
}
