// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package container_registry

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestDockerRegistry(t *testing.T) {
	name := "index.docker.io"
	// url, err := url.Parse("//" + name)
	// require.NoError(t, err)

	// assert.True(t, url.Host != name)
	// assert.Equal(t, "index.docker.io", url.Host)

	if url, err := url.Parse("//" + name); err != nil || url.Host != name {
		t.Fatal(url.Host)
		// t.Fatal(fmt.Errorf("registries must be valid RFC 3986 URI authorities: %s", name))
	}

	// r := docker.NewImageLister()
	// assets, err := r.List(name)
	// require.NoError(t, err)
	// assert.True(t, len(assets) > 0)
}

func TestHarbor(t *testing.T) {
	urls := []string{
		"index.docker.io/library/alpine:latest",
		// 3.21.3
		"index.docker.io/library/alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c",
	}

	for i := range urls {
		url := urls[i]
		ref, err := name.ParseReference(url, name.WeakValidation)
		require.NoError(t, err, url)
		assert.NotNil(t, ref, url)

		dri := ImageLister{}
		a, err := dri.toAsset(ref, nil)
		require.NoError(t, err, url)

		// check that we resolved it correctly and we got a specific shasum
		assert.Equal(t, "registry-image", a.Connections[0].Type)
		assert.True(t, strings.HasPrefix(a.Connections[0].Host, "index.docker.io/library/alpine"), url)
		assert.True(t, len(strings.Split(a.Connections[0].Host, "@")) == 2, url)
	}
}

// An OCI image index manifest as remote.Get returns it (the child digest is
// synthetic). testIndexDigest is the real sha256 of these bytes, as remote.Get
// guarantees for a descriptor; TestFixtureDigestMatchesManifest pins that.
const testIndexManifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:d3f0ce2b2f7a3b4b1e4e2a4d0a1b0d3f5c3b7d3c5a3f1e2d4c6b8a0f2e4d6c8b","size":483,"platform":{"architecture":"amd64","os":"linux"}}]}`

const testIndexDigest = "sha256:f00f56e576cb61555b7bf9969953bd832f0c3114eb2a8c4fe5532fc4ea88266d"

func TestFixtureDigestMatchesManifest(t *testing.T) {
	sum := sha256.Sum256([]byte(testIndexManifest))
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), testIndexDigest)
}

func TestContainerImageClaimFromDescriptor(t *testing.T) {
	ref := "index.docker.io/library/alpine@" + testIndexDigest

	t.Run("digest and ref only", func(t *testing.T) {
		claim := containerImageClaimFromDescriptor(testIndexDigest, ref)
		require.NotNil(t, claim)
		assert.Equal(t, inventory.AssetClaimKindContainerImage, claim.Kind)
		assert.Equal(t, map[string]string{
			inventory.AssetClaimDigest: testIndexDigest,
			inventory.AssetClaimRef:    ref,
		}, claim.Claims)
	})

	t.Run("neither arch nor manifest is set", func(t *testing.T) {
		claim := containerImageClaimFromDescriptor(testIndexDigest, ref)
		assert.NotContains(t, claim.Claims, inventory.AssetClaimArch)
		assert.NotContains(t, claim.Claims, inventory.AssetClaimManifest)
	})
}

// assetFromDescriptor is the offline half of toAsset: everything after remote.Get.
func TestAssetFromDescriptorClaims(t *testing.T) {
	ref, err := name.ParseReference("index.docker.io/library/alpine:3.21.3")
	require.NoError(t, err)
	hash, err := v1.NewHash(testIndexDigest)
	require.NoError(t, err)
	desc := &remote.Descriptor{}
	desc.Digest = hash
	desc.Manifest = []byte(testIndexManifest)

	asset := assetFromDescriptor(ref, desc, nil)

	require.Len(t, asset.Claims, 1, "exactly one claim per discovered image")
	claim := asset.Claims[0]
	assert.Equal(t, inventory.AssetClaimKindContainerImage, claim.Kind)
	assert.Equal(t, testIndexDigest, claim.Claims[inventory.AssetClaimDigest])
	// ref is the same repo@digest string used as the connection host
	require.Len(t, asset.Connections, 1)
	assert.Equal(t, asset.Connections[0].Host, claim.Claims[inventory.AssetClaimRef])
	assert.Equal(t, "index.docker.io/library/alpine@"+testIndexDigest, claim.Claims[inventory.AssetClaimRef])
	assert.NotContains(t, claim.Claims, inventory.AssetClaimManifest, "the seed lane owns the manifest")

	// same descriptor, different tag: identical claim, and AddClaim dedupes it,
	// which is what ListRepository's tag-merge path relies on (it keeps the first asset).
	ref2, err := name.ParseReference("index.docker.io/library/alpine:latest")
	require.NoError(t, err)
	asset2 := assetFromDescriptor(ref2, desc, nil)
	assert.Equal(t, asset.PlatformIds, asset2.PlatformIds)
	assert.Equal(t, asset.Claims[0].Claims, asset2.Claims[0].Claims)
	asset.AddClaim(asset2.Claims[0])
	assert.Len(t, asset.Claims, 1)
}
