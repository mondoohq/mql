// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The fixtures in testdata/containerd-image come from a kindest/node:v1.34.0
// container (containerd 2.1.3, arm64): `ctr -n k8s.io images list` and
// `ctr -n default images list` after `ctr images pull
// docker.io/library/alpine:3.22`, and the blobs of alpine:3.22,
// registry.k8s.io/coredns/coredns:v1.12.1 and
// registry.k8s.io/kube-apiserver:v1.34.0 copied from
// /var/lib/containerd/io.containerd.content.v1.content/blobs/sha256.
func loadCtrImageFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "containerd-image", name))
	require.NoError(t, err)
	return data
}

// ctrContentStore serves the fixture blobs by their digest, as containerd's
// content store does.
func ctrContentStore(t *testing.T, names ...string) func(string) ([]byte, bool) {
	blobs := map[string][]byte{}
	for _, name := range names {
		data := loadCtrImageFixture(t, name)
		blobs[fmt.Sprintf("sha256:%x", sha256.Sum256(data))] = data
	}
	return func(digest string) ([]byte, bool) {
		b, ok := blobs[digest]
		return b, ok
	}
}

func TestParseCtrImageList(t *testing.T) {
	images := parseCtrImageList(string(loadCtrImageFixture(t, "ls-k8s.io.txt")))
	require.Len(t, images, 24)

	byName := map[string]ctrImage{}
	for _, img := range images {
		byName[img.name] = img
	}

	pause := byName["registry.k8s.io/pause:3.10"]
	assert.Equal(t, "application/vnd.docker.distribution.manifest.list.v2+json", pause.mediaType)
	assert.Equal(t, "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a", pause.digest)
	assert.Equal(t, []string{"linux/amd64", "linux/arm/v7", "linux/arm64", "linux/ppc64le", "linux/s390x", "windows/amd64"}, pause.platforms)
	assert.Equal(t, map[string]string{"io.cri-containerd.image": "managed", "io.cri-containerd.pinned": "pinned"}, pause.labels)

	api := byName["registry.k8s.io/kube-apiserver:v1.34.0"]
	assert.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", api.mediaType)
	assert.Equal(t, []string{"linux/arm64"}, api.platforms)
	assert.Equal(t, map[string]string{"io.cri-containerd.image": "managed"}, api.labels)

	// the image ID references CRI adds are images too
	_, ok := byName["sha256:138784d87c9c50f8e59412544da4cf4928d61ccbaf93b9f5898a3ba406871bfc"]
	assert.True(t, ok)

	def := parseCtrImageList(string(loadCtrImageFixture(t, "ls-default.txt")))
	require.Len(t, def, 1)
	assert.Equal(t, "docker.io/library/alpine:3.22", def[0].name)
	assert.Equal(t, "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8", def[0].digest)
	assert.Empty(t, def[0].labels, "a dash is no labels")
	assert.Len(t, def[0].platforms, 8)
	assert.Contains(t, def[0].platforms, "linux/arm64/v8")

	assert.Empty(t, parseCtrImageList("REF TYPE DIGEST SIZE PLATFORMS LABELS \n"))
	assert.Empty(t, parseCtrImageList(""))
}

func TestResolveOCIImageIndex(t *testing.T) {
	read := ctrContentStore(t, "alpine-index.json", "alpine-manifest-arm64.json", "alpine-config.json")
	c, err := resolveOCIImage(read, "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
		ocispec.MediaTypeImageIndex, "linux", "arm64", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, int64(4123711), c.size, "ctr reports 3.9 MiB")
	assert.Equal(t, "arm64", c.config.Architecture)
	assert.Equal(t, "v8", c.config.Variant)
	assert.Equal(t, "linux", c.config.OS)
	require.NotNil(t, c.config.Created)
	assert.Equal(t, time.Date(2026, 9, 17, 20, 37, 30, 780047516, time.UTC), c.config.Created.UTC())
	assert.Empty(t, c.config.Config.User)
	assert.True(t, imageUserIsRoot(c.config.Config.User))
	assert.Equal(t, []string{"/bin/sh"}, c.config.Config.Cmd)
	require.Len(t, c.config.RootFS.DiffIDs, 1)

	// the amd64 manifest is listed in the index but its content was not pulled
	c, err = resolveOCIImage(read, "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
		ocispec.MediaTypeImageIndex, "linux", "amd64", "")
	require.NoError(t, err)
	assert.Nil(t, c)

	// without a known host architecture the stored manifest is the host's
	c, err = resolveOCIImage(read, "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
		ocispec.MediaTypeImageIndex, "", "", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "arm64", c.config.Architecture)
}

func TestResolveOCIImageDockerManifestList(t *testing.T) {
	read := ctrContentStore(t, "coredns-index.json", "coredns-manifest-arm64.json", "coredns-config.json")
	c, err := resolveOCIImage(read, "sha256:e8c262566636e6bc340ece6473b0eed193cad045384401529721ddbe6463d31c",
		"application/vnd.docker.distribution.manifest.list.v2+json", "linux", "arm64", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "sha256:138784d87c9c50f8e59412544da4cf4928d61ccbaf93b9f5898a3ba406871bfc", c.configDigest)
	assert.Equal(t, int64(20387171), c.size, "ctr reports 19.4 MiB")
	assert.Equal(t, "nonroot:nonroot", c.config.Config.User)
	assert.False(t, imageUserIsRoot(c.config.Config.User))
	assert.Equal(t, []string{"/coredns"}, c.config.Config.Entrypoint)
	assert.Equal(t, []any{"53/tcp", "53/udp"}, sortedPorts(c.config.Config.ExposedPorts))
}

func TestResolveOCIImageManifest(t *testing.T) {
	read := ctrContentStore(t, "apiserver-manifest.json", "apiserver-config.json")
	c, err := resolveOCIImage(read, "sha256:36836dc24337476b8138ae54e16c6b440a9b26b506545098828f726271fa843d",
		"application/vnd.docker.distribution.manifest.v2+json", "linux", "amd64", "")
	require.NoError(t, err)
	require.NotNil(t, c, "a single-platform manifest is used as it is")
	assert.Equal(t, int64(84811098), c.size, "ctr reports 80.9 MiB")
	assert.Equal(t, "0", c.config.Config.User)
	assert.Equal(t, []string{"/go-runner"}, c.config.Config.Entrypoint)

	c, err = resolveOCIImage(read, "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"application/vnd.docker.distribution.manifest.v2+json", "linux", "arm64", "")
	require.NoError(t, err)
	assert.Nil(t, c, "content that is not stored is null")
}

func TestResolveOCIImageMalformed(t *testing.T) {
	read := func(string) ([]byte, bool) { return []byte("{not json"), true }
	_, err := resolveOCIImage(read, "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8",
		ocispec.MediaTypeImageIndex, "linux", "arm64", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, llx.ErrMalformedData)
}

func TestSelectPlatformManifestSkipsAttestations(t *testing.T) {
	att := ocispec.Descriptor{Digest: "sha256:aa", Platform: &ocispec.Platform{OS: "unknown", Architecture: "unknown"}}
	armv7 := ocispec.Descriptor{Digest: "sha256:bb", Platform: &ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}}
	armv6 := ocispec.Descriptor{Digest: "sha256:cc", Platform: &ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}}
	all := func(string) bool { return true }

	d, ok := selectPlatformManifest([]ocispec.Descriptor{att, armv6, armv7}, "linux", "arm", "v7", all)
	require.True(t, ok)
	assert.Equal(t, armv7.Digest, d.Digest)

	d, ok = selectPlatformManifest([]ocispec.Descriptor{att, armv7}, "", "", "", all)
	require.True(t, ok)
	assert.Equal(t, armv7.Digest, d.Digest, "an attestation manifest is no image")

	_, ok = selectPlatformManifest([]ocispec.Descriptor{armv7}, "windows", "arm", "v7", all)
	assert.False(t, ok)
}

func TestOCIArch(t *testing.T) {
	for machine, want := range map[string][2]string{
		"x86_64":  {"amd64", ""},
		"aarch64": {"arm64", ""},
		"arm64":   {"arm64", ""},
		"armv7l":  {"arm", "v7"},
		"armv6l":  {"arm", "v6"},
		"i686":    {"386", ""},
		"s390x":   {"s390x", ""},
		"sparc64": {"", ""},
	} {
		arch, variant := ociArch(machine)
		assert.Equal(t, want, [2]string{arch, variant}, machine)
	}
	assert.True(t, ociVariantMatches("arm64", "", "v8"))
	assert.True(t, ociVariantMatches("arm64", "v8", ""))
	assert.False(t, ociVariantMatches("arm", "v7", "v6"))
}

func TestContainerdBlobPath(t *testing.T) {
	p, ok := containerdBlobPath("/var/lib/containerd", "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8")
	require.True(t, ok)
	assert.Equal(t, "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8", p)

	for _, bad := range []string{"", "sha256:../../etc/shadow", "sha256:", "5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8", "SHA256:abc"} {
		_, ok := containerdBlobPath("/var/lib/containerd", bad)
		assert.False(t, ok, bad)
	}
	_, ok = containerdBlobPath("", "sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8")
	assert.False(t, ok)
}
