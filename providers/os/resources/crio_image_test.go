// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The fixtures in testdata/crio-image come from the minikube node of
// `minikube start --driver=docker --container-runtime=cri-o` (CRI-O 1.35.7,
// arm64): /var/lib/containers/storage/overlay-images/images.json,
// /var/lib/containers/storage/overlay-layers/layers.json, and the
// overlay-images directories of registry.k8s.io/pause:3.10.2,
// registry.k8s.io/coredns/coredns:v1.14.6 and
// docker.io/kindest/kindnetd:v20250512-df8de77b.
const (
	crioPauseID    = "3884a337192318652b28de0de1aeb07f446a14f220feb5066f03e93f23ea3b60"
	crioCorednsID  = "fbccbf70a429fb9ce1cdb13a40ed96b16272ef763dafe050b2c0d121dd29811b"
	crioKindnetdID = "b1a8c6f707935fd5f346ce5846d21ff8dd65e14c15406a14dbd16b9b897b9b4c"
)

func readCrioImageFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "crio-image", name))
	require.NoError(t, err)
	return string(data)
}

func crioFixtureImages(t *testing.T) map[string]crioStorageImage {
	t.Helper()
	images, err := parseCrioStorageImages(readCrioImageFixture(t, "images.json"))
	require.NoError(t, err)
	res := map[string]crioStorageImage{}
	for _, img := range images {
		res[img.ID] = img
	}
	return res
}

func TestParseCrioStorageImages(t *testing.T) {
	images := crioFixtureImages(t)
	require.Len(t, images, 10)
	pause := images[crioPauseID]
	assert.Equal(t, []string{"registry.k8s.io/pause:3.10.2"}, pause.Names)
	assert.Equal(t, "sha256:f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4", pause.Digest)
	assert.NotEmpty(t, pause.Layer)

	none, err := parseCrioStorageImages("")
	require.NoError(t, err)
	assert.Empty(t, none)
	_, err = parseCrioStorageImages("{not json")
	assert.ErrorIs(t, err, llx.ErrMalformedData)
}

// The expected sizes are what `crictl images -o json` reported on the same node.
func TestCrioImageSize(t *testing.T) {
	images := crioFixtureImages(t)
	layers, err := parseCrioStorageLayers(readCrioImageFixture(t, "layers.json"))
	require.NoError(t, err)

	assert.Equal(t, int64(520240), crioImageSize(images[crioPauseID], layers))
	assert.Equal(t, int64(73021099), crioImageSize(images[crioCorednsID], layers))
	assert.Equal(t, int64(111333938), crioImageSize(images[crioKindnetdID], layers))

	loop := map[string]crioStorageLayer{
		"a": {ID: "a", Parent: "b", DiffSize: 1},
		"b": {ID: "b", Parent: "a", DiffSize: 2},
	}
	assert.Equal(t, int64(3), crioImageSize(crioStorageImage{Layer: "a"}, loop), "a parent cycle ends the chain")

	_, err = parseCrioStorageLayers("[{")
	assert.ErrorIs(t, err, llx.ErrMalformedData)
}

func TestCrioBigDataFileName(t *testing.T) {
	assert.Equal(t, "manifest", crioBigDataFileName("manifest"))
	name := crioBigDataFileName("sha256:" + crioPauseID)
	assert.Equal(t, "=c2hhMjU2OjM4ODRhMzM3MTkyMzE4NjUyYjI4ZGUwZGUxYWViMDdmNDQ2YTE0ZjIyMGZlYjUwNjZmMDNlOTNmMjNlYTNiNjA=", name)
	_, err := os.Stat(filepath.Join("testdata", "crio-image", "overlay-images", crioPauseID, name))
	assert.NoError(t, err, "the file containers/storage wrote")
}

func TestCrioImageConfigKey(t *testing.T) {
	images := crioFixtureImages(t)
	assert.Equal(t, "sha256:"+crioPauseID, crioImageConfigKey(images[crioPauseID]))

	// an image whose ID is not its configuration's digest
	other := crioStorageImage{ID: crioPauseID, BigDataNames: []string{"manifest", "manifest-sha256:" + crioCorednsID, "sha256:" + crioCorednsID}}
	assert.Equal(t, "sha256:"+crioCorednsID, crioImageConfigKey(other))
	assert.Empty(t, crioImageConfigKey(crioStorageImage{ID: crioPauseID, BigDataNames: []string{"manifest"}}))
}

func TestCrioImageConfig(t *testing.T) {
	read := func(id string) ocispec.Image {
		raw := readCrioImageFixture(t, filepath.Join("overlay-images", id, crioBigDataFileName("sha256:"+id)))
		var img ocispec.Image
		require.NoError(t, json.Unmarshal([]byte(raw), &img))
		return img
	}

	pause := read(crioPauseID)
	assert.Equal(t, "65535:65535", pause.Config.User)
	assert.False(t, imageUserIsRoot(pause.Config.User))
	assert.Equal(t, []string{"/pause"}, pause.Config.Entrypoint)
	assert.Equal(t, "arm64", pause.Architecture)
	require.NotNil(t, pause.Created)
	assert.Equal(t, time.Date(2026, 2, 26, 23, 48, 23, 255251471, time.UTC), pause.Created.UTC())

	coredns := read(crioCorednsID)
	assert.Equal(t, "nonroot:nonroot", coredns.Config.User)
	assert.Equal(t, []any{"53/tcp", "53/udp"}, sortedPorts(coredns.Config.ExposedPorts))
	assert.Len(t, coredns.RootFS.DiffIDs, 13)

	kindnetd := read(crioKindnetdID)
	assert.Empty(t, kindnetd.Config.User)
	assert.True(t, imageUserIsRoot(kindnetd.Config.User))
	assert.Equal(t, []string{"/bin/kindnetd"}, kindnetd.Config.Cmd)
}

func TestCrioRepoDigests(t *testing.T) {
	images := crioFixtureImages(t)
	assert.Equal(t, []string{
		"docker.io/kindest/kindnetd@sha256:07a4b3fe0077a0ae606cc0a200fc25a28fa64dcc30b8d311b461089969449f9a",
		"docker.io/kindest/kindnetd@sha256:2bdc3188f2ddc8e54841f69ef900a8dde1280057c97500f966a7ef31364021f1",
	}, crioRepoDigests(images[crioKindnetdID]))
	assert.Empty(t, crioRepoDigests(crioStorageImage{Digest: "sha256:aa"}), "an untagged image has no repository")
}

func TestImageRepository(t *testing.T) {
	for ref, want := range map[string]string{
		"registry.k8s.io/pause:3.10.2": "registry.k8s.io/pause",
		"localhost:5000/app:1":         "localhost:5000/app",
		"localhost:5000/app":           "localhost:5000/app",
		"quay.io/app@sha256:aa":        "quay.io/app",
		"quay.io/app:1@sha256:aa":      "quay.io/app",
		"docker.io/library/alpine":     "docker.io/library/alpine",
	} {
		assert.Equal(t, want, imageRepository(ref), ref)
	}
}
