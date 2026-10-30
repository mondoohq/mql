// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDownloadTarget pins which field the download is fetched from.
//
// filename is the plain artifact name in some manifests and the fully qualified
// URL in others, which is why url exists and is preferred. The fallback keeps
// working against manifests published before url did.
func TestDownloadTarget(t *testing.T) {
	const url = "https://releases.mondoo.com/cnspec/13.38.1/cnspec_13.38.1_darwin_arm64.tar.gz"

	t.Run("url wins when present", func(t *testing.T) {
		f := ReleaseFile{Filename: "cnspec_13.38.1_darwin_arm64.tar.gz", Url: url}
		assert.Equal(t, url, f.downloadTarget())
	})

	t.Run("falls back to filename when url is absent", func(t *testing.T) {
		// How every latest.json looked before the url field existed.
		f := ReleaseFile{Filename: url}
		assert.Equal(t, url, f.downloadTarget())
	})

	t.Run("url is preferred even when filename also holds a url", func(t *testing.T) {
		f := ReleaseFile{Filename: "https://mirror.example.com/old.tar.gz", Url: url}
		assert.Equal(t, url, f.downloadTarget())
	})
}

// TestGetPlatformFileSelection covers picking this platform's artifact out of a
// manifest, in each shape a manifest can arrive in.
func TestGetPlatformFileSelection(t *testing.T) {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := "cnspec_13.38.1_" + runtime.GOOS + "_" + runtime.GOARCH + "." + ext
	const base = "https://releases.mondoo.com/cnspec/13.38.1/"

	t.Run("normalized manifest: plain filename plus url", func(t *testing.T) {
		// The shape the install service serves once filenames are normalized.
		// Selection must not depend on filename carrying the URL.
		rel := &Release{Version: "13.38.1", Files: []ReleaseFile{
			{Filename: "cnspec_13.38.1_other_arch.tar.gz", Url: base + "cnspec_13.38.1_other_arch.tar.gz"},
			{Filename: name, Url: base + name},
		}}
		got := getPlatformFile(rel, "cnspec")
		require.NotNil(t, got, "no entry selected for %s_%s", runtime.GOOS, runtime.GOARCH)
		assert.Equal(t, base+name, got.downloadTarget())
	})

	t.Run("legacy manifest: filename carries the url", func(t *testing.T) {
		rel := &Release{Version: "13.38.1", Files: []ReleaseFile{
			{Filename: base + "cnspec_13.38.1_other_arch.tar.gz"},
			{Filename: base + name},
		}}
		got := getPlatformFile(rel, "cnspec")
		require.NotNil(t, got)
		assert.Equal(t, base+name, got.downloadTarget())
	})

	t.Run("no entry for this platform", func(t *testing.T) {
		rel := &Release{Version: "13.38.1", Files: []ReleaseFile{
			{Filename: "cnspec_13.38.1_someos_somearch.tar.gz", Url: base + "cnspec_13.38.1_someos_somearch.tar.gz"},
		}}
		assert.Nil(t, getPlatformFile(rel, "cnspec"))
	})
}

// TestDownloadRejectsNonUrlTarget covers a manifest that carries only a plain
// filename and no url. There is no download target in that document, and the
// error has to say so: passing the bare name through fails later as a URL parse
// error, which points at the request rather than at the manifest.
func TestDownloadRejectsNonUrlTarget(t *testing.T) {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := "cnspec_13.38.1_" + runtime.GOOS + "_" + runtime.GOARCH + "." + ext

	rel := &Release{Name: "cnspec", Version: "13.38.1", Files: []ReleaseFile{{Filename: name}}}

	// Selection still succeeds - a plain name satisfies the suffix match - so
	// the guard has to be at the download, not at selection.
	require.NotNil(t, getPlatformFile(rel, "cnspec"))

	_, err := downloadAndInstall(context.Background(), rel, t.TempDir(), "cnspec")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no download url")
	assert.Contains(t, err.Error(), name)
}

// TestSelectionDoesNotConstrainTheDownloadUrl covers a manifest whose url is a
// service route rather than a path ending in the artifact name.
//
// Whoever serves the manifest decides where the bytes come from. Selection has
// to answer "which artifact is mine" from the filename, or that decision would
// be constrained by a naming rule the client happens to use for matching.
func TestSelectionDoesNotConstrainTheDownloadUrl(t *testing.T) {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := "cnspec_13.38.1_" + runtime.GOOS + "_" + runtime.GOARCH + "." + ext
	serviceURL := "https://install.mondoo.com/package/cnspec/" + runtime.GOOS + "/" + runtime.GOARCH + "/" + ext + "/latest/download"

	rel := &Release{Name: "cnspec", Version: "13.38.1", Files: []ReleaseFile{
		{Filename: "cnspec_13.38.1_someos_somearch." + ext, Url: "https://install.mondoo.com/other/download"},
		{Filename: name, Url: serviceURL},
	}}

	got := getPlatformFile(rel, "cnspec")
	require.NotNil(t, got, "a url that does not end in the artifact name must not break selection")
	assert.Equal(t, name, got.Filename)
	assert.Equal(t, serviceURL, got.downloadTarget())
}
