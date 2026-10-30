// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

var azureLinux3 = &inventory.Platform{Name: "azurelinux", Version: "3.0", Arch: "aarch64", Family: []string{"linux", "unix", "os"}}

// distrolessRpmManager is an rpm manager on an Azure Linux distroless image:
// no rpm binary and no rpm database, only the manifest the image build writes.
func distrolessRpmManager(t *testing.T, files map[string]string) *RpmPkgManager {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: azureLinux3}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			rpmProbeCommand: {Stderr: "sh: rpm: command not found\n", ExitStatus: 127},
		},
		Files: mockFiles,
	}))
	require.NoError(t, err)
	return &RpmPkgManager{conn: conn, platform: azureLinux3}
}

func readManifestTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(b)
}

// mcr.microsoft.com/azurelinux/distroless/base:3.0 and
// cbl-mariner/distroless/base:2.0 have no rpm database. The package list was
// empty with no error.
func TestRpmManifestFallback(t *testing.T) {
	for _, tc := range []struct {
		file  string
		count int
	}{
		{"rpmmanifest-azurelinux3-distroless.tsv", 14},
		{"rpmmanifest-mariner2-distroless.tsv", 12},
	} {
		t.Run(tc.file, func(t *testing.T) {
			rpm := distrolessRpmManager(t, map[string]string{rpmManifestPath: readManifestTestdata(t, tc.file)})
			pkgs, err := rpm.List()
			require.NoError(t, err)
			assert.Len(t, pkgs, tc.count)
		})
	}
}

func TestParseRpmManifest(t *testing.T) {
	pkgs, err := parseRpmManifest(azureLinux3, strings.NewReader(readManifestTestdata(t, "rpmmanifest-azurelinux3-distroless.tsv")))
	require.NoError(t, err)
	require.Len(t, pkgs, 14)

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	glibc := byName["glibc"]
	assert.Equal(t, "2.38-21.azl3", glibc.Version)
	assert.Equal(t, "", glibc.Epoch)
	assert.Equal(t, "aarch64", glibc.Arch)
	assert.Equal(t, "Microsoft Corporation", glibc.Vendor)
	assert.Equal(t, RpmPkgFormat, glibc.Format)
	assert.Equal(t, time.Unix(1790188863, 0).UTC(), glibc.InstallDate)
	assert.Equal(t, "pkg:rpm/azurelinux/glibc@2.38-21.azl3?arch=aarch64", glibc.PUrl)

	// EPOCHNUM is the ninth column; the sixth is EPOCH, "(none)" when unset
	ca := byName["prebuilt-ca-certificates"]
	assert.Equal(t, "1", ca.Epoch)
	assert.Equal(t, "1:3.0.0-16.azl3", ca.Version)
	assert.Equal(t, "noarch", ca.Arch)
}

func TestParseRpmManifestMalformed(t *testing.T) {
	_, err := parseRpmManifest(azureLinux3, strings.NewReader("glibc 2.38-21.azl3\n"))
	assert.Error(t, err, "a manifest with no readable line is not an empty system")

	_, err = parseRpmManifest(azureLinux3, strings.NewReader(" \n\n"))
	assert.Error(t, err, "an empty manifest is not an empty system")
}

// With neither an rpm database nor a manifest the list cannot be read. It
// returned no packages and no error, so `packages.none(...)` passed.
func TestRpmStaticListWithoutDatabase(t *testing.T) {
	_, err := distrolessRpmManager(t, nil).List()
	assert.Error(t, err)
}
