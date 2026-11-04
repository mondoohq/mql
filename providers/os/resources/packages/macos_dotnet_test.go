// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestMacOSDotnetPackages(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Version: "26.0", Arch: "arm64"}

	fs := afero.NewMemMapFs()
	for _, d := range []string{
		"/usr/local/share/dotnet/shared/Microsoft.NETCore.App/8.0.10",
		"/usr/local/share/dotnet/shared/Microsoft.NETCore.App/10.0.14",
		"/usr/local/share/dotnet/shared/Microsoft.AspNetCore.App/8.0.10",
		"/usr/local/share/dotnet/shared/Microsoft.NETCore.App/not-a-version",
		"/usr/local/share/dotnet/shared/Other.Framework/1.0.0",
		"/usr/local/share/dotnet/x64/shared/Microsoft.NETCore.App/6.0.36",
	} {
		require.NoError(t, fs.MkdirAll(d, 0o755))
	}
	// a stray file named like a version is not a runtime
	require.NoError(t, afero.WriteFile(fs, "/usr/local/share/dotnet/shared/Microsoft.NETCore.App/9.0.1", nil, 0o644))

	pkgs := macOSDotnetPackages(fs, pf)
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.PUrl] = p
	}
	require.Len(t, pkgs, 4)
	require.Contains(t, got, "pkg:macos/macos/Microsoft.NETCore.App@8.0.10?arch=arm64")
	require.Contains(t, got, "pkg:macos/macos/Microsoft.NETCore.App@10.0.14?arch=arm64")
	require.Contains(t, got, "pkg:macos/macos/Microsoft.AspNetCore.App@8.0.10?arch=arm64")
	x64 := got["pkg:macos/macos/Microsoft.NETCore.App@6.0.36?arch=x86_64"]
	assert.Equal(t, "Microsoft.NETCore.App", x64.Name)
	assert.Equal(t, "6.0.36", x64.Version)
	assert.Equal(t, "x86_64", x64.Arch)
	assert.Equal(t, MacosPkgFormat, x64.Format)
	assert.Equal(t, "/usr/local/share/dotnet/x64/shared/Microsoft.NETCore.App/6.0.36", x64.Files[0].Path)
}

func TestMacOSDotnetPackagesMissingRoot(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Arch: "arm64"}
	assert.Empty(t, macOSDotnetPackages(afero.NewMemMapFs(), pf))

	// root without a shared directory
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/usr/local/share/dotnet/host", 0o755))
	assert.Empty(t, macOSDotnetPackages(fs, pf))
}

func TestMacOSDotnetPackagesPrerelease(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Arch: "arm64"}
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/usr/local/share/dotnet/shared/Microsoft.NETCore.App/9.0.0-preview.7.24405.7", 0o755))
	pkgs := macOSDotnetPackages(fs, pf)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "9.0.0-preview.7.24405.7", pkgs[0].Version)
}
