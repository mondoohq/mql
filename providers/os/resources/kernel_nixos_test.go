// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Store paths captured from a NixOS 26.05 EC2 host and a NixOS 25.11 one.
const (
	nixKernel618 = "/nix/store/dvab2dg1czm40gp5si151sj86rfjwnfm-linux-6.18.50/bzImage"
	nixKernel612 = "/nix/store/qzl0003mqn698wxc4yv31zyz95lxl51b-linux-6.12.93/bzImage"
	nixInitrd618 = "/nix/store/0svpws07al77h054na894bbbz61p8rj7-initrd-linux-6.18.50/initrd"
)

// bootJSONFor is the shape NixOS writes into every generation, trimmed to the
// namespace that names the kernel. A second namespace sits beside it on a real
// host, so the reader has to pick rather than take the first thing it finds.
func bootJSONFor(kernel string) []byte {
	return []byte(`{
  "org.nixos.bootspec.v1": {
    "initrd": "` + nixInitrd618 + `",
    "kernel": "` + kernel + `",
    "kernelParams": ["console=ttyS0,115200n8"],
    "label": "NixOS 26.05 (Linux 6.18.50)",
    "system": "x86_64-linux",
    "toplevel": "/nix/store/99bljb0jiac0rzkjv0hhclbzz2fn3jx5-nixos-system-unnamed-amazon-26.05"
  },
  "org.nixos.nixos-init.v1": {
    "env_binary": "/nix/store/61685rbaxmpnnnr9kkxsq5k3g1zf3g9k-coreutils-9.11/bin/env"
  }
}`)
}

// nixosProfiles builds a system profile directory. generations maps a
// generation number to the kernel it boots; booted is the kernel /run says was
// booted, or "" for a host where /run holds nothing.
func nixosProfiles(t *testing.T, generations map[string]string, booted string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()

	for gen, kernel := range generations {
		dir := nixosSystemProfilesDir + "/system-" + gen + "-link"
		require.NoError(t, fs.MkdirAll(dir, 0o755))
		require.NoError(t, afero.WriteFile(fs, dir+"/boot.json", bootJSONFor(kernel), 0o444))
	}
	// The directory also holds these two, and neither is a generation.
	require.NoError(t, fs.MkdirAll(nixosSystemProfilesDir+"/per-user", 0o755))
	require.NoError(t, fs.MkdirAll(nixosSystemProfilesDir+"/system", 0o755))

	if booted != "" {
		require.NoError(t, fs.MkdirAll(nixosBootedSystemDir, 0o755))
		require.NoError(t, afero.WriteFile(fs, nixosBootedSystemDir+"/boot.json", bootJSONFor(booted), 0o444))
	}

	return fs
}

// A stock host has one generation, and its kernel is the running one.
func TestNixosInstalledKernelsSingleGeneration(t *testing.T) {
	fs := nixosProfiles(t, map[string]string{"1": nixKernel618}, nixKernel618)

	kernels, err := nixosInstalledKernels(fs, "6.18.50")
	require.NoError(t, err)

	require.Len(t, kernels, 1)
	assert.Equal(t, "linux", kernels[0].Name)
	assert.Equal(t, "6.18.50", kernels[0].Version)
	assert.True(t, kernels[0].Running)
}

// A host that has been rebuilt onto a newer kernel but not rebooted has both
// installed, and the older one is still the running one.
func TestNixosInstalledKernelsRunningIsNotTheNewest(t *testing.T) {
	fs := nixosProfiles(t, map[string]string{
		"1": nixKernel612,
		"2": nixKernel618,
	}, nixKernel612)

	kernels, err := nixosInstalledKernels(fs, "6.12.93")
	require.NoError(t, err)

	require.Len(t, kernels, 2)
	// Newest first, so a policy comparing the running kernel to the newest
	// installed one reads the list the way the boot menu presents it.
	assert.Equal(t, "6.18.50", kernels[0].Version)
	assert.False(t, kernels[0].Running)
	assert.Equal(t, "6.12.93", kernels[1].Version)
	assert.True(t, kernels[1].Running)
}

// Most generations share a kernel: a configuration change rebuilds the system
// without touching it. That is one installed kernel, not four.
func TestNixosInstalledKernelsCollapsesSharedKernels(t *testing.T) {
	fs := nixosProfiles(t, map[string]string{
		"1": nixKernel618,
		"2": nixKernel618,
		"3": nixKernel618,
		"4": nixKernel618,
	}, nixKernel618)

	kernels, err := nixosInstalledKernels(fs, "6.18.50")
	require.NoError(t, err)

	require.Len(t, kernels, 1)
	assert.Equal(t, "6.18.50", kernels[0].Version)
	assert.True(t, kernels[0].Running)
}

// The booted kernel's store path decides which is running, because a hardened
// or realtime kernel reports a `uname -r` its derivation version does not
// contain. Matching the version string alone would mark none of them running.
func TestNixosInstalledKernelsRunningFromBootedPath(t *testing.T) {
	hardened := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux-hardened-6.12.93/bzImage"
	fs := nixosProfiles(t, map[string]string{"1": hardened}, hardened)

	kernels, err := nixosInstalledKernels(fs, "6.12.93-hardened1")
	require.NoError(t, err)

	require.Len(t, kernels, 1)
	assert.Equal(t, "linux-hardened", kernels[0].Name)
	assert.Equal(t, "6.12.93", kernels[0].Version)
	assert.True(t, kernels[0].Running, "the booted store path identifies it where the version string cannot")
}

// Without /run there is nothing to compare a path against, so the version
// string is all that is left.
func TestNixosInstalledKernelsWithoutBootedSystem(t *testing.T) {
	fs := nixosProfiles(t, map[string]string{
		"1": nixKernel612,
		"2": nixKernel618,
	}, "")

	kernels, err := nixosInstalledKernels(fs, "6.18.50")
	require.NoError(t, err)

	require.Len(t, kernels, 2)
	byVersion := map[string]bool{}
	for _, k := range kernels {
		byVersion[k.Version] = k.Running
	}
	assert.True(t, byVersion["6.18.50"])
	assert.False(t, byVersion["6.12.93"])
}

// A host with no system profile directory is not a NixOS host this can answer
// for, and an empty list would read as "no kernels installed".
func TestNixosInstalledKernelsWithoutProfiles(t *testing.T) {
	_, err := nixosInstalledKernels(afero.NewMemMapFs(), "6.18.50")
	require.Error(t, err)
}

func TestParseNixosKernelStorePath(t *testing.T) {
	tests := []struct {
		path    string
		name    string
		version string
		ok      bool
	}{
		{nixKernel618, "linux", "6.18.50", true},
		{nixKernel612, "linux", "6.12.93", true},
		{
			"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux-hardened-6.12.93/bzImage",
			"linux-hardened", "6.12.93", true,
		},
		{
			"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux-rt-6.6.30/bzImage",
			"linux-rt", "6.6.30", true,
		},
		// The initrd sits beside the kernel in the same shape.
		{nixInitrd618, "", "", false},
		// Not a store path.
		{"/boot/vmlinuz-6.18.50", "", "", false},
		// A store entry with no version is not a kernel.
		{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-kernel/bzImage", "", "", false},
	}

	for _, tt := range tests {
		name, version, ok := parseNixosKernelStorePath(tt.path)
		assert.Equal(t, tt.ok, ok, "ok for %q", tt.path)
		assert.Equal(t, tt.name, name, "name for %q", tt.path)
		assert.Equal(t, tt.version, version, "version for %q", tt.path)
	}
}

// Kernel versions are not strings. A host whose generations span a minor bump
// carries 6.9 and 6.18 at once, and comparing those lexicographically puts 6.9
// first because "9" sorts above "1" -- so a policy reading the list as
// newest-first, or taking element 0 as the newest installed kernel, gets the
// older one.
func TestNixosInstalledKernelsOrdersVersionsNumerically(t *testing.T) {
	older := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux-6.9.1/bzImage"
	newer := "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-linux-6.18.50/bzImage"

	fs := nixosProfiles(t, map[string]string{
		"1": older,
		"2": newer,
	}, older)

	kernels, err := nixosInstalledKernels(fs, "6.9.1")
	require.NoError(t, err)

	require.Len(t, kernels, 2)
	assert.Equal(t, "6.18.50", kernels[0].Version, "6.18.50 is newer than 6.9.1")
	assert.False(t, kernels[0].Running)
	assert.Equal(t, "6.9.1", kernels[1].Version)
	assert.True(t, kernels[1].Running)
}

// Kernels of different flavours stay grouped by name, and each group is
// ordered newest-first within itself.
func TestNixosInstalledKernelsOrdersByNameThenVersion(t *testing.T) {
	fs := nixosProfiles(t, map[string]string{
		"1": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux-6.9.1/bzImage",
		"2": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-linux-6.18.50/bzImage",
		"3": "/nix/store/cccccccccccccccccccccccccccccccc-linux-hardened-6.9.1/bzImage",
		"4": "/nix/store/dddddddddddddddddddddddddddddddd-linux-hardened-6.18.50/bzImage",
	}, "")

	kernels, err := nixosInstalledKernels(fs, "6.18.50")
	require.NoError(t, err)
	require.Len(t, kernels, 4)

	assert.Equal(t, "linux", kernels[0].Name)
	assert.Equal(t, "6.18.50", kernels[0].Version)
	assert.Equal(t, "linux", kernels[1].Name)
	assert.Equal(t, "6.9.1", kernels[1].Version)
	assert.Equal(t, "linux-hardened", kernels[2].Name)
	assert.Equal(t, "6.18.50", kernels[2].Version)
	assert.Equal(t, "linux-hardened", kernels[3].Name)
	assert.Equal(t, "6.9.1", kernels[3].Version)
}
