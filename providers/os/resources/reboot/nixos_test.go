// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reboot

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bootJSON is the shape NixOS writes, trimmed to the fields that decide a
// reboot. Captured from /run/current-system/boot.json on NixOS 26.05: the
// document is keyed by bootspec namespace, and a second namespace sits beside
// the one that matters.
func bootJSON(kernel, initrd string) string {
	return `{
  "org.nixos.bootspec.v1": {
    "init": "/nix/store/99bljb0jiac0rzkjv0hhclbzz2fn3jx5-nixos-system-unnamed-amazon-26.05/init",
    "initrd": "` + initrd + `",
    "kernel": "` + kernel + `",
    "kernelParams": ["panic=1", "console=ttyS0,115200n8"],
    "label": "NixOS Yarara amazon-26.05.9592.21a67dc47014 (Linux 6.18.50)",
    "system": "x86_64-linux",
    "toplevel": "/nix/store/99bljb0jiac0rzkjv0hhclbzz2fn3jx5-nixos-system-unnamed-amazon-26.05"
  },
  "org.nixos.nixos-init.v1": {
    "env_binary": "/nix/store/61685rbaxmpnnnr9kkxsq5k3g1zf3g9k-coreutils-9.11/bin/env"
  }
}`
}

const (
	kernel618 = "/nix/store/dvab2dg1czm40gp5si151sj86rfjwnfm-linux-6.18.50/bzImage"
	initrd618 = "/nix/store/0svpws07al77h054na894bbbz61p8rj7-initrd-linux-6.18.50/initrd"
	kernel612 = "/nix/store/qzl0003mqn698wxc4yv31zyz95lxl51b-linux-6.12.93/bzImage"
	initrd612 = "/nix/store/mks1hnym57qn8m5payqgqgz5qnhjcxpk-initrd-linux-6.12.93/initrd"
)

func nixosFs(t *testing.T, booted, current string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, nixosBootedSystemBootJSON, []byte(booted), 0o444))
	require.NoError(t, afero.WriteFile(fs, nixosCurrentSystemBootJSON, []byte(current), 0o444))
	return fs
}

// NixOS activates a new generation without rebooting, so the question is
// whether the running kernel and initrd are the ones the activated system
// boots.
func TestNixosRebootPending(t *testing.T) {
	tests := []struct {
		name    string
		booted  string
		current string
		pending bool
	}{
		{
			name:    "same generation",
			booted:  bootJSON(kernel618, initrd618),
			current: bootJSON(kernel618, initrd618),
			pending: false,
		},
		{
			name:    "kernel upgraded, not yet booted",
			booted:  bootJSON(kernel612, initrd612),
			current: bootJSON(kernel618, initrd618),
			pending: true,
		},
		{
			name:    "initrd rebuilt on the same kernel",
			booted:  bootJSON(kernel618, initrd618),
			current: bootJSON(kernel618, initrd612),
			pending: true,
		},
	}

	for _, tt := range tests {
		r := &NixosReboot{fs: nixosFs(t, tt.booted, tt.current)}
		pending, err := r.RebootPending()
		require.NoError(t, err, tt.name)
		assert.Equal(t, tt.pending, pending, tt.name)
	}
}

// A config-only change -- a service, a package, a file in /etc -- produces a
// new generation that boots the same kernel and initrd. It is already in
// effect, so it is not a reboot.
func TestNixosRebootPendingIgnoresToplevel(t *testing.T) {
	booted := bootJSON(kernel618, initrd618)
	current := `{
  "org.nixos.bootspec.v1": {
    "initrd": "` + initrd618 + `",
    "kernel": "` + kernel618 + `",
    "toplevel": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nixos-system-unnamed-amazon-26.05"
  }
}`

	r := &NixosReboot{fs: nixosFs(t, booted, current)}
	pending, err := r.RebootPending()
	require.NoError(t, err)
	assert.False(t, pending, "a new generation booting the same kernel needs no reboot")
}

// /run is a tmpfs the running system populates, so an offline scan of a NixOS
// disk or image has neither file. Reporting "no reboot pending" there would
// state as fact something that was never read.
func TestNixosRebootPendingWithoutRunFiles(t *testing.T) {
	r := &NixosReboot{fs: afero.NewMemMapFs()}
	_, err := r.RebootPending()
	require.Error(t, err)
}

func TestNixosRebootPendingMalformedBootJSON(t *testing.T) {
	r := &NixosReboot{fs: nixosFs(t, "not json at all", bootJSON(kernel618, initrd618))}
	_, err := r.RebootPending()
	require.Error(t, err)
}

// boot.json without a kernel is not a generation we can compare, and guessing
// equality from two empty strings would report no reboot pending.
func TestNixosRebootPendingEmptyKernel(t *testing.T) {
	empty := `{"org.nixos.bootspec.v1": {"initrd": "", "kernel": ""}}`
	r := &NixosReboot{fs: nixosFs(t, empty, empty)}
	_, err := r.RebootPending()
	require.Error(t, err)
}

// A boot.json carrying no bootspec namespace this code knows is not a
// generation it can compare. Saying so beats reading two absent kernels as
// equal and reporting that no reboot is pending.
func TestNixosRebootPendingUnknownBootspecVersion(t *testing.T) {
	future := `{"org.nixos.bootspec.v2": {"kernel": "` + kernel618 + `"}}`
	r := &NixosReboot{fs: nixosFs(t, future, future)}
	_, err := r.RebootPending()
	require.Error(t, err)
}
