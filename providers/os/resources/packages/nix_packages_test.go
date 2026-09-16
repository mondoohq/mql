// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nixStoreFromListing builds an in-memory /nix/store from a captured listing.
// Nix realizes every output as a directory and writes every derivation, patch
// and source as a plain file, and the listing records which is which, so the
// in-memory store has to reproduce both kinds for a scan of it to mean
// anything.
func nixStoreFromListing(t *testing.T, path string) *afero.Afero {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/nix/store", 0o755))

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, name, ok := strings.Cut(line, " ")
		require.True(t, ok, "malformed listing line %q", line)

		switch kind {
		case "d":
			require.NoError(t, afs.MkdirAll("/nix/store/"+name, 0o755))
		case "f":
			require.NoError(t, afs.WriteFile("/nix/store/"+name, []byte("fixture"), 0o444))
		default:
			t.Fatalf("unknown entry type %q in listing line %q", kind, line)
		}
	}
	require.NoError(t, scanner.Err())

	return afs
}

func TestParseNixJSON(t *testing.T) {
	f, err := os.Open("testdata/nix_env.json")
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := ParseNixJSON(f)
	require.NoError(t, err)
	require.Len(t, pkgs, 19)

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// pname and version come apart in the nix-env output itself, so a package
	// whose name carries a word that looks like a version suffix still has to
	// survive intact.
	tests := []struct {
		name    string
		version string
	}{
		{"hello", "2.12.3"},
		{"curl", "8.20.0"},
		{"openssl", "3.6.2"},
		{"python3", "3.12.13"},
		{"git-minimal", "2.54.0"},
		{"coreutils-full", "9.11"},
		{"bash-interactive", "5.3p9"},
		{"nss-cacert", "3.123"},
		{"openssh", "10.3p1"},
		{"less", "692"},
		{"iana-etc", "20251215"},
	}
	for _, tt := range tests {
		pkg, ok := byName[tt.name]
		require.True(t, ok, "nix-env output has no package %q", tt.name)
		assert.Equal(t, tt.version, pkg.Version, "version of %q", tt.name)
		assert.Equal(t, "nix", pkg.Format, "format of %q", tt.name)
		assert.Equal(t, "aarch64", pkg.Arch, "arch of %q", tt.name)
	}

	assert.Equal(t, "pkg:nix/curl@8.20.0", byName["curl"].PUrl)
	assert.Equal(t, "pkg:nix/bash-interactive@5.3p9", byName["bash-interactive"].PUrl)
}

func TestSplitNixNameVersion(t *testing.T) {
	// Every input is a real store entry name from testdata/nix_store_listing.txt;
	// the expectations are the pname and version nix itself reports for them.
	tests := []struct {
		input   string
		name    string
		version string
	}{
		// The version starts at the first hyphen not followed by a letter, so a
		// name may hold several hyphens and digits of its own.
		{"curl-8.20.0", "curl", "8.20.0"},
		{"git-minimal-2.54.0", "git-minimal", "2.54.0"},
		{"coreutils-full-9.11", "coreutils-full", "9.11"},
		{"bash-interactive-5.3p9", "bash-interactive", "5.3p9"},
		{"nss-cacert-3.123", "nss-cacert", "3.123"},
		{"gmp-with-cxx-6.3.0", "gmp-with-cxx", "6.3.0"},
		{"systemd-minimal-libs-260.2", "systemd-minimal-libs", "260.2"},
		{"util-linux-minimal-2.42", "util-linux-minimal", "2.42"},
		{"libssh2-1.11.1", "libssh2", "1.11.1"},
		{"python3-3.12.13", "python3", "3.12.13"},
		{"openssh-10.3p1", "openssh", "10.3p1"},
		{"less-692", "less", "692"},
		{"iana-etc-20251215", "iana-etc", "20251215"},
		{"dns-root-data-2025-04-14", "dns-root-data", "2025-04-14"},

		// A multi-output derivation gets one store path per output, suffixed
		// with the output name. They are the same package, so the suffix
		// belongs to neither the name nor the version.
		{"curl-8.20.0-bin", "curl", "8.20.0"},
		{"curl-8.20.0-dev", "curl", "8.20.0"},
		{"curl-8.20.0-man", "curl", "8.20.0"},
		{"curl-8.20.0-doc", "curl", "8.20.0"},
		{"curl-8.20.0-devdoc", "curl", "8.20.0"},
		{"curl-8.20.0-debug", "curl", "8.20.0"},
		{"libarchive-3.8.7-lib", "libarchive", "3.8.7"},
		{"zlib-1.3.2-static", "zlib", "1.3.2"},
		{"bash-interactive-5.3p9-man", "bash-interactive", "5.3p9"},
		{"less-692-man", "less", "692"},
		{"gcc-15.2.0-libgcc", "gcc", "15.2.0"},
		{"util-linux-minimal-2.42-login", "util-linux-minimal", "2.42"},
		{"util-linux-minimal-2.42-mount", "util-linux-minimal", "2.42"},
		{"util-linux-minimal-2.42-swap", "util-linux-minimal", "2.42"},

		// glibc's version carries a patch counter, so the output suffix is not
		// the only hyphenated tail a version can have.
		{"glibc-2.42-67", "glibc", "2.42-67"},
		{"glibc-2.42-67-bin", "glibc", "2.42-67"},
		{"glibc-2.42-84-getent", "glibc", "2.42-84"},

		// An output name can run to several components.
		{"linux-6.12.93-modules-shrunk", "linux", "6.12.93"},
		{"linux-6.18.50-modules", "linux", "6.18.50"},
		{"util-linux-2.42.2-lastlog", "util-linux", "2.42.2"},
		{"bind-9.20.26-host", "bind", "9.20.26"},
		{"libressl-4.2.1-nc", "libressl", "4.2.1"},
		{"shadow-4.19.4-su", "shadow", "4.19.4"},
		{"lvm2-2.03.39-scripts", "lvm2", "2.03.39"},
		{"cloud-utils-0.33-guest", "cloud-utils", "0.33"},

		// A version can end in words of its own. Those are part of the version
		// and must survive, which is why only a known output name is stripped.
		{"editline-1.17.1-unstable-2025-05-24", "editline", "1.17.1-unstable-2025-05-24"},
		{"publicsuffix-list-0-unstable-2026-05-13", "publicsuffix-list", "0-unstable-2026-05-13"},
		{"libsodium-1.0.22-unstable-2026-04-09", "libsodium", "1.0.22-unstable-2026-04-09"},

		// Store entries that carry no version at all.
		{"source", "source", ""},
		{"base-system", "base-system", ""},
		{"channel-nixos", "channel-nixos", ""},
		{"user-environment", "user-environment", ""},
		{"root-profile-env", "root-profile-env", ""},
	}
	for _, tt := range tests {
		name, version := splitNixNameVersion(tt.input)
		assert.Equal(t, tt.name, name, "splitNixNameVersion(%q) name", tt.input)
		assert.Equal(t, tt.version, version, "splitNixNameVersion(%q) version", tt.input)
	}
}

func TestParseNixStore(t *testing.T) {
	afs := nixStoreFromListing(t, "testdata/nix_store_listing.txt")

	pkgs, err := ParseNixStore(afs, "/nix/store")
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	byName := map[string][]Package{}
	for _, p := range pkgs {
		byName[p.Name] = append(byName[p.Name], p)
	}

	// The captured store holds curl's out, bin, dev, man, doc, devdoc and
	// debug outputs. All seven are one installed package at one version.
	require.Len(t, byName["curl"], 1, "curl reported %d times", len(byName["curl"]))
	assert.Equal(t, "8.20.0", byName["curl"][0].Version)
	assert.Equal(t, "pkg:nix/curl@8.20.0", byName["curl"][0].PUrl)

	require.Len(t, byName["openssl"], 1)
	assert.Equal(t, "3.6.2", byName["openssl"][0].Version)

	require.Len(t, byName["util-linux-minimal"], 1)
	assert.Equal(t, "2.42", byName["util-linux-minimal"][0].Version)

	require.Len(t, byName["glibc"], 1)
	assert.Equal(t, "2.42-67", byName["glibc"][0].Version)

	// Nothing in the store that is not a package may be reported as one. These
	// are the store's own bookkeeping outputs.
	for _, name := range []string{
		"source", "base-system", "channel-nixos", "user-environment", "root-profile-env",
	} {
		assert.NotContains(t, byName, name, "%q is not an installed package", name)
	}

	// Derivations, patches, hooks and source archives are files in the store,
	// never installed packages.
	for _, p := range pkgs {
		assert.NotContains(t, p.Version, ".drv", "package %q carries a derivation version", p.Name)
		assert.NotContains(t, p.Name, ".patch", "patch file reported as package: %q", p.Name)
		assert.NotContains(t, p.Name, ".sh", "setup hook reported as package: %q", p.Name)
		assert.NotContains(t, p.Name, ".tar", "source archive reported as package: %q", p.Name)
	}

	// No version may carry an output name. Listed here rather than read from
	// the implementation so that shortening that list fails this test.
	outputs := []string{
		"bin", "dev", "lib", "man", "doc", "devdoc", "info", "static",
		"debug", "dist", "out", "libgcc", "login", "mount", "swap",
	}
	for _, p := range pkgs {
		for _, out := range outputs {
			assert.False(t, strings.HasSuffix(p.Version, "-"+out),
				"package %q version %q ends in output name %q", p.Name, p.Version, out)
		}
		assert.NotEmpty(t, p.Version, "package %q has no version", p.Name)
	}
}

// TestParseNixStoreMatchesNixEnv holds the store scan to what nix itself
// reports. Both fixtures were captured from the same container at the same
// moment, but by different parts of nix: the scan reads store path names off
// the filesystem, while nix-env reads pname and version out of each
// derivation. Every package nix-env names must come back from the scan once,
// at the same version.
func TestParseNixStoreMatchesNixEnv(t *testing.T) {
	f, err := os.Open("testdata/nix_env.json")
	require.NoError(t, err)
	defer f.Close()

	var installed map[string]struct {
		PName   string `json:"pname"`
		Version string `json:"version"`
	}
	require.NoError(t, json.NewDecoder(f).Decode(&installed))
	require.NotEmpty(t, installed)

	afs := nixStoreFromListing(t, "testdata/nix_store_listing.txt")
	pkgs, err := ParseNixStore(afs, "/nix/store")
	require.NoError(t, err)

	scanned := map[string][]string{}
	for _, p := range pkgs {
		scanned[p.Name] = append(scanned[p.Name], p.Version)
	}

	for _, want := range installed {
		versions := scanned[want.PName]
		require.Len(t, versions, 1,
			"nix-env reports %s-%s, store scan reports versions %v",
			want.PName, want.Version, versions)
		assert.Equal(t, want.Version, versions[0], "version of %q", want.PName)
	}
}

func TestParseNixStoreSkipsDerivations(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	// A .drv is a file in a real store, but an image or archive filesystem can
	// report entries without a reliable mode, so the name alone has to be
	// enough to reject a derivation.
	require.NoError(t, afs.MkdirAll("/nix/store/035zic59kxhrjvrh6bb9p5q5s93hci01-patchelf-0.15.2.drv", 0o755))
	require.NoError(t, afs.MkdirAll("/nix/store/03ip3cwbyashqb2gsq6q6ag69187zy5j-perl-5.42.0.tar.gz.drv", 0o755))
	require.NoError(t, afs.MkdirAll("/nix/store/8gdgwydsf6gia9j178nymxwm2bl0z3m3-curl-8.20.0-bin", 0o755))

	pkgs, err := ParseNixStore(afs, "/nix/store")
	require.NoError(t, err)

	require.Len(t, pkgs, 1)
	assert.Equal(t, "curl", pkgs[0].Name)
	assert.Equal(t, "8.20.0", pkgs[0].Version)
}

func TestNewNixPurl(t *testing.T) {
	assert.Equal(t, "pkg:nix/curl@8.20.0", newNixPurl("curl", "8.20.0"))
	assert.Equal(t, "pkg:nix/git-minimal@2.54.0", newNixPurl("git-minimal", "2.54.0"))
	assert.Equal(t, "", newNixPurl("", "1.0"))
}
