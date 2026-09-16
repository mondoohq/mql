// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	NixPkgFormat = "nix"
)

type NixPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (npm *NixPkgManager) Name() string {
	return "Nix Package Manager"
}

func (npm *NixPkgManager) Format() string {
	return NixPkgFormat
}

func (npm *NixPkgManager) List() ([]Package, error) {
	// Primary: nix-env CLI (available on NixOS and standalone Nix)
	if npm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		pkgs, err := npm.listFromCLI()
		if err == nil {
			return pkgs, nil
		}
		log.Debug().Err(err).Msg("mql[nix]> could not enumerate via CLI, falling back to filesystem")
	}

	// Fallback: parse /nix/store/ directory names
	return npm.listFromFS()
}

func (npm *NixPkgManager) listFromCLI() ([]Package, error) {
	cmd, err := npm.conn.RunCommand("nix-env --query --installed --json")
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("nix-env query failed with exit code %d", cmd.ExitStatus)
	}

	return ParseNixJSON(cmd.Stdout)
}

// nixJSONPackage is one entry of the JSON object `nix-env --query --installed
// --json` prints. The object is keyed by the package's position in the
// profile ("0", "1", "2", ...), so only the values carry meaning.
//
// pname and version are the fields to read: nix has already split them out of
// the derivation, which makes them authoritative where a store path name has
// to be parsed.
type nixJSONPackage struct {
	PName   string `json:"pname"`
	Version string `json:"version"`
	// Nix system double pairing architecture with kernel, e.g. "aarch64-linux".
	System string `json:"system"`
}

// ParseNixJSON parses the JSON output of `nix-env --query --installed --json`.
func ParseNixJSON(r io.Reader) ([]Package, error) {
	var packages map[string]nixJSONPackage
	if err := json.NewDecoder(r).Decode(&packages); err != nil {
		return nil, fmt.Errorf("could not parse nix-env JSON: %w", err)
	}

	pkgs := make([]Package, 0, len(packages))
	for _, np := range packages {
		name := np.PName
		if name == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:    name,
			Version: np.Version,
			Arch:    nixSystemArch(np.System),
			Format:  NixPkgFormat,
			PUrl:    newNixPurl(name, np.Version),
		})
	}

	return pkgs, nil
}

// nixSystemArch returns the architecture of a nix system double such as
// "aarch64-linux" or "x86_64-darwin". Nix pairs the architecture with the
// kernel, and only the architecture describes the package.
func nixSystemArch(system string) string {
	arch, _, _ := strings.Cut(system, "-")
	return arch
}

func (npm *NixPkgManager) listFromFS() ([]Package, error) {
	afs := &afero.Afero{Fs: npm.conn.FileSystem()}
	return ParseNixStore(afs, "/nix/store")
}

// nixStoreRegex matches Nix store path directory names.
// Format: <32-char hash>-<name>[-<version>][-<output>]
// Example: "8gdgwydsf6gia9j178nymxwm2bl0z3m3-curl-8.20.0-bin"
var nixStoreRegex = regexp.MustCompile(`^[a-z0-9]{32}-(.+)$`)

// ParseNixStore enumerates packages from the /nix/store directory.
//
// The store is a weaker source than nix-env: it holds every path ever built
// or fetched on the machine, so a package that only an old generation
// references is still there, and nothing in a path name says whether the
// running system uses it. Read it only when nix cannot be asked directly.
func ParseNixStore(afs *afero.Afero, storePath string) ([]Package, error) {
	entries, err := afs.ReadDir(storePath)
	if err != nil {
		return nil, fmt.Errorf("could not read nix store at %s: %w", storePath, err)
	}

	// Use a map to deduplicate (same package may appear multiple times
	// in the store with different hashes)
	seen := map[string]Package{}
	for _, entry := range entries {
		// Nix realizes an output as a directory, and writes a derivation,
		// patch, setup hook or source archive as a plain file. On the store
		// captured in testdata that is 684 of 841 entries, none of them a
		// package.
		if !entry.IsDir() {
			continue
		}

		m := nixStoreRegex.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}

		nameVersion := m[1]

		// An image or archive filesystem can report an entry without a usable
		// mode, so reject a derivation by name as well. Derivations outnumber
		// outputs in a store that has built anything.
		if strings.HasSuffix(nameVersion, ".drv") {
			continue
		}

		name, version := splitNixNameVersion(nameVersion)
		if name == "" || version == "" {
			// The store's own bookkeeping outputs carry no version:
			// user-environment, root-profile-env, base-system, channel-nixos,
			// and the unpacked sources under source. A package always has one.
			continue
		}

		key := name + "@" + version
		if _, ok := seen[key]; !ok {
			seen[key] = Package{
				Name:    name,
				Version: version,
				Format:  NixPkgFormat,
				PUrl:    newNixPurl(name, version),
			}
		}
	}

	pkgs := make([]Package, 0, len(seen))
	for _, p := range seen {
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// nixOutputNames are the output names nixpkgs derivations declare. Nix
// realizes one store path per output and suffixes the path with the output
// name, so curl-8.20.0 and curl-8.20.0-bin are one package at one version.
//
// Only a name on this list is treated as an output, because a version can end
// in a word of its own: publicsuffix-list-0-unstable-2026-05-13 is version
// 0-unstable-2026-05-13, and stripping its tail would report a package that
// does not exist.
var nixOutputNames = map[string]struct{}{
	"bin": {}, "debug": {}, "dev": {}, "devdoc": {}, "dist": {},
	"doc": {}, "info": {}, "lib": {}, "man": {}, "out": {}, "static": {},
	// gcc calls its runtime output libgcc; util-linux splits login, mount and
	// swap out of its bin output.
	"libgcc": {}, "login": {}, "mount": {}, "swap": {},
}

// splitNixNameVersion splits a nix derivation name into pname and version the
// way nix itself does: the version begins at the first hyphen that is not
// followed by a letter (DrvName, src/libexpr/names.cc). A pname can therefore
// carry hyphens and digits of its own, and a version can carry hyphens too.
//
// A store path adds the derivation's output name as a further suffix, which
// belongs to neither field, so a known output name is removed.
//
//	"curl-8.20.0-bin"                     → ("curl", "8.20.0")
//	"git-minimal-2.54.0"                  → ("git-minimal", "2.54.0")
//	"glibc-2.42-67"                       → ("glibc", "2.42-67")
//	"editline-1.17.1-unstable-2025-05-24" → ("editline", "1.17.1-unstable-2025-05-24")
func splitNixNameVersion(s string) (string, string) {
	name, version := s, ""
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '-' && !isNixNameLetter(s[i+1]) {
			name, version = s[:i], s[i+1:]
			break
		}
	}

	if i := strings.LastIndexByte(version, '-'); i != -1 {
		if _, ok := nixOutputNames[version[i+1:]]; ok {
			version = version[:i]
		}
	}

	return name, version
}

// isNixNameLetter reports whether b continues a pname rather than starting a
// version. Nix decides this with isalpha() in the C locale.
func isNixNameLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// newNixPurl creates a PURL for a Nix package.
// Format: pkg:nix/name@version
func newNixPurl(name, version string) string {
	if name == "" {
		return ""
	}
	return packageurl.NewPackageURL(
		packageurl.TypeNix,
		"",
		name,
		version,
		nil,
		"",
	).String()
}

func (npm *NixPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (npm *NixPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}
