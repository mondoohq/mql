// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
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

	// nixStorePrefix is where nix realizes its outputs. It is configurable, but
	// a NixOS system cannot move it, and a relocated store on another
	// distribution still answers through nix-env.
	nixStorePrefix = "/nix/store/"

	// nixosCurrentSystem is the generation NixOS has activated. Its closure is
	// the set of store paths the running system is built from.
	nixosCurrentSystem = "/run/current-system"

	// nixSystemClosureCommand lists the directories in the current system's
	// closure. The directory test runs on the host because nix realizes an
	// output as a directory and writes generated configuration as a plain file
	// (etc-sysctl.d-60-nixos.conf), and one round-trip is cheaper than a stat
	// per path over a remote connection.
	nixSystemClosureCommand = `nix-store --query --requisites ` + nixosCurrentSystem +
		` | while IFS= read -r p; do [ -d "$p" ] && printf '%s\n' "$p"; done`
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
	if npm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		// On NixOS the packages that make up the system are declared in the
		// configuration and built into a generation, not installed into a
		// profile. nix-env reports a profile, so on a declaratively managed
		// host it reports nothing: `nix-env --query --installed --json`
		// answers "{}" on a NixOS host whose closure holds 681 store paths.
		// Reading the profile alone left every such host reporting no packages
		// at all, which a policy asserting a package is absent then passed.
		closure, closureErr := npm.listFromSystemClosure()
		if closureErr != nil {
			log.Debug().Err(closureErr).
				Msg("mql[nix]> could not read the system closure")
		}

		// A profile can hold packages beside the system's own, on NixOS as
		// well as on a distribution that only has nix installed, so both are
		// asked and the answers merged.
		profile, profileErr := npm.listFromCLI()
		if profileErr != nil {
			log.Debug().Err(profileErr).
				Msg("mql[nix]> could not enumerate the nix profile")
		}

		if len(closure) > 0 || len(profile) > 0 {
			return mergeNixPackages(closure, profile), nil
		}

		// Neither source answered. An empty profile on a host with no system
		// closure is a real answer on a machine where nothing is installed,
		// but so is a failure of both commands, so fall through to the store
		// rather than reporting an empty list either way.
		if closureErr == nil && profileErr == nil {
			log.Debug().Msg("mql[nix]> neither the system closure nor the profile named a package")
		}
	}

	// Fallback: parse /nix/store/ directory names
	return npm.listFromFS()
}

// listFromSystemClosure reports the packages the running NixOS generation is
// built from. It returns nothing, and no error, on a host that has no
// activated generation -- a distribution with nix installed alongside its own
// package manager.
func (npm *NixPkgManager) listFromSystemClosure() ([]Package, error) {
	if _, err := npm.conn.FileSystem().Stat(nixosCurrentSystem); err != nil {
		return nil, nil
	}

	cmd, err := npm.conn.RunCommand(nixSystemClosureCommand)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("nix-store query of %s failed with exit code %d",
			nixosCurrentSystem, cmd.ExitStatus)
	}

	return ParseNixSystemClosure(cmd.Stdout)
}

// mergeNixPackages unions the two sources on name and version. A package in
// the system closure is usually in no profile and vice versa, but a profile
// can install the very version the system already has.
func mergeNixPackages(lists ...[]Package) []Package {
	seen := map[string]struct{}{}
	res := make([]Package, 0, len(lists[0]))
	for _, list := range lists {
		for _, p := range list {
			key := p.Name + "@" + p.Version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			res = append(res, p)
		}
	}
	return res
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

		pkg := nixPackageFromStoreEntry(m[1])
		if pkg == nil {
			continue
		}

		key := pkg.Name + "@" + pkg.Version
		if _, ok := seen[key]; !ok {
			seen[key] = *pkg
		}
	}

	pkgs := make([]Package, 0, len(seen))
	for _, p := range seen {
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// nixPackageFromStoreEntry turns a store entry name -- the part of a store
// path after the hash -- into the package it holds, or nil when it holds
// something that is not one.
//
// Both callers need the same answer: a store directory listing and the closure
// of the running system name their entries identically, and a rule applied to
// one and not the other would report a different set of packages depending on
// whether nix could be asked.
func nixPackageFromStoreEntry(entry string) *Package {
	// A derivation is a file rather than a directory, so a caller reading real
	// modes has already skipped it. An image or archive filesystem can report
	// an entry without a usable mode, and derivations outnumber outputs in a
	// store that has built anything.
	if strings.HasSuffix(entry, ".drv") {
		return nil
	}

	name, version := splitNixNameVersion(entry)
	if name == "" || version == "" {
		// Bookkeeping outputs carry no version: user-environment,
		// root-profile-env, base-system, channel-nixos, the unpacked sources
		// under source, and on NixOS every generated systemd unit
		// (unit-systemd-journald.service). A package always has one.
		return nil
	}

	// nix splits the version off at the first hyphen that is not followed by a
	// letter, so a version can begin with a dot or a hyphen as well as with a
	// digit. Only a digit begins a real one. NixOS builds a templated systemd
	// unit into the store as unit-systemd-backlight-.service, whose version
	// would otherwise read as ".service".
	if version[0] < '0' || version[0] > '9' {
		return nil
	}

	return &Package{
		Name:    name,
		Version: version,
		Format:  NixPkgFormat,
		PUrl:    newNixPurl(name, version),
	}
}

// ParseNixSystemClosure reads the store paths of a NixOS system closure, one
// per line, as `nix-store --query --requisites` prints them.
func ParseNixSystemClosure(r io.Reader) ([]Package, error) {
	seen := map[string]Package{}

	scanner := bufio.NewScanner(r)
	// A closure line is a store path, but the buffer has to hold one even on a
	// store with a long prefix.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// nix writes warnings to stderr, but a caller that merged the streams
		// would hand them over here, and a warning is not a package.
		entry, ok := strings.CutPrefix(line, nixStorePrefix)
		if !ok {
			continue
		}

		m := nixStoreRegex.FindStringSubmatch(entry)
		if m == nil {
			continue
		}

		pkg := nixPackageFromStoreEntry(m[1])
		if pkg == nil {
			continue
		}

		key := pkg.Name + "@" + pkg.Version
		if _, dup := seen[key]; !dup {
			seen[key] = *pkg
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read nix system closure: %w", err)
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
// A name missing from this list costs a duplicate entry -- the package is
// reported once at its version and once with the output name trailing it --
// while a version word wrongly on it corrupts the version of every release
// that uses it. That asymmetry is why this is a list of outputs to strip
// rather than a list of version words to keep.
var nixOutputNames = map[string]struct{}{
	"bin": {}, "debug": {}, "dev": {}, "devdoc": {}, "dist": {},
	"doc": {}, "info": {}, "lib": {}, "man": {}, "out": {}, "static": {},
	// Outputs a single derivation names for itself, all seen in the closure of
	// a stock NixOS 26.05 system: gcc calls its runtime output libgcc,
	// util-linux splits login, mount, swap and lastlog out of bin, glibc ships
	// getent, bind ships host, libressl ships nc, shadow ships su, lvm2 ships
	// scripts, cloud-utils ships guest, and the kernel ships modules.
	"libgcc": {}, "login": {}, "mount": {}, "swap": {}, "lastlog": {},
	"getent": {}, "host": {}, "nc": {}, "su": {}, "scripts": {},
	"guest": {}, "modules": {}, "env": {},
	// NixOS builds the kernel modules the initrd needs into
	// linux-<version>-modules-shrunk, so an output name can be more than one
	// component long.
	"shrunk": {},
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

	// An output name can be several components long, as in
	// linux-6.12.93-modules-shrunk, so strip for as long as the tail is one.
	// Each pass removes a component, so this ends.
	for {
		i := strings.LastIndexByte(version, '-')
		if i == -1 {
			break
		}
		if _, ok := nixOutputNames[version[i+1:]]; !ok {
			break
		}
		version = version[:i]
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
