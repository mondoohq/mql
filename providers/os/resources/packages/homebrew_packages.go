// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// newHomebrewPurl creates a PURL for a Homebrew package.
// Per the PURL spec, the tap is used as the namespace:
// pkg:brew/homebrew/core/curl@8.7.1
// pkg:brew/homebrew/cask/firefox@120.0
func newHomebrewPurl(name, version, tap string) string {
	return packageurl.NewPackageURL(
		"brew",
		tap,
		name,
		version,
		nil,
		"").String()
}

const (
	HomebrewPkgFormat = "homebrew"
)

// HomebrewPkgManager discovers Homebrew packages on macOS and Linux.
type HomebrewPkgManager struct {
	Conn shared.Connection
}

func (h *HomebrewPkgManager) Name() string {
	return "Homebrew Package Manager"
}

func (h *HomebrewPkgManager) Format() string {
	return HomebrewPkgFormat
}

// HomebrewPackage represents a Homebrew package with extended metadata
// beyond the standard Package struct.
type HomebrewPackage struct {
	Name                  string
	Version               string
	LatestVersion         string
	Purl                  string
	Description           string
	Homepage              string
	Path                  string
	Type                  string // "formula" or "cask"
	AppName               string
	AutoUpdates           bool
	InstalledOnRequest    bool
	InstalledAsDependency bool
	Outdated              bool
	// OutdatedUnknown is set when the listing could not tell whether a newer
	// version exists (the filesystem fallback has no access to brew's index),
	// so outdated reads as null rather than as a confident false.
	OutdatedUnknown bool
	Pinned          bool
	Tap             string
	Prefix          string
}

// List returns Homebrew packages using brew info CLI with file parsing fallback.
func (h *HomebrewPkgManager) List() ([]Package, error) {
	// Homebrew data uses the extended HomebrewPackage type, not the standard Package.
	// This method exists for interface compatibility but returns basic Package data.
	pkgs, err := h.ListExtended()
	if err != nil {
		return nil, err
	}

	result := make([]Package, len(pkgs))
	for i, p := range pkgs {
		result[i] = Package{
			Name:        p.Name,
			Version:     p.Version,
			Format:      HomebrewPkgFormat,
			Description: p.Description,
		}
	}
	return result, nil
}

// ListExtended returns Homebrew packages with full metadata.
func (h *HomebrewPkgManager) ListExtended() ([]HomebrewPackage, error) {
	if h.Conn.Capabilities().Has(shared.Capability_RunCommand) {
		pkgs, err := h.listFromCLI()
		if err == nil {
			return pkgs, nil
		}
		log.Debug().Err(err).Msg("mql[homebrew]> could not enumerate via CLI, falling back to filesystem")
	}

	return h.listFromFS()
}

func (h *HomebrewPkgManager) Available() (map[string]PackageUpdate, error) {
	return nil, nil
}

func (h *HomebrewPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}

// brewBinaryPaths are the known locations of the brew binary.
var brewBinaryPaths = []string{
	"/opt/homebrew/bin/brew",              // macOS arm64
	"/usr/local/bin/brew",                 // macOS Intel
	"/home/linuxbrew/.linuxbrew/bin/brew", // Linuxbrew
}

func (h *HomebrewPkgManager) listFromCLI() ([]HomebrewPackage, error) {
	// Find the brew binary
	brewPath := ""
	afs := &afero.Afero{Fs: h.Conn.FileSystem()}
	for _, candidate := range brewBinaryPaths {
		if exists, _ := afs.Exists(candidate); exists {
			brewPath = candidate
			break
		}
	}
	if brewPath == "" {
		return nil, fmt.Errorf("brew binary not found")
	}

	// Derive prefix from brew binary path
	prefix := deriveBrewPrefix(brewPath)

	cmdResult, err := h.Conn.RunCommand(h.brewInfoCommand(brewPath, prefix))
	if err != nil {
		return nil, err
	}

	if cmdResult.ExitStatus != 0 {
		stderr := "unknown error"
		if cmdResult.Stderr != nil {
			stderrBytes, readErr := io.ReadAll(cmdResult.Stderr)
			if readErr == nil {
				stderr = strings.TrimSpace(string(stderrBytes))
			}
		}
		return nil, fmt.Errorf("brew info failed: %s", stderr)
	}

	if cmdResult.Stdout == nil {
		return []HomebrewPackage{}, nil
	}

	data, err := io.ReadAll(cmdResult.Stdout)
	if err != nil {
		return nil, err
	}

	return ParseHomebrewInfo(data, prefix)
}

// brewInfoCommand returns the command that lists the installed packages.
//
// brew refuses to run as root ("Running Homebrew as root is extremely
// dangerous and no longer supported"), so a scan running as root, locally or
// through an SSH connection that elevates with sudo, used to fall back to
// reading the Cellar and lost outdated, pinned, descriptions and latest
// versions. As root the command runs brew as the user that owns the
// installation instead. The connection still wraps the whole command in its
// own sudo where it is configured to, which leaves this command running as
// root, as it expects.
func (h *HomebrewPkgManager) brewInfoCommand(brewPath, prefix string) string {
	if !h.runsAsRoot() {
		return brewPath + " info --json=v2 --installed"
	}
	// The Cellar belongs to the user who installed Homebrew. The prefix
	// itself does not always: /usr/local is root's on Intel Macs.
	for _, p := range []string{prefix + "/Cellar", brewPath} {
		fi, err := h.Conn.FileInfo(p)
		if err == nil && fi.Uid > 0 {
			return brewAsUserCommand(fi.Uid, brewPath)
		}
	}
	return brewPath + " info --json=v2 --installed"
}

// brewAsUserCommand runs `brew info` as the user with the given uid. brew
// also refuses a working directory its user cannot read, which root's home
// is, so the command changes to / first.
//
// brewPath is embedded unquoted in a single-quoted sh -c script. It is always
// one of the fixed brewBinaryPaths, never input from the scan target or the
// user; keep it that way or quote it.
func brewAsUserCommand(uid int64, brewPath string) string {
	return fmt.Sprintf("sudo -n -H -u '#%d' /bin/sh -c 'cd / && exec %s info --json=v2 --installed'", uid, brewPath)
}

func (h *HomebrewPkgManager) runsAsRoot() bool {
	cmd, err := h.Conn.RunCommand("id -u")
	if err != nil || cmd.ExitStatus != 0 || cmd.Stdout == nil {
		return false
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

func (h *HomebrewPkgManager) listFromFS() ([]HomebrewPackage, error) {
	afs := &afero.Afero{Fs: h.Conn.FileSystem()}

	// Try known Homebrew prefix locations, accumulate across all prefixes
	var allPkgs []HomebrewPackage
	prefixes := []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"}
	for _, prefix := range prefixes {
		cellarPath := prefix + "/Cellar"
		caskroomPath := prefix + "/Caskroom"
		cellarExists, _ := afs.DirExists(cellarPath)
		caskroomExists, _ := afs.DirExists(caskroomPath)

		if !cellarExists && !caskroomExists {
			continue
		}

		// Scan formulae from Cellar
		if cellarExists {
			formulae, err := h.parseFromCellar(afs, prefix)
			if err != nil {
				log.Debug().Err(err).Str("path", cellarPath).Msg("mql[homebrew]> could not parse Cellar")
			} else {
				pinned := readBrewPinned(afs, prefix)
				for i := range formulae {
					formulae[i].Pinned = pinned[formulae[i].Name]
				}
				allPkgs = append(allPkgs, formulae...)
			}
		}

		// Scan casks from Caskroom
		if caskroomExists {
			casks, err := h.parseFromCaskroom(afs, prefix)
			if err != nil {
				log.Debug().Err(err).Str("path", caskroomPath).Msg("mql[homebrew]> could not parse Caskroom")
			} else {
				allPkgs = append(allPkgs, casks...)
			}
		}
	}

	// Whether a newer version exists is only known to brew, from its index.
	for i := range allPkgs {
		allPkgs[i].OutdatedUnknown = true
	}

	return allPkgs, nil
}

// readBrewPinned returns the formulae `brew pin` has pinned under prefix.
// brew records a pin as a symlink named after the formula in
// var/homebrew/pinned, pointing at the pinned keg.
func readBrewPinned(afs *afero.Afero, prefix string) map[string]bool {
	res := map[string]bool{}
	entries, err := afs.ReadDir(prefix + "/var/homebrew/pinned")
	if err != nil {
		return res
	}
	for _, e := range entries {
		res[e.Name()] = true
	}
	return res
}

func (h *HomebrewPkgManager) parseFromCellar(afs *afero.Afero, prefix string) ([]HomebrewPackage, error) {
	cellarPath := prefix + "/Cellar"
	entries, err := afs.ReadDir(cellarPath)
	if err != nil {
		return nil, err
	}

	var pkgs []HomebrewPackage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Each formula dir contains version subdirectories
		versionDirs, err := afs.ReadDir(cellarPath + "/" + name)
		if err != nil {
			continue
		}
		for _, vDir := range versionDirs {
			if !vDir.IsDir() {
				continue
			}
			version := vDir.Name()

			// Default tap to homebrew/core for Cellar-discovered formulae
			tap := "homebrew/core"

			pkg := HomebrewPackage{
				Name:    name,
				Version: version,
				Type:    "formula",
				Tap:     tap,
				Prefix:  prefix,
				Path:    cellarPath + "/" + name + "/" + version,
			}

			// Try to read INSTALL_RECEIPT.json for additional metadata
			receiptPath := cellarPath + "/" + name + "/" + version + "/INSTALL_RECEIPT.json"
			if receiptData, err := afs.ReadFile(receiptPath); err == nil {
				enrichFromReceipt(&pkg, receiptData)
				if pkg.Tap != "" {
					tap = pkg.Tap
				}
			}

			pkg.Purl = newHomebrewPurl(name, version, tap)

			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs, nil
}

func (h *HomebrewPkgManager) parseFromCaskroom(afs *afero.Afero, prefix string) ([]HomebrewPackage, error) {
	caskroomPath := prefix + "/Caskroom"
	entries, err := afs.ReadDir(caskroomPath)
	if err != nil {
		return nil, err
	}

	var pkgs []HomebrewPackage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Each cask dir contains version subdirectories
		versionDirs, err := afs.ReadDir(caskroomPath + "/" + name)
		if err != nil {
			continue
		}
		for _, vDir := range versionDirs {
			if !vDir.IsDir() {
				continue
			}
			version := vDir.Name()

			pkgs = append(pkgs, HomebrewPackage{
				Name:               name,
				Version:            version,
				Purl:               newHomebrewPurl(name, version, "homebrew/cask"),
				Type:               "cask",
				Prefix:             prefix,
				Path:               caskroomPath + "/" + name + "/" + version,
				InstalledOnRequest: true, // Casks are always explicit installs
			})
		}
	}

	return pkgs, nil
}

// brewInfoJSON represents the top-level structure of `brew info --json=v2` output.
type brewInfoJSON struct {
	Formulae []brewFormula `json:"formulae"`
	Casks    []brewCask    `json:"casks"`
}

type brewFormula struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Tap      string `json:"tap"`
	Desc     string `json:"desc"`
	Homepage string `json:"homepage"`
	Revision int    `json:"revision"`
	Versions struct {
		Stable string `json:"stable"`
	} `json:"versions"`
	Installed []brewInstalled `json:"installed"`
	LinkedKeg string          `json:"linked_keg"`
	Pinned    bool            `json:"pinned"`
	Outdated  bool            `json:"outdated"`
}

type brewInstalled struct {
	Version            string `json:"version"`
	InstalledOnRequest bool   `json:"installed_on_request"`
	// Homebrew 4 no longer writes installed_as_dependency; see
	// installedAsDependency.
	InstalledAsDependency *bool `json:"installed_as_dependency"`
}

type brewCask struct {
	Token       string   `json:"token"`
	FullToken   string   `json:"full_token"`
	Tap         string   `json:"tap"`
	Name        []string `json:"name"`
	Desc        string   `json:"desc"`
	Homepage    string   `json:"homepage"`
	Version     string   `json:"version"`
	AutoUpdates bool     `json:"auto_updates"`
	Installed   string   `json:"installed"`
	Outdated    bool     `json:"outdated"`
}

// installReceipt represents the INSTALL_RECEIPT.json file found in Cellar directories.
type installReceipt struct {
	InstalledOnRequest bool `json:"installed_on_request"`
	// nil when the receipt has no installed_as_dependency key, which Homebrew
	// 4 no longer writes; see installedAsDependency.
	InstalledAsDependency *bool `json:"installed_as_dependency"`
	Source                struct {
		Tap string `json:"tap"`
	} `json:"source"`
}

// ParseHomebrewInfo parses `brew info --json=v2 --installed` output.
func ParseHomebrewInfo(data []byte, prefix string) ([]HomebrewPackage, error) {
	var info brewInfoJSON
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	var pkgs []HomebrewPackage

	// Parse formulae — iterate all installed versions (Homebrew can have multiple)
	for _, f := range info.Formulae {
		latestVersion := f.Versions.Stable
		if f.Revision > 0 {
			latestVersion = fmt.Sprintf("%s_%d", latestVersion, f.Revision)
		}
		for _, inst := range f.Installed {
			pkgs = append(pkgs, HomebrewPackage{
				Name:                  f.Name,
				Version:               inst.Version,
				LatestVersion:         latestVersion,
				Purl:                  newHomebrewPurl(f.Name, inst.Version, f.Tap),
				Description:           f.Desc,
				Homepage:              f.Homepage,
				Path:                  prefix + "/Cellar/" + f.Name + "/" + inst.Version,
				Type:                  "formula",
				InstalledOnRequest:    inst.InstalledOnRequest,
				InstalledAsDependency: installedAsDependency(inst.InstalledAsDependency, inst.InstalledOnRequest),
				Outdated:              f.Outdated,
				Pinned:                f.Pinned,
				Tap:                   f.Tap,
				Prefix:                prefix,
			})
		}
	}

	// Parse casks
	for _, c := range info.Casks {
		if c.Installed == "" {
			continue
		}

		appName := ""
		if len(c.Name) > 0 {
			appName = c.Name[0]
		}

		pkgs = append(pkgs, HomebrewPackage{
			Name:               c.Token,
			Version:            c.Installed,
			LatestVersion:      c.Version,
			Purl:               newHomebrewPurl(c.Token, c.Installed, c.Tap),
			Description:        c.Desc,
			Homepage:           c.Homepage,
			Type:               "cask",
			AppName:            appName,
			AutoUpdates:        c.AutoUpdates,
			InstalledOnRequest: true, // Casks are always explicit installs
			Outdated:           c.Outdated,
			Tap:                c.Tap,
			Prefix:             prefix,
		})
	}

	return pkgs, nil
}

func enrichFromReceipt(pkg *HomebrewPackage, data []byte) {
	var receipt installReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return
	}
	pkg.InstalledOnRequest = receipt.InstalledOnRequest
	pkg.InstalledAsDependency = installedAsDependency(receipt.InstalledAsDependency, receipt.InstalledOnRequest)
	if receipt.Source.Tap != "" {
		pkg.Tap = receipt.Source.Tap
	}
}

// installedAsDependency reads installed_as_dependency where brew still
// reports it. Homebrew 4 dropped the key from both `brew info` and the
// install receipt and keeps only installed_on_request, so a keg brew did not
// install on request was installed as a dependency.
func installedAsDependency(reported *bool, onRequest bool) bool {
	if reported != nil {
		return *reported
	}
	return !onRequest
}

func deriveBrewPrefix(brewPath string) string {
	// /opt/homebrew/bin/brew -> /opt/homebrew
	// /usr/local/bin/brew -> /usr/local
	if idx := strings.LastIndex(brewPath, "/bin/brew"); idx != -1 {
		return brewPath[:idx]
	}
	return "/opt/homebrew" // default
}
