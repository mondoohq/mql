// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	ChocolateyPkgFormat = "chocolatey"
	// defaultChocoPath is the default Chocolatey installation directory on Windows.
	// Uses forward slashes so path.Join works correctly when mql runs on Linux
	// scanning a remote Windows system via SSH/WinRM.
	defaultChocoPath = "C:/ProgramData/chocolatey"
)

// ChocolateyPkgManager discovers Chocolatey packages on Windows.
type ChocolateyPkgManager struct {
	Conn shared.Connection
}

// ChocolateyPackage represents a Chocolatey package with extended metadata.
type ChocolateyPackage struct {
	Name         string
	Version      string
	Purl         string
	Summary      string
	Description  string
	Author       string
	License      string
	LicenseUrl   string
	Path         string
	Pinned       bool
	Dependencies []string
	Tags         []string
	ProjectUrl   string
}

func (c *ChocolateyPkgManager) Name() string {
	return "Chocolatey Package Manager"
}

func (c *ChocolateyPkgManager) Format() string {
	return ChocolateyPkgFormat
}

func (c *ChocolateyPkgManager) List() ([]Package, error) {
	pkgs, err := c.ListExtended()
	if err != nil {
		return nil, err
	}

	result := make([]Package, len(pkgs))
	for i, p := range pkgs {
		result[i] = Package{
			Name:        p.Name,
			Version:     p.Version,
			Format:      ChocolateyPkgFormat,
			Description: p.Summary,
		}
	}
	return result, nil
}

// ListExtended returns Chocolatey packages with full metadata.
func (c *ChocolateyPkgManager) ListExtended() ([]ChocolateyPackage, error) {
	afs := &afero.Afero{Fs: c.Conn.FileSystem()}

	chocoPath := c.discoverChocoPath(afs)
	if chocoPath == "" {
		return []ChocolateyPackage{}, nil
	}

	libPath := path.Join(chocoPath, "lib")
	exists, err := afs.DirExists(libPath)
	if err != nil || !exists {
		return []ChocolateyPackage{}, nil
	}

	return c.parseFromLib(afs, libPath)
}

func (c *ChocolateyPkgManager) Available() (map[string]PackageUpdate, error) {
	return nil, nil
}

func (c *ChocolateyPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}

// discoverChocoPath finds the Chocolatey installation directory.
// Checks the ChocolateyInstall env var (via command execution) first,
// then falls back to the default path.
func (c *ChocolateyPkgManager) discoverChocoPath(afs *afero.Afero) string {
	// Try to read ChocolateyInstall env var from the target system.
	// Use PowerShell syntax ($env:) which works on modern Windows + WinRM.
	if c.Conn.Capabilities().Has(shared.Capability_RunCommand) {
		cmd, err := c.Conn.RunCommand(`powershell -NoProfile -Command "$env:ChocolateyInstall"`)
		if err == nil && cmd.ExitStatus == 0 && cmd.Stdout != nil {
			data, _ := io.ReadAll(cmd.Stdout)
			envPath := strings.TrimSpace(string(data))
			if envPath != "" {
				if exists, _ := afs.DirExists(envPath); exists {
					return envPath
				}
			}
		}
	}

	// Fall back to default path
	if exists, _ := afs.DirExists(defaultChocoPath); exists {
		return defaultChocoPath
	}

	return ""
}

// parseFromLib enumerates package directories and parses .nuspec files.
func (c *ChocolateyPkgManager) parseFromLib(afs *afero.Afero, libPath string) ([]ChocolateyPackage, error) {
	entries, err := afs.ReadDir(libPath)
	if err != nil {
		return nil, err
	}

	var pkgs []ChocolateyPackage
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgDir := path.Join(libPath, entry.Name())

		// Glob for *.nuspec instead of assuming the filename matches the directory name,
		// since Chocolatey may use versioned directory names (e.g., git.2.45.2/git.nuspec).
		matches, _ := afero.Glob(afs, path.Join(pkgDir, "*.nuspec"))
		if len(matches) == 0 {
			continue
		}
		nuspecPath := matches[0]

		pkg, err := parseNuspec(afs, nuspecPath)
		if err != nil {
			log.Debug().Err(err).Str("path", nuspecPath).Msg("mql[chocolatey]> could not parse nuspec")
			continue
		}

		pkg.Path = pkgDir
		pkg.Purl = newChocolateyPurl(pkg.Name, pkg.Version)

		// Check for pin
		pinPath := path.Join(pkgDir, ".pin")
		if exists, _ := afs.Exists(pinPath); exists {
			pkg.Pinned = true
		}

		pkgs = append(pkgs, *pkg)
	}

	return pkgs, nil
}

// nuspecPackage represents the XML structure of a .nuspec file.
// Go's encoding/xml ignores namespaces when struct tags omit them,
// so this matches both the 2010 and 2015 NuGet schema URIs.
type nuspecPackage struct {
	XMLName  xml.Name       `xml:"package"`
	Metadata nuspecMetadata `xml:"metadata"`
}

type nuspecMetadata struct {
	ID           string             `xml:"id"`
	Version      string             `xml:"version"`
	Title        string             `xml:"title"`
	Authors      string             `xml:"authors"`
	Summary      string             `xml:"summary"`
	Description  string             `xml:"description"`
	Tags         string             `xml:"tags"`
	LicenseUrl   string             `xml:"licenseUrl"`
	ProjectUrl   string             `xml:"projectUrl"`
	Dependencies nuspecDependencies `xml:"dependencies"`
}

type nuspecDependencies struct {
	// Flat dependencies (directly under <dependencies>)
	Dependency []nuspecDependency `xml:"dependency"`
	// Grouped dependencies (under <dependencies><group>)
	Group []nuspecGroup `xml:"group"`
}

type nuspecGroup struct {
	TargetFramework string             `xml:"targetFramework,attr"`
	Dependency      []nuspecDependency `xml:"dependency"`
}

type nuspecDependency struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// parseNuspec reads and parses a single .nuspec XML file.
func parseNuspec(afs *afero.Afero, path string) (*ChocolateyPackage, error) {
	f, err := afs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var nuspec nuspecPackage
	if err := xml.Unmarshal(data, &nuspec); err != nil {
		return nil, err
	}

	m := nuspec.Metadata

	// Extract dependency IDs from both flat and grouped entries.
	// Nuspec files may use <dependency> directly or wrap them in <group targetFramework="...">.
	seen := make(map[string]bool)
	var deps []string
	for _, d := range m.Dependencies.Dependency {
		if d.ID != "" && !seen[d.ID] {
			seen[d.ID] = true
			deps = append(deps, d.ID)
		}
	}
	for _, g := range m.Dependencies.Group {
		for _, d := range g.Dependency {
			if d.ID != "" && !seen[d.ID] {
				seen[d.ID] = true
				deps = append(deps, d.ID)
			}
		}
	}

	// Split tags on whitespace
	var tags []string
	if m.Tags != "" {
		tags = strings.Fields(m.Tags)
	}

	return &ChocolateyPackage{
		Name:         m.ID,
		Version:      m.Version,
		Summary:      m.Summary,
		Description:  m.Description,
		Author:       m.Authors,
		License:      "", // License text not in nuspec; only URL
		LicenseUrl:   m.LicenseUrl,
		Dependencies: deps,
		Tags:         tags,
		ProjectUrl:   m.ProjectUrl,
	}, nil
}

// newChocolateyPurl creates a PURL for a Chocolatey package.
// Uses pkg:chocolatey/<name>@<version>.
func newChocolateyPurl(name, version string) string {
	return packageurl.NewPackageURL(
		string(purl.TypeChocolatey),
		"",
		name,
		version,
		nil,
		"").String()
}
