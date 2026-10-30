// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	NetbsdPkgFormat = "netbsd"
)

var netbsdPkgNameRegex = regexp.MustCompile(`^(.+)-([0-9].*)$`)

type NetBSDPackage struct {
	Name        string
	Version     string
	Comment     string
	Description string
	Categories  string
	PkgPath     string
	Arch        string
	SizePkg     string
}

// ParseNetBSDPackages parses the output of 'pkg_info -X -a'
// The format is key=value pairs separated by empty lines for each package
func ParseNetBSDPackages(r io.Reader) ([]Package, error) {
	pkgs := []Package{}
	scanner := bufio.NewScanner(r)

	currentPkg := make(map[string]string)
	var currentKey string
	var isMultiLine bool

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line indicates end of package entry
		if line == "" {
			if len(currentPkg) > 0 {
				pkg, err := convertNetBSDPackage(currentPkg)
				if err != nil {
					log.Debug().Err(err).Msg("skipping invalid netbsd package entry")
				} else {
					pkgs = append(pkgs, pkg)
				}
				currentPkg = make(map[string]string)
				currentKey = ""
				isMultiLine = false
			}
			continue
		}

		// Check if this is a continuation line (starts with key=)
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]

				// Check if this is a continuation of a multi-line field
				if key == currentKey {
					// Multi-line continuation
					currentPkg[key] = currentPkg[key] + "\n" + value
					isMultiLine = true
				} else {
					// New field
					currentPkg[key] = value
					currentKey = key
					isMultiLine = false
				}
			}
		} else if isMultiLine && currentKey != "" {
			// Continuation line without key= prefix
			currentPkg[currentKey] = currentPkg[currentKey] + "\n" + line
		}
	}

	// Handle last package if file doesn't end with empty line
	if len(currentPkg) > 0 {
		pkg, err := convertNetBSDPackage(currentPkg)
		if err != nil {
			log.Debug().Err(err).Msg("skipping invalid netbsd package entry")
		} else {
			pkgs = append(pkgs, pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// convertNetBSDPackage converts a map of package fields to a Package struct
func convertNetBSDPackage(fields map[string]string) (Package, error) {
	pkgName := fields["PKGNAME"]
	if pkgName == "" {
		return Package{}, fmt.Errorf("missing PKGNAME field")
	}

	// Split package name and version using regex
	// Package names can contain hyphens, so we need to find the last hyphen before the version
	matches := netbsdPkgNameRegex.FindStringSubmatch(pkgName)
	if len(matches) != 3 {
		return Package{}, fmt.Errorf("could not parse package name and version from: %s", pkgName)
	}

	name := matches[1]
	version := matches[2]

	// Get description (prefer COMMENT for consistency with other platforms)
	description := fields["COMMENT"]
	if description == "" {
		// Fallback to DESCRIPTION if COMMENT is missing
		description = fields["DESCRIPTION"]
	}

	pkg := Package{
		Name:        name,
		Version:     version,
		Description: description,
		Arch:        fields["MACHINE_ARCH"],
		Origin:      fields["PKGPATH"],
		Format:      NetbsdPkgFormat,
	}

	return pkg, nil
}

type NetBSDPkgManager struct {
	conn shared.Connection
}

func (n *NetBSDPkgManager) Name() string {
	return "NetBSD Package Manager"
}

func (n *NetBSDPkgManager) Format() string {
	return NetbsdPkgFormat
}

func (n *NetBSDPkgManager) List() ([]Package, error) {
	cmd, err := n.conn.RunCommand("/usr/sbin/pkg_info -X -a")
	if err != nil {
		return nil, fmt.Errorf("could not read netbsd package list")
	}

	return ParseNetBSDPackages(cmd.Stdout)
}

func (n *NetBSDPkgManager) Available() (map[string]PackageUpdate, error) {
	// Not yet implemented
	return map[string]PackageUpdate{}, nil
}

func (n *NetBSDPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// Not yet implemented
	// Future: could use pkg_info -L <pkgname>
	return nil, nil
}
