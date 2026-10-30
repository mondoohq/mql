// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	OpenbsdPkgFormat = "openbsd"
)

// ParseOpenbsdPackages parses the output of 'pkg_info -a' on OpenBSD.
// Each line has the format: name-version  description
func ParseOpenbsdPackages(r io.Reader) ([]Package, error) {
	pkgs := []Package{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		pkg, err := parseOpenbsdPackageLine(line)
		if err != nil {
			log.Debug().Err(err).Msg("skipping invalid openbsd package line")
			continue
		}
		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// parseOpenbsdPackageLine parses a single line from pkg_info output.
// Format: "name-version  description text"
// The name-version field never contains spaces, so we split on the first space.
func parseOpenbsdPackageLine(line string) (Package, error) {
	idx := strings.IndexByte(line, ' ')
	if idx == -1 {
		return Package{}, fmt.Errorf("could not parse package line: %s", line)
	}

	nameVersion := line[:idx]
	description := strings.TrimSpace(line[idx:])

	// Split name and version using the same regex as NetBSD.
	// Package names can contain hyphens; the version starts with a digit.
	matches := netbsdPkgNameRegex.FindStringSubmatch(nameVersion)
	if len(matches) != 3 {
		return Package{}, fmt.Errorf("could not parse package name and version from: %s", nameVersion)
	}

	return Package{
		Name:        matches[1],
		Version:     matches[2],
		Description: description,
		Format:      OpenbsdPkgFormat,
	}, nil
}

type OpenBSDPkgManager struct {
	conn shared.Connection
}

func (o *OpenBSDPkgManager) Name() string {
	return "OpenBSD Package Manager"
}

func (o *OpenBSDPkgManager) List() ([]Package, error) {
	cmd, err := o.conn.RunCommand("pkg_info -a")
	if err != nil {
		return nil, fmt.Errorf("could not read openbsd package list")
	}

	return ParseOpenbsdPackages(cmd.Stdout)
}

func (o *OpenBSDPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (o *OpenBSDPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}
