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
	OpkgPkgFormat = "opkg"
)

var OPKG_LIST_PACKAGE_REGEX = regexp.MustCompile(`^([\w\d\-]+)\s-\s([\w\d\-\.]+)$`)

// ParseOpkgListPackagesCommand parses the output of `opkg list-installed`
func ParseOpkgListPackagesCommand(input io.Reader) []Package {
	pkgs := []Package{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		m := OPKG_LIST_PACKAGE_REGEX.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, Package{
				Name:    m[1],
				Version: m[2],
				Format:  OpkgPkgFormat,
			})
		}
	}
	return pkgs
}

var (
	OPKG_REGEX        = regexp.MustCompile(`^(.+):\s(.+)$`)
	OPKG_ORIGIN_REGEX = regexp.MustCompile(`^\s*([^\(]*)(?:\((.*)\))?\s*$`)
)

// ParseOpkgPackages parses the opkg database content located in:
// `/var/lib/opkg/status` or `/usr/lib/opkg/status`
func ParseOpkgPackages(input io.Reader) ([]Package, error) {
	const STATE_RESET = 0
	const STATE_DESC = 1
	pkgs := []Package{}

	add := func(pkg Package) {
		// do sanitization checks to ensure we have minimal information
		if pkg.Name != "" && pkg.Version != "" {
			// opkg records a hold in the flag field of the status triple,
			// where dpkg carried it historically.
			pkg.Pinned = isHeldStatus(pkg.Status)
			pkgs = append(pkgs, pkg)
		} else {
			log.Debug().Msg("ignored opkg packages since information is missing")
		}
	}

	scanner := bufio.NewScanner(input)
	pkg := Package{Format: OpkgPkgFormat}
	state := STATE_RESET
	var key string
	for scanner.Scan() {
		line := scanner.Text()

		// reset package definition once we reach a newline
		if len(line) == 0 {
			add(pkg)
			pkg = Package{Format: OpkgPkgFormat}
		}

		m := OPKG_REGEX.FindStringSubmatch(line)
		key = ""
		if m != nil {
			key = m[1]
			state = STATE_RESET
		}
		switch {
		case key == "Package":
			pkg.Name = strings.TrimSpace(m[2])
		case key == "Version":
			pkg.Version = strings.TrimSpace(m[2])
		case key == "Architecture":
			pkg.Arch = strings.TrimSpace(m[2])
		case key == "Status":
			pkg.Status = strings.TrimSpace(m[2])
		case key == "Source":
			o := OPKG_ORIGIN_REGEX.FindStringSubmatch(m[2])
			if len(o) >= 1 {
				pkg.Origin = strings.TrimSpace(o[1])
			} else {
				log.Error().Str("origin", m[2]).Msg("cannot parse opkg origin")
			}
		// description supports multi-line statements, start desc
		case key == "Description":
			pkg.Description = strings.TrimSpace(m[2])
			state = STATE_DESC
		// next desc line, append to previous one
		case state == STATE_DESC:
			pkg.Description += "\n" + strings.TrimSpace(line)
		}
	}

	// if the last line is not an empty line we have things in flight, lets check it
	add(pkg)

	return pkgs, nil
}

type OpkgPkgManager struct {
	conn shared.Connection
}

func (opkg *OpkgPkgManager) Name() string {
	return "Opkg Package Manager"
}

func (opkg *OpkgPkgManager) Format() string {
	return OpkgPkgFormat
}

func (opkg *OpkgPkgManager) List() ([]Package, error) {
	// if we can run commands, we can use `opkg list-installed`
	if opkg.conn.Capabilities().Has(shared.Capability_RunCommand) {
		cmd, err := opkg.conn.RunCommand("opkg list-installed")
		if err != nil {
			return nil, fmt.Errorf("could not read opkg package list")
		}
		return ParseOpkgListPackagesCommand(cmd.Stdout), nil
	}

	// otherwise let's try to read the package list from file
	return opkg.ListFromFile()
}

func (opkg *OpkgPkgManager) ListFromFile() ([]Package, error) {
	fs := opkg.conn.FileSystem()
	opkgStatusFiles := []string{
		"/usr/lib/opkg/status",
		"/var/lib/opkg/status",
	}

	var opkgStatusFile string
	for _, f := range opkgStatusFiles {
		_, err := fs.Stat(f)
		if err == nil {
			opkgStatusFile = f
			break
		}
	}

	if opkgStatusFile == "" {
		return nil, fmt.Errorf("could not find opkg package list")
	}

	fi, err := fs.Open(opkgStatusFile)
	if err != nil {
		return nil, fmt.Errorf("could not read opkg package list")
	}
	defer fi.Close()

	list, err := ParseOpkgPackages(fi)
	if err != nil {
		return nil, fmt.Errorf("could not parse opkg package list")
	}
	return list, nil
}

func (opkg *OpkgPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (opkg *OpkgPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}
