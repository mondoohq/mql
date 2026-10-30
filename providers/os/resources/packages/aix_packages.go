// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	cpe2 "go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/purl"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	AixPkgFormat = "bff"
)

// aixRpmDbPaths hold the AIX Toolbox rpm database. /var/lib/rpm is a link
// to /usr/opt/freeware/packages on AIX 7.3.
var aixRpmDbPaths = []string{"/opt/freeware/packages", "/var/lib/rpm"}

// parseAixPackages parses `lslpp -cl`. lslpp prints one row per fileset
// part, and a fileset with a root part (bos.rte, most of bos.*) appears once
// under /usr/lib/objrepos and again under /etc/objrepos, so each fileset is
// kept once. The usr part comes first and carries the state, unless a later
// part reports one that needs attention (BROKEN, APPLYING): that state wins.
func parseAixPackages(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	pkgs := []Package{}
	seen := map[string]int{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Path:Fileset:Level:PTF Id:State:Type:Description:EFIX Locked
		record := strings.Split(line, ":")
		if len(record) < 8 {
			continue
		}
		// a colon in the description shifts EFIX Locked to the last field
		efix := record[len(record)-1]
		description := strings.Join(record[6:len(record)-1], ":")

		state := record[4]
		qualifiers := map[string]string{}
		if efix != "" {
			state = state + "|" + efix
			qualifiers["efix"] = "locked"
		}

		// A fileset's parts share its level and PTF Id (on AIX 7.3 TL4 all
		// 339 filesets listed twice agree on both), so name and level
		// identify it.
		key := record[1] + "@" + record[2]
		if i, ok := seen[key]; ok {
			if !aixHealthyState(record[4]) {
				pkgs[i].Status = state
			}
			continue
		}
		seen[key] = len(pkgs)

		cpes, _ := cpe2.NewPackage2Cpe(record[1], record[1], record[2], "", pf.Arch)
		pkgs = append(pkgs, Package{
			Name:        record[1],
			Version:     record[2],
			Description: strings.TrimSpace(description),
			Format:      AixPkgFormat,
			Arch:        pf.Arch,
			PUrl: purl.NewPackageURL(
				pf, purl.TypeGeneric, record[1], record[2], purl.WithNamespace(pf.Name), purl.WithQualifiers(qualifiers),
			).String(),
			CPEs:   cpes,
			Status: state,
		})
	}
	return pkgs, scanner.Err()
}

// aixHealthyState reports whether a fileset part is fully installed.
func aixHealthyState(state string) bool {
	return state == "COMMITTED" || state == "APPLIED"
}

type AixPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (a *AixPkgManager) Name() string {
	return "AIX Package Manager"
}

func (a *AixPkgManager) Format() string {
	return AixPkgFormat
}

func (a *AixPkgManager) List() ([]Package, error) {
	cmd, err := a.conn.RunCommand("lslpp -cl")
	if err != nil {
		return nil, fmt.Errorf("could not read aix package list: %w", err)
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("lslpp exited with %d", cmd.ExitStatus)
	}

	return parseAixPackages(a.platform, cmd.Stdout)
}

func (a *AixPkgManager) Available() (map[string]PackageUpdate, error) {
	return map[string]PackageUpdate{}, nil
}

func (a *AixPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// not yet implemented
	return nil, nil
}
