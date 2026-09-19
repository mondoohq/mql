// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
)

func ParseRpmUpdates(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Bytes()

		// we try to parse the content into the struct
		var pkg PackageUpdate
		err := json.Unmarshal(line, &pkg)
		if err != nil {
			// there are string lines that cannot be parsed
			continue
		}
		pkgs[pkg.Name] = pkg
	}
	return pkgs, nil
}

type zypperUpdate struct {
	Name        string `xml:"name,attr"`
	Kind        string `xml:"kind,attr"`
	Arch        string `xml:"arch,attr"`
	Edition     string `xml:"edition,attr"`
	OldEdition  string `xml:"edition-old,attr"`
	Status      string `xml:"status,attr"`
	Category    string `xml:"category,attr"`
	Severity    string `xml:"severity,attr"`
	PkgManager  string `xml:"pkgmanager,attr"`
	Restart     string `xml:"restart,attr"`
	Interactive string `xml:"interactive,attr"`

	Summary     string `xml:"summary"`
	Description string `xml:"description"`
}

type zypper struct {
	XMLNode xml.Name       `xml:"stream"`
	Updates []zypperUpdate `xml:"update-status>update-list>update"`
	Blocked []zypperUpdate `xml:"update-status>blocked-update-list>update"`
}

// for Suse, updates are package updates
// parses the output of `zypper -n --xmlout list-updates`
func ParseZypperUpdates(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	zypper, err := ParseZypper(input)
	if err != nil {
		return nil, err
	}

	for _, u := range zypper.Updates {
		// filter for kind package
		if u.Kind != "package" {
			continue
		}
		pkgs[u.Name] = PackageUpdate{
			Name:      u.Name,
			Version:   u.OldEdition,
			Arch:      u.Arch,
			Available: u.Edition,
		}
	}
	return pkgs, nil
}

func ParseZypper(input io.Reader) (*zypper, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	var patches zypper
	err = xml.Unmarshal(content, &patches)
	if err != nil {
		return nil, err
	}
	return &patches, nil
}

// rpmCheckUpdateLine matches one package line of `dnf check-update`:
//
//	NetworkManager.x86_64      1:1.54.3-5.el9_8      rhel-9-baseos-rhui-rpms
//
// The first field is "<name>.<arch>", the second the available
// "[epoch:]version-release" and the third the repository.
//
// The leading anchor is deliberate. dnf ends its output with an "Obsoleting
// Packages" section whose second line of each pair is indented and names the
// *installed* package being obsoleted, with the repo @System:
//
//	grub2-tools-minimal.x86_64   1:2.06-126.el9_8    rhel-9-baseos-rhui-rpms
//	    grub2-tools.x86_64       1:2.06-105.el9_6.2  @System
//
// Reading that indented line as an update would report grub2-tools as having
// an older version available than the one installed. Requiring the line to
// start at column zero drops it; the @System repo check below is a second
// guard for the same thing.
var rpmCheckUpdateLine = regexp.MustCompile(`^(\S+)\.(\S+)\s+(\S+)\s+(\S+)\s*$`)

// ParseRpmCheckUpdate parses the output of `dnf check-update` / `yum
// check-update` into the available updates, keyed by package name.
func ParseRpmCheckUpdate(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, rpmMaxLineSize)
	for scanner.Scan() {
		line := scanner.Text()
		m := rpmCheckUpdateLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// the installed side of an obsoletes pair, not an update
		if m[4] == "@System" {
			continue
		}
		name, arch, available, repo := m[1], m[2], m[3], m[4]
		pkgs[name] = PackageUpdate{
			Name:      name,
			Arch:      arch,
			Available: available,
			Repo:      repo,
		}
	}
	if err := scanner.Err(); err != nil {
		// a truncated read hides pending updates, which reads as "up to date"
		return nil, fmt.Errorf("could not read the rpm update list to its end: %w", err)
	}
	return pkgs, nil
}
