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

// rpmCheckUpdateWrappedName matches a "<name>.<arch>" line that yum 3 (RHEL 7)
// printed on its own because it is wider than the first column. The version
// and repository follow on the next, indented line:
//
//	g03-a-very-long-package-name-that-exceeds-the-check-update-column-width.x86_64
//	                                        2.0-1        g03repo
//
// dnf 4 and dnf 5 widen the column instead and never wrap.
var rpmCheckUpdateWrappedName = regexp.MustCompile(`^(\S+)\.(\S+)\s*$`)

// rpmCheckUpdateContinuation matches the indented version and repository
// that finish a wrapped "<name>.<arch>" line.
var rpmCheckUpdateContinuation = regexp.MustCompile(`^\s+(\S+)\s+(\S+)\s*$`)

// ParseRpmCheckUpdate parses the output of `dnf check-update` / `yum
// check-update` into the available updates, keyed by "<name>.<arch>".
//
// The key carries the architecture because a multilib package is installed
// once per architecture (g03-multi.i686 and g03-multi.x86_64) and check-update
// lists an update for each. Keyed by name alone, the second line replaced the
// first and one of the two packages reported no update.
func ParseRpmCheckUpdate(input io.Reader) (map[string]PackageUpdate, error) {
	pkgs := map[string]PackageUpdate{}
	add := func(name, arch, available, repo string) {
		// the installed side of an obsoletes pair, not an update
		// (dnf prints @System, yum 3 prints installed; both are indented)
		if repo == "@System" || repo == "installed" {
			return
		}
		pkgs[name+"."+arch] = PackageUpdate{
			Name:      name,
			Arch:      arch,
			Available: available,
			Repo:      repo,
		}
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(nil, rpmMaxLineSize)
	// wrapped holds a "<name>.<arch>" line yum 3 printed alone, waiting for
	// the indented line with its version and repository.
	var wrapped []string
	for scanner.Scan() {
		line := scanner.Text()
		if wrapped != nil {
			if m := rpmCheckUpdateContinuation.FindStringSubmatch(line); m != nil {
				add(wrapped[1], wrapped[2], m[1], m[2])
				wrapped = nil
				continue
			}
			wrapped = nil
		}
		if m := rpmCheckUpdateLine.FindStringSubmatch(line); m != nil {
			add(m[1], m[2], m[3], m[4])
			continue
		}
		if m := rpmCheckUpdateWrappedName.FindStringSubmatch(line); m != nil {
			wrapped = m
		}
	}
	if err := scanner.Err(); err != nil {
		// a truncated read hides pending updates, which reads as "up to date"
		return nil, fmt.Errorf("could not read the rpm update list to its end: %w", err)
	}
	return pkgs, nil
}
