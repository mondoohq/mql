// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

const (
	FreebsdPkgFormat = "freebsd"

	// freebsdPkgQuery lists every installed package in one call: name,
	// version, comment, ABI, origin, install time (Unix seconds), license
	// logic (single, or, and) and the license list, tab separated. pkg
	// expands the \t escapes itself.
	freebsdPkgQuery = `pkg query -a '%n\t%v\t%c\t%q\t%o\t%t\t%l\t%L'`

	// freebsdPkgUpdatesQuery compares every installed package against the
	// remote catalogue and prints only the ones that differ from it.
	freebsdPkgUpdatesQuery = "pkg version -vRL="
)

// freebsdPkgUpdateRegex matches a `pkg version -v` line for a package the
// remote catalogue has a newer version of:
//
//	ca_root_nss-3.127                  <   needs updating (remote has 3.130)
//
// pkg does not allow a hyphen in a version, so the last hyphen of the first
// token separates the name from the version.
var freebsdPkgUpdateRegex = regexp.MustCompile(`^(\S+)-(\S+)\s+<\s+needs updating \(remote has ([^)\s]+)\)`)

func ParseFreeBSDPackages(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	pkgs := []Package{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 5 && len(parts) != 8 {
			log.Debug().Msgf("skipping invalid freebsd package line: %s", line)
			continue
		}

		pkg := Package{
			Name:        parts[0],
			Version:     parts[1],
			Description: parts[2],
			Arch:        parts[3],
			Origin:      parts[4],
			Format:      FreebsdPkgFormat,
			// pkg keeps the file list in its database, one query per package
			// away, so Files() reads it only when asked.
			FilesAvailable: PkgFilesAsync,
		}

		if len(parts) == 8 {
			pkg.InstallDate = parseFreeBSDInstallTime(parts[5])
			pkg.License = freebsdLicense(parts[6], parts[7])
		}

		// purl has no FreeBSD pkg type, so the generic type carries the name
		// and version, as it does for xbps and AIX.
		pkg.PUrl = purl.NewPackageURL(pf, purl.TypeGeneric, pkg.Name, pkg.Version,
			purl.WithArch(freebsdAbiArch(pkg.Arch)),
		).String()

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// parseFreeBSDInstallTime reads pkg's %t, the install time in Unix seconds. A
// package whose database row has no time reports 0, which is no answer rather
// than 1970.
func parseFreeBSDInstallTime(s string) time.Time {
	secs, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

// freebsdLicense combines pkg's %l (how several licenses combine: single, or,
// and) and %L (the licenses, comma separated) into one expression, so a
// dual-licensed package reads "ART10 OR GPLv1+" and not a list that loses
// whether one or all of them apply. The license names are the ones pkg
// records, which are not always SPDX identifiers.
func freebsdLicense(logic string, list string) string {
	var licenses []string
	for l := range strings.SplitSeq(list, ",") {
		if l = strings.TrimSpace(l); l != "" {
			licenses = append(licenses, l)
		}
	}
	switch len(licenses) {
	case 0:
		return ""
	case 1:
		return licenses[0]
	}

	op := ""
	switch logic {
	case "or":
		op = " OR "
	case "and":
		op = " AND "
	default:
		// A combination pkg did not say how to read: keep its own list rather
		// than guess.
		return strings.Join(licenses, ", ")
	}
	return strings.Join(licenses, op)
}

// freebsdAbiArch returns the architecture part of a pkg ABI string such as
// "FreeBSD:14:amd64". A package that runs on any architecture carries "*",
// which names no architecture, so it returns "".
func freebsdAbiArch(abi string) string {
	parts := strings.SplitN(abi, ":", 3)
	if len(parts) != 3 || parts[2] == "*" {
		return ""
	}
	return parts[2]
}

// ParseFreeBSDUpdates reads `pkg version -vRL=`. Only packages the remote
// catalogue has a newer version of are returned; a package the catalogue
// does not carry ("?") or that is newer than the catalogue (">") has no
// update. arches maps a package name to its installed ABI, which is the arch
// the package list reports and the key an update is matched on.
func ParseFreeBSDUpdates(r io.Reader, arches map[string]string) (map[string]PackageUpdate, error) {
	updates := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		m := freebsdPkgUpdateRegex.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		updates[m[1]] = PackageUpdate{
			Name:      m[1],
			Version:   m[2],
			Available: m[3],
			Arch:      arches[m[1]],
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the pkg update list to its end: %w", err)
	}
	return updates, nil
}

type FreeBSDPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform

	// arches is the installed ABI of every package List() saw, kept so
	// Available() can match updates to packages without listing them again.
	archesLock sync.Mutex
	arches     map[string]string
}

func (f *FreeBSDPkgManager) Name() string {
	return "FreeBSD Package Manager"
}

func (f *FreeBSDPkgManager) Format() string {
	return FreebsdPkgFormat
}

func (f *FreeBSDPkgManager) List() ([]Package, error) {
	cmd, err := f.conn.RunCommand(freebsdPkgQuery)
	if err != nil {
		return nil, fmt.Errorf("could not read freebsd package list")
	}

	pkgs, err := ParseFreeBSDPackages(f.platform, cmd.Stdout)
	if err != nil {
		return nil, err
	}

	arches := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		arches[p.Name] = p.Arch
	}
	f.archesLock.Lock()
	f.arches = arches
	f.archesLock.Unlock()

	return pkgs, nil
}

// Available asks pkg which installed packages the configured repositories
// have a newer version of. Like apt-get update before an apt upgrade dry run,
// pkg refreshes a stale repository catalogue first; without the privileges to
// do that it compares against the catalogue it already has.
func (f *FreeBSDPkgManager) Available() (map[string]PackageUpdate, error) {
	if !f.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return map[string]PackageUpdate{}, nil
	}

	f.archesLock.Lock()
	arches := f.arches
	f.archesLock.Unlock()
	if arches == nil {
		if _, err := f.List(); err != nil {
			return nil, err
		}
		f.archesLock.Lock()
		arches = f.arches
		f.archesLock.Unlock()
	}

	cmd, err := f.conn.RunCommand(freebsdPkgUpdatesQuery)
	if err != nil {
		return nil, fmt.Errorf("could not read the pkg update list: %w", err)
	}
	updates, err := ParseFreeBSDUpdates(cmd.Stdout, arches)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 && len(updates) == 0 {
		log.Debug().Int("exit", cmd.ExitStatus).
			Msg("mql[packages]> pkg version exited non-zero, reporting no available updates")
	}
	return updates, nil
}

// Files lists the files a package installed, as `pkg query %Fp` reports them.
func (f *FreeBSDPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	if name == "" || !f.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}
	cmd, err := f.conn.RunCommand("pkg query '%Fp' " + shellQuote(name))
	if err != nil {
		return nil, fmt.Errorf("could not read the file list of package %s: %w", name, err)
	}
	return ParseFreeBSDFileList(cmd.Stdout)
}

// ParseFreeBSDFileList reads `pkg query %Fp`, one absolute path per line.
func ParseFreeBSDFileList(r io.Reader) ([]FileRecord, error) {
	records := []FileRecord{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		p := scanner.Text()
		if p == "" {
			continue
		}
		records = append(records, FileRecord{Path: p})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the pkg file list to its end: %w", err)
	}
	return records, nil
}
