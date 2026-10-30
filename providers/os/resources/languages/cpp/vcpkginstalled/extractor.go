// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package vcpkginstalled parses the status database vcpkg writes into its
// install tree (`vcpkg_installed/vcpkg/status`).
//
// This is the only place a vcpkg dependency's RESOLVED version exists offline.
// A `vcpkg.json` names ports and defers their versions to the registry's
// `builtin-baseline` — a git commit of the registry — so a manifest-only scan
// produces version-less components, and a component with no version matches no
// advisory. The install tree is the toolchain's own record of what it actually
// put on disk, which is the same claim that makes a jar's META-INF worth
// reading when no build file is present.
//
// It exists only where `vcpkg install` has run, so it fills blanks rather than
// replacing the manifest: a scan without one still reports the manifest's
// dependencies, without versions.
package vcpkginstalled

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/cpp"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*statusDB)(nil)
)

// Extractor parses vcpkg_installed/vcpkg/status.
type Extractor struct{}

func (e *Extractor) Name() string { return "vcpkg-installed" }

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	db := &statusDB{}
	if filename != "" {
		db.evidence = append(db.evidence, filename)
	}
	return db, db.parse(r)
}

// statusDB holds the installed entries read from the status file.
type statusDB struct {
	entries  []statusEntry
	evidence []string
}

// statusEntry is one installed port.
type statusEntry struct {
	name    string
	version string
	// feature is set on a stanza describing a port's FEATURE rather than the
	// port itself. A feature stanza carries no version of its own and would
	// otherwise be reported as a second, version-less copy of the port.
	feature string
	// triplet is the target the port was built for (e.g. "x64-linux"). Recorded
	// as a purl qualifier: the same project can install one port for several
	// triplets, and they are genuinely different builds.
	triplet string
	// installed distinguishes a port that is present from one the database
	// still lists after removal ("purge ok not-installed").
	installed bool
}

// maxLines bounds the read. The status file is machine-written, but it is still
// input from the scanned tree.
//
// Lines, not stanzas. A stanza counter only advances on a blank-line separator,
// so a file containing no blank line at all — which is exactly the shape a
// hostile tree would use — never advanced it and was read to the end however
// large it was. A line bound implies a stanza bound, since a stanza is at least
// one line.
const maxLines = 200000

// parse reads the status file's Debian-control-style stanzas: `Key: value`
// lines, one stanza per package, separated by a blank line.
func (db *statusDB) parse(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	// A status file can be large; the default 64KiB token limit is per LINE,
	// which is ample here, but the Buffer call makes the bound explicit.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	cur := statusEntry{}
	flush := func() {
		if cur.name != "" && cur.installed && cur.feature == "" {
			db.entries = append(db.entries, cur)
		}
		cur = statusEntry{}
	}

	for n := 0; scanner.Scan() && n < maxLines; n++ {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			// A continuation line of a multi-line field (Description), which
			// carries nothing this reader wants.
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "package":
			cur.name = value
		case "version":
			cur.version = value
		case "feature":
			cur.feature = value
		case "architecture":
			cur.triplet = value
		case "status":
			// vcpkg writes Debian's three-word form, e.g. "install ok
			// installed". Only the last word says whether it is on disk.
			fields := strings.Fields(value)
			cur.installed = len(fields) > 0 && fields[len(fields)-1] == "installed"
		}
	}
	flush()
	return scanner.Err()
}

// Root returns nil — the status database records what was installed, not the
// identity of the project that asked for it.
func (db *statusDB) Root() *languages.Package { return nil }

// Direct returns nil — the status file lists a flat installed set with no
// record of which entries the project asked for and which came in as their
// dependencies. Reporting them all as direct would claim a distinction it does
// not make.
func (db *statusDB) Direct() languages.Packages { return nil }

// Transitive returns every installed port.
func (db *statusDB) Transitive() languages.Packages {
	var packages languages.Packages
	for _, e := range db.entries {
		qualifiers := map[string]string{}
		if e.triplet != "" {
			qualifiers["triplet"] = e.triplet
		}
		// vcpkg appends a port-revision to the version as "1.2.3#1". The
		// revision is vcpkg's own packaging iteration, not upstream's version,
		// so it is dropped: an advisory states the upstream version.
		version, _, _ := strings.Cut(e.version, "#")
		packages = append(packages, &languages.Package{
			Name:         e.name,
			Version:      version,
			Purl:         cpp.NewVcpkgPackageUrlWithQualifiers(e.name, version, qualifiers),
			EvidenceList: cpp.NewEvidenceList(db.evidence),
			Scope:        languages.PackageScopeProd,
		})
	}
	return packages
}
