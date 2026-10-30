// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"github.com/package-url/packageurl-go"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

// Collapse merges the inventory read from a Terraform workspace into one list.
//
// The same dependency is stated in more than one place, at different
// fidelities. required_providers names a provider and a version *constraint*;
// the lock file names it again at the version init resolved. A module call
// names a registry module and its version; the module manifest names it again
// after installation. Reported as written, a workspace lists every provider
// twice — once with no version, which nothing can match, and once with one.
//
// Collapse keeps the version-bearing record and drops the version-less one for
// the same coordinate. A version-less record with no version-bearing twin is
// kept: it is the only statement of that dependency, which is exactly the case
// in a repository that does not commit its lock file.
func Collapse(packages []*languages.Package) []*languages.Package {
	versioned := make(map[string]bool, len(packages))
	for _, p := range packages {
		if p.Version != "" {
			versioned[coordinate(p.Purl)] = true
		}
	}

	seen := make(map[string]*languages.Package, len(packages))
	out := packages[:0]
	for _, p := range packages {
		if p.Version == "" && versioned[coordinate(p.Purl)] {
			continue
		}
		// The same dependency legitimately appears more than once: declared in
		// the configuration and installed in the manifest, or pinned by several
		// workspaces in one repository. That is one component with several
		// pieces of evidence, not several components — so the duplicate is
		// folded in and the file it came from is kept.
		if first, ok := seen[p.Purl]; ok {
			first.EvidenceList = mergeEvidence(first.EvidenceList, p.EvidenceList)
			continue
		}
		seen[p.Purl] = p
		out = append(out, p)
	}
	return out
}

// mergeEvidence appends evidence not already recorded, preserving order.
func mergeEvidence(into, from []*sbom.Evidence) []*sbom.Evidence {
	have := make(map[string]bool, len(into))
	for _, e := range into {
		have[e.Type.String()+"\x00"+e.Value] = true
	}
	for _, e := range from {
		key := e.Type.String() + "\x00" + e.Value
		if have[key] {
			continue
		}
		have[key] = true
		into = append(into, e)
	}
	return into
}

// coordinate is a purl with its version removed: the identity of the artifact
// rather than of the release.
func coordinate(purl string) string {
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return purl
	}
	parsed.Version = ""
	return parsed.ToString()
}
