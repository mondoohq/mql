// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package python

import (
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/sbom"
)

type PackageDetails struct {
	Name           string
	File           string
	License        string
	Author         string
	AuthorEmail    string
	Summary        string
	Version        string
	RequiresPython string
	ProjectUrls    map[string]string
	Dependencies   []string
	IsLeaf         bool
	Purl           string
	Cpes           []string
}

// nameSeparators matches any run of the characters PEP 503 treats as
// equivalent separators in a project name.
var nameSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizeName returns the PEP 503 normalized form of a project name: any run
// of "-", "_" or "." collapses to a single "-", and the result is lowercased.
// "Zope.Interface", "zope_interface" and "zope--interface" all normalize to
// "zope-interface".
//
// Use this whenever a name is compared or used as a key. Names are recorded
// inconsistently across metadata, manifests and lock files, so comparing the raw
// strings both misses matches and produces package URLs that do not resolve
// against vulnerability data.
//
// See https://packaging.python.org/en/latest/specifications/name-normalization/
func NormalizeName(name string) string {
	return strings.ToLower(nameSeparators.ReplaceAllString(name, "-"))
}

func NewPackageUrl(name string, version string) string {
	// ensure the name is according to the PURL spec
	// see https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/pypi-definition.md
	name = NormalizeName(name)

	return packageurl.NewPackageURL(
		packageurl.TypePyPi,
		"",
		name,
		version,
		nil,
		"").String()
}

func NewCpes(name string, version string) []string {
	cpes := []string{}
	// what we see in the cpe dictionary is that the vendor is the name of the package itself + "_project"
	vendor := name + "_project"
	cpeEntries, err := cpe.NewPackage2Cpe(vendor, name, version, "", "")
	if err != nil {
		log.Warn().Str("name", name).Str("version", version).Err(err).Msg("failed to create cpe for Python package")
	} else if len(cpeEntries) > 0 {
		cpes = append(cpes, cpeEntries...)
	}
	return cpes
}

// NewEvidenceList converts a list of file paths to evidence entries.
func NewEvidenceList(evidence []string) []*sbom.Evidence {
	evidenceList := make([]*sbom.Evidence, len(evidence))
	for i, e := range evidence {
		evidenceList[i] = NewEvidence(e)
	}
	return evidenceList
}

// NewEvidence creates a file evidence entry.
func NewEvidence(filepath string) *sbom.Evidence {
	return &sbom.Evidence{
		Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
		Value: filepath,
	}
}
