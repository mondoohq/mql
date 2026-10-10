// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package javascript

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/cpe"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/sbom"
)

// sriAlgToCycloneDX maps a Subresource-Integrity algorithm token (as it appears
// in npm/pnpm/yarn lockfiles' `integrity`) to the CycloneDX hash-algorithm spelling.
var sriAlgToCycloneDX = map[string]string{
	"sha512": "SHA-512",
	"sha384": "SHA-384",
	"sha256": "SHA-256",
	"sha1":   "SHA-1",
	"md5":    "MD5",
}

// NewHashes parses a JavaScript-ecosystem Subresource-Integrity string — one or
// more space-separated `<alg>-<base64>` entries, e.g. "sha512-vG6…" — into
// languages.PackageHash values with lower-case hex-encoded digests. Unknown
// algorithms and malformed entries are skipped; returns nil when nothing parses.
// Shared by the npm, pnpm and yarn parsers, which all record SRI integrity.
func NewHashes(integrity string) []languages.PackageHash {
	if strings.TrimSpace(integrity) == "" {
		return nil
	}
	var hashes []languages.PackageHash
	for _, entry := range strings.Fields(integrity) {
		dash := strings.IndexByte(entry, '-')
		if dash <= 0 {
			continue
		}
		alg, ok := sriAlgToCycloneDX[strings.ToLower(entry[:dash])]
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(entry[dash+1:])
		if err != nil || len(raw) == 0 {
			continue
		}
		hashes = append(hashes, languages.PackageHash{Alg: alg, Value: hex.EncodeToString(raw)})
	}
	return hashes
}

// NewPackageUrl creates a npm package url for a given package name and version
// see https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/npm-definition.md
func NewPackageUrl(name string, version string) string {
	namespace := ""
	// ensure the name is according to the PURL spec
	name = strings.ReplaceAll(name, "_", "-")

	components := strings.Split(name, "/")
	if len(components) > 1 {
		namespace = components[0]
		name = components[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		cleanVersion(version),
		nil,
		"").String()
}

func NewCpes(name string, version string) []string {
	cpes := []string{}
	cpeEntries, err := cpe.NewPackage2Cpe(name, name, cleanVersion(version), "", "")
	// we only add the cpe if it could be created
	// if the cpe could not be created, we log the error and continue to ensure the package is still added to the list
	if err != nil {
		log.Warn().Str("name", name).Str("version", version).Err(err).Msg("failed to create cpe")
	} else if len(cpeEntries) > 0 {
		cpes = append(cpes, cpeEntries...)
	}
	return cpes
}

func cleanVersion(version string) string {
	v := strings.ReplaceAll(version, "^", "")
	v = strings.ReplaceAll(v, "~", "")
	v = strings.ReplaceAll(v, ">", "")
	v = strings.ReplaceAll(v, "<", "")
	v = strings.ReplaceAll(v, "=", "")
	v = strings.ReplaceAll(v, " ", "")
	return v
}

func NewEvidenceList(evidence []string) []*sbom.Evidence {
	evidenceList := make([]*sbom.Evidence, len(evidence))
	for i, e := range evidence {
		evidenceList[i] = NewEvidence(e)
	}
	return evidenceList
}

func NewEvidence(filepath string) *sbom.Evidence {
	return &sbom.Evidence{
		Type:  sbom.EvidenceType_EVIDENCE_TYPE_FILE,
		Value: filepath,
	}
}
