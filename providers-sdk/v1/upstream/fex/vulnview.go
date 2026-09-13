// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
)

// This file holds rendering-agnostic helpers that turn the platform's VEX
// documents ([]*VulnerabilityExchange) into a flat, renderable vulnerability
// model. The goal is a single source of truth for severity, affected-component,
// reference, remediation, and fixed-version derivation so that every client
// (tables, JSON, CSV, ...) shares the same interpretation instead of each
// re-deriving it. Nothing here formats output; callers own presentation.

// Severity vocabulary emitted by Severity. Callers can rely on these exact
// strings when rendering or filtering.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityNone     = "NONE"
)

// SeverityLabel reduces a vulnerability's ratings to a single severity label
// (CRITICAL/HIGH/MEDIUM/LOW/NONE), picking the most severe rating. It uses the
// rating's severity word when present and otherwise derives one from the CVSS
// score. A vulnerability with no usable rating is NONE. (The bare name Severity
// is already a generated proto message in this package.)
func SeverityLabel(v *VulnerabilityExchange) string {
	if v == nil {
		return SeverityNone
	}
	best := 0
	for _, r := range v.Ratings {
		if r == nil {
			continue
		}
		rank := SeverityRank(mapRatingSeverity(r.Severity))
		if rank == 0 {
			rank = SeverityRank(scoreToSeverity(r.Score))
		}
		if rank > best {
			best = rank
		}
	}
	switch best {
	case 4:
		return SeverityCritical
	case 3:
		return SeverityHigh
	case 2:
		return SeverityMedium
	case 1:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// mapRatingSeverity normalizes an advisory severity word to the label
// vocabulary, or returns "" when the word is unknown.
func mapRatingSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low", "negligible":
		return SeverityLow
	case "none":
		// An explicit "none" rating means genuinely no severity — keep it at
		// NONE rather than promoting it to LOW.
		return SeverityNone
	default:
		return ""
	}
}

// scoreToSeverity buckets a CVSS base score into a severity word.
func scoreToSeverity(score float32) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return ""
	}
}

// SeverityRank orders severity labels for sorting (higher = worse). It accepts
// both the label vocabulary Severity emits and the common CVSS synonyms
// (HIGH/MEDIUM/LOW), so callers can rank whichever labels they hold.
func SeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH", "ERROR":
		return 3
	case "MEDIUM", "MODERATE", "WARNING":
		return 2
	case "LOW", "INFO", "NEGLIGIBLE":
		return 1
	default:
		return 0
	}
}

// AffectedComponents returns the concrete affected packages for a vulnerability.
// The platform nests the matched package PURL(s) in SubComponents under a coarser
// root Component (often just the ecosystem), so prefer the sub-components and fall
// back to the root only when a row carries none — otherwise every entry is
// duplicated by a pathless ecosystem-level component.
func AffectedComponents(v *VulnerabilityExchange) []*Component {
	if v == nil {
		return nil
	}
	var out []*Component
	for _, a := range v.Affects {
		if a == nil {
			continue
		}
		if len(a.SubComponents) > 0 {
			for _, sc := range a.SubComponents {
				if sc != nil {
					out = append(out, sc)
				}
			}
			continue
		}
		if a.Component != nil {
			out = append(out, a.Component)
		}
	}
	return out
}

// ComponentCoords extracts a package's name, version, and purl from an affected
// component. The server sets the component id to the package name and carries
// purl/version in the identifiers map. When only a PURL is present, it is parsed
// for a human-friendly name/version so callers can render "lodash 4.17.20"
// rather than "pkg:npm/lodash@4.17.20".
func ComponentCoords(c *Component) (name, version, purl string) {
	if c == nil {
		return "", "", ""
	}
	name = c.Id
	if c.Identifiers != nil {
		purl = c.Identifiers["purl"]
		version = c.Identifiers["version"]
		if name == "" {
			name = c.Identifiers["name"]
		}
	}
	// The platform sets a sub-component's Id to the package PURL.
	if purl == "" && strings.HasPrefix(name, "pkg:") {
		purl = name
	}
	if strings.HasPrefix(purl, "pkg:") {
		if p, err := packageurl.FromString(purl); err == nil {
			pname := p.Name
			if p.Namespace != "" {
				pname = p.Namespace + "/" + p.Name
			}
			if pname != "" {
				name = pname
			}
			if version == "" {
				version = p.Version
			}
		}
	}
	return name, version, purl
}

// ReferenceURLs collects the advisory/reference URLs attached to a vulnerability.
func ReferenceURLs(v *VulnerabilityExchange) []string {
	if v == nil {
		return nil
	}
	var urls []string
	for _, r := range v.References {
		if r != nil && r.Url != "" {
			urls = append(urls, r.Url)
		}
	}
	return urls
}

// RemediationHint returns the first available remediation summary for display.
func RemediationHint(v *VulnerabilityExchange) string {
	if v == nil {
		return ""
	}
	for _, r := range v.Remediations {
		if r == nil {
			continue
		}
		if s := strings.TrimSpace(r.Summary); s != "" {
			return s
		}
		if d := strings.TrimSpace(r.Details); d != "" {
			return d
		}
	}
	return ""
}

// FixedVersion determines the version to upgrade to for a vulnerability, in
// descending order of trust:
//
//  1. A structured field on an affected component's identifiers
//     ("fixed_version"/"fixed") — authoritative.
//  2. A version parsed from a package-category remediation's prose — plausible
//     but unverified.
//
// It returns the empty string when neither yields a version.
func FixedVersion(v *VulnerabilityExchange) string {
	if v == nil {
		return ""
	}
	// (1) Structured identifier on any affected component.
	for _, c := range AffectedComponents(v) {
		if c == nil || c.Identifiers == nil {
			continue
		}
		for _, key := range []string{"fixed_version", "fixed"} {
			if fv := strings.TrimSpace(c.Identifiers[key]); fv != "" {
				return fv
			}
		}
	}

	// (2) Conservative prose parse of a package-fix remediation.
	for _, r := range v.Remediations {
		if r == nil {
			continue
		}
		// Prefer remediations that are about a package upgrade; FixType is
		// free-form ("package", "terraform", ...), so treat an empty type as
		// eligible rather than dropping it.
		if r.FixType != "" && !strings.EqualFold(r.FixType, "package") {
			continue
		}
		for _, text := range []string{r.Summary, r.Details} {
			if fv, ok := parseFixedVersion(text); ok {
				return fv
			}
		}
	}
	return ""
}

// intentRe requires an upgrade-intent keyword so a bare version elsewhere in the
// prose (e.g. "affects 1.2.3") is not mistaken for the fix target.
var intentRe = regexp.MustCompile(`(?i)\b(upgrade|update|fixed in|fix in|patched in|bump|use version|please use|>=)\b`)

// versionRe matches a dotted, optionally v-prefixed version token.
var versionRe = regexp.MustCompile(`\bv?\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z.]+)?\b`)

// parseFixedVersion conservatively extracts a fixed version from remediation
// prose. It fires only when the text expresses upgrade intent AND names exactly
// one distinct version — ambiguity (no versions, or several different ones)
// yields nothing, to avoid manufacturing precision.
func parseFixedVersion(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text == "" || !intentRe.MatchString(text) {
		return "", false
	}
	matches := versionRe.FindAllString(text, -1)
	if len(matches) == 0 {
		return "", false
	}
	distinct := map[string]bool{}
	for _, m := range matches {
		distinct[strings.TrimPrefix(m, "v")] = true
	}
	if len(distinct) != 1 {
		// Zero handled above; more than one distinct version is ambiguous.
		return "", false
	}
	return matches[0], true
}

// EcosystemOf returns the purl type of a package URL ("npm", "golang", ...), or
// "" when the purl is absent or unparseable.
func EcosystemOf(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	p, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	return p.Type
}

// VulnRow is a flat, rendering-agnostic view of a single vulnerability as it
// affects one package. Clients render it however they like (table, JSON, CSV);
// this package derives the fields but never formats them.
type VulnRow struct {
	ID              string   // CVE/advisory id
	Severity        string   // CRITICAL..NONE (from SeverityLabel)
	Summary         string   // human-readable summary of the vulnerability
	AffectedName    string   // affected package name
	AffectedVersion string   // affected package version
	AffectedPurl    string   // affected package PURL
	FixedVersion    string   // upgrade target, if resolvable
	References      []string // advisory/reference URLs
	RemediationHint string   // first remediation summary/details, if any
}

// VulnRows flattens VEX documents into one row per (vulnerability, affected
// component), sorted by severity (most severe first) then id. A vulnerability
// with no resolved component still yields a single row so it is never silently
// dropped. Rows carry only derived data — callers add file location and
// presentation themselves.
func VulnRows(vex []*VulnerabilityExchange) []VulnRow {
	var rows []VulnRow
	for _, v := range vex {
		if v == nil || v.Id == "" {
			continue
		}
		severity := SeverityLabel(v)
		summary := vulnSummary(v)
		fixed := FixedVersion(v)
		refs := ReferenceURLs(v)
		hint := RemediationHint(v)

		comps := AffectedComponents(v)
		if len(comps) == 0 {
			rows = append(rows, VulnRow{
				ID:              v.Id,
				Severity:        severity,
				Summary:         summary,
				FixedVersion:    fixed,
				References:      refs,
				RemediationHint: hint,
			})
			continue
		}
		for _, c := range comps {
			name, version, purl := ComponentCoords(c)
			rows = append(rows, VulnRow{
				ID:              v.Id,
				Severity:        severity,
				Summary:         summary,
				AffectedName:    name,
				AffectedVersion: version,
				AffectedPurl:    purl,
				FixedVersion:    fixed,
				References:      refs,
				RemediationHint: hint,
			})
		}
	}

	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := SeverityRank(rows[i].Severity), SeverityRank(rows[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

// vulnSummary returns the best human-readable summary for a vulnerability,
// falling back to the detailed description when the short summary is empty.
func vulnSummary(v *VulnerabilityExchange) string {
	summary := strings.TrimSpace(v.Summary)
	if summary == "" && v.Details != nil {
		summary = strings.TrimSpace(v.Details.Details)
	}
	return summary
}
