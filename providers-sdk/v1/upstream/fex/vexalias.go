// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FoldAliases collapses VEX records that describe ONE vulnerability under
// several identifiers into one record per vulnerability.
//
// The platform answers an SBOM scan with one record per advisory *source*: a
// GHSA-keyed row from the GitHub advisory database and a CVE-keyed row for the
// same weakness, linked to each other — the GHSA row names the CVE in
// `upstream`, and both name the other in `related`. Rendered as-is, every
// dependency vulnerability is two findings with the same package, the same
// summary and the same fix, and the coverage line counts them twice. Measured on
// a nine-dependency pom.xml: 145 rows for 73 distinct advisories.
//
// Folding is by IDENTITY links only — `aliases` and `upstream`. `related` alone
// is not enough: in OSV's vocabulary a related advisory is a different
// vulnerability that shares context, and treating it as the same one would fold
// two real CVEs into one finding, which is a lost true positive. A GHSA record
// that carries no upstream CVE stays its own finding.
//
// The record that survives is the CVE-keyed one when the group has it (the
// identifier every other tool reports, so a side-by-side comparison lines up),
// and it absorbs what the folded twins knew that it did not: the GHSA row's
// severity word (the CVE row carries CVSS scores only), a structured fixed
// version, ratings, references and remediations. The folded identifiers land in
// `Aliases`, and the finding carries them as metadata, so nothing the platform
// said is dropped — it is stated once.
//
// The input is not mutated: the returned records are clones, so the raw VEX can
// still be uploaded exactly as the platform produced it.
func FoldAliases(vex []*VulnerabilityExchange) []*VulnerabilityExchange {
	byID := map[string]int{}
	for i, v := range vex {
		if v == nil || v.Id == "" {
			continue
		}
		if _, dup := byID[v.Id]; !dup {
			byID[v.Id] = i
		}
	}

	// Union-find over record positions, linked through identity ids.
	parent := make([]int, len(vex))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}
	for i, v := range vex {
		if v == nil || v.Id == "" {
			continue
		}
		// A repeated id is the same record stated twice.
		union(byID[v.Id], i)
		for _, id := range identityLinks(v) {
			if j, ok := byID[id]; ok {
				union(i, j)
			}
		}
	}

	// Groups in first-appearance order, so the output is stable for a stable
	// input. Callers order the findings themselves later.
	groups := map[int][]int{}
	var order []int
	for i, v := range vex {
		if v == nil || v.Id == "" {
			continue
		}
		r := find(i)
		if _, seen := groups[r]; !seen {
			order = append(order, r)
		}
		groups[r] = append(groups[r], i)
	}

	out := make([]*VulnerabilityExchange, 0, len(order))
	for _, r := range order {
		members := groups[r]
		sort.SliceStable(members, func(a, b int) bool {
			return idRank(vex[members[a]].Id) < idRank(vex[members[b]].Id)
		})
		canonical := proto.Clone(vex[members[0]]).(*VulnerabilityExchange)
		for _, m := range members[1:] {
			mergeVuln(canonical, vex[m])
		}
		canonical.Aliases = finishAliases(canonical)
		out = append(out, canonical)
	}
	return out
}

// identityLinks returns the ids a record states are the SAME vulnerability:
// its aliases, and the upstream advisory it was derived from. `related` is
// deliberately excluded (see FoldAliases).
func identityLinks(v *VulnerabilityExchange) []string {
	links := make([]string, 0, len(v.Aliases)+len(v.Upstream))
	links = append(links, v.Aliases...)
	links = append(links, v.Upstream...)
	return links
}

// idRank orders a group's members so the canonical record is the one a reader
// expects: a CVE first, then a GHSA, then anything else; ties by id so the pick
// is deterministic.
func idRank(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "0" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "1" + id
	default:
		return "2" + id
	}
}

// mergeVuln folds src into dst: dst keeps its own answer wherever it has one and
// takes src's where it does not, and the list-valued fields are unioned so no
// rating, reference, remediation or affected component the platform returned is
// lost in the fold.
func mergeVuln(dst, src *VulnerabilityExchange) {
	if strings.TrimSpace(dst.Summary) == "" {
		dst.Summary = src.Summary
	}
	if dst.Details == nil && src.Details != nil {
		dst.Details = proto.Clone(src.Details).(*VulnerabilityDetails)
	}
	if dst.DatabaseSpecific == nil && src.DatabaseSpecific != nil {
		dst.DatabaseSpecific = proto.Clone(src.DatabaseSpecific).(*structpb.Struct)
	}
	// Clone rather than share the pointer: the input is not mutated, so the
	// survivor must not alias a timestamp the caller still holds.
	if src.FirstSeen != nil && (dst.FirstSeen == nil || src.FirstSeen.AsTime().Before(dst.FirstSeen.AsTime())) {
		dst.FirstSeen = proto.Clone(src.FirstSeen).(*timestamppb.Timestamp)
	}
	// The folded twin's own id and everything it pointed at become aliases of
	// the survivor; finishAliases dedupes and drops the survivor's own id.
	dst.Aliases = append(dst.Aliases, src.Id)
	dst.Aliases = append(dst.Aliases, src.Aliases...)
	dst.Aliases = append(dst.Aliases, src.Upstream...)
	dst.Related = append(dst.Related, src.Related...)

	for _, r := range src.Ratings {
		if r != nil && !hasRating(dst.Ratings, r) {
			dst.Ratings = append(dst.Ratings, proto.Clone(r).(*Rating))
		}
	}
	for _, ref := range src.References {
		if ref != nil && !hasReference(dst.References, ref) {
			dst.References = append(dst.References, proto.Clone(ref).(*Reference))
		}
	}
	for _, rem := range src.Remediations {
		if rem != nil && !hasRemediation(dst.Remediations, rem) {
			dst.Remediations = append(dst.Remediations, proto.Clone(rem).(*Remediation))
		}
	}
	mergeAffects(dst, src)
}

// mergeAffects unions the affected components. A component both records name is
// kept once, and a structured identifier (`fixed`, `fixed_version`) only the
// folded twin carried is copied onto the survivor's component, so the fold can
// only add remediation knowledge, never lose it.
func mergeAffects(dst, src *VulnerabilityExchange) {
	for _, sa := range src.Affects {
		if sa == nil {
			continue
		}
		var target *Affects
		for _, da := range dst.Affects {
			if da != nil && componentKey(da.Component) == componentKey(sa.Component) {
				target = da
				break
			}
		}
		if target == nil {
			dst.Affects = append(dst.Affects, proto.Clone(sa).(*Affects))
			continue
		}
		if target.Component != nil && sa.Component != nil {
			copyMissingIdentifiers(target.Component, sa.Component)
		}
		for _, sc := range sa.SubComponents {
			if sc == nil {
				continue
			}
			var have *Component
			for _, dc := range target.SubComponents {
				if dc != nil && componentKey(dc) == componentKey(sc) {
					have = dc
					break
				}
			}
			if have == nil {
				target.SubComponents = append(target.SubComponents, proto.Clone(sc).(*Component))
				continue
			}
			copyMissingIdentifiers(have, sc)
		}
	}
}

// copyMissingIdentifiers fills identifiers dst lacks from src without
// overwriting any dst already states.
func copyMissingIdentifiers(dst, src *Component) {
	if len(src.Identifiers) == 0 {
		return
	}
	if dst.Identifiers == nil {
		dst.Identifiers = map[string]string{}
	}
	for k, v := range src.Identifiers {
		if v == "" {
			continue
		}
		if _, ok := dst.Identifiers[k]; !ok || dst.Identifiers[k] == "" {
			dst.Identifiers[k] = v
		}
	}
}

// componentKey is the identity two affected components share: the purl when
// present (canonicalised the way the coverage index does), else the id.
func componentKey(c *Component) string {
	if c == nil {
		return ""
	}
	if c.Identifiers != nil {
		if p := c.Identifiers["purl"]; p != "" {
			return purlKey(p)
		}
	}
	if strings.HasPrefix(c.Id, "pkg:") {
		return purlKey(c.Id)
	}
	return c.Id
}

// purlKey canonicalises a package URL to its type/namespace/name@version
// identity, lower-cased, so two records naming the same package under
// differently-formatted purls still match. It returns "" for a non-purl.
func purlKey(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	p, err := packageurl.FromString(purl)
	if err != nil || p.Name == "" {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%s/%s/%s@%s", p.Type, p.Namespace, p.Name, p.Version))
}

func hasRating(list []*Rating, r *Rating) bool {
	for _, have := range list {
		if have == nil {
			continue
		}
		if have.Score == r.Score && have.Vector == r.Vector && have.Method == r.Method &&
			strings.EqualFold(have.Severity, r.Severity) {
			return true
		}
	}
	return false
}

func hasReference(list []*Reference, r *Reference) bool {
	for _, have := range list {
		if have != nil && have.Url == r.Url {
			return true
		}
	}
	return false
}

func hasRemediation(list []*Remediation, r *Remediation) bool {
	for _, have := range list {
		if have != nil && have.Summary == r.Summary && have.Details == r.Details {
			return true
		}
	}
	return false
}

// finishAliases returns the survivor's alias list deduplicated, sorted, and
// without its own id. The same ids are removed from Related: an identifier that
// turned out to be the same vulnerability is not a related one.
func finishAliases(v *VulnerabilityExchange) []string {
	seen := map[string]bool{v.Id: true}
	var out []string
	for _, a := range v.Aliases {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Strings(out)

	var related []string
	seenRel := map[string]bool{}
	for _, r := range v.Related {
		if r == "" || seen[r] || seenRel[r] {
			continue
		}
		seenRel[r] = true
		related = append(related, r)
	}
	v.Related = related
	return out
}
