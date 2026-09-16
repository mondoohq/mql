// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fex

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const strutsPurl = "pkg:maven/org.apache.struts/struts2-core@2.5.20"

// platformPair is the shape the platform returns for one advisory: a CVE-keyed
// record with CVSS scores and no fixed version, and a GHSA-keyed record naming
// the CVE in `upstream`, carrying the severity word and the structured fix.
func platformPair() []*VulnerabilityExchange {
	return []*VulnerabilityExchange{
		{
			Id:      "CVE-2023-50164",
			Summary: "Apache Struts vulnerable to path traversal",
			Related: []string{"GHSA-2j39-qcjm-428w"},
			Ratings: []*Rating{{Score: 9.8, Vector: "CVSS:3.1/AV:N"}},
			Affects: []*Affects{{
				Component:     &Component{Id: "Maven", Identifiers: map[string]string{"namespace": "Maven"}},
				SubComponents: []*Component{{Id: strutsPurl, Identifiers: map[string]string{"purl": strutsPurl}}},
			}},
			References: []*Reference{{Url: "https://nvd.nist.gov/vuln/detail/CVE-2023-50164"}},
		},
		{
			Id:       "GHSA-2j39-qcjm-428w",
			Summary:  "Apache Struts vulnerable to path traversal",
			Related:  []string{"CVE-2023-50164"},
			Upstream: []string{"CVE-2023-50164"},
			Ratings:  []*Rating{{Score: 9.8, Severity: "critical", Vector: "CVSS:3.1/AV:N"}},
			Affects: []*Affects{{
				Component:     &Component{Id: "Maven", Identifiers: map[string]string{"namespace": "Maven"}},
				SubComponents: []*Component{{Id: strutsPurl, Identifiers: map[string]string{"purl": strutsPurl, "fixed": "2.5.33"}}},
			}},
			References:   []*Reference{{Url: "https://github.com/advisories/GHSA-2j39-qcjm-428w"}},
			Remediations: []*Remediation{{Summary: "Upgrade to 2.5.33"}},
		},
	}
}

// TestFoldAliasesCollapsesCveGhsaTwins is the measured case: 145 platform rows
// for 73 advisories on a nine-dependency pom.xml, every CVE stated twice.
func TestFoldAliasesCollapsesCveGhsaTwins(t *testing.T) {
	in := platformPair()
	out := FoldAliases(in)
	require.Len(t, out, 1)

	v := out[0]
	assert.Equal(t, "CVE-2023-50164", v.Id, "the CVE is the survivor: it is the id every other tool reports")
	assert.Equal(t, []string{"GHSA-2j39-qcjm-428w"}, v.Aliases)
	assert.Empty(t, v.Related, "an id that turned out to be the same vulnerability is not a related one")

	// What only the GHSA row knew is carried over.
	assert.Equal(t, "CRITICAL", SeverityLabel(v), "the GHSA severity word must survive the fold")
	assert.Equal(t, "2.5.33", FixedVersion(v), "the structured fixed version must survive the fold")
	assert.Len(t, v.References, 2)
	assert.Len(t, v.Remediations, 1)

	// One affected component, not two.
	comps := AffectedComponents(v)
	require.Len(t, comps, 1)
	assert.Equal(t, strutsPurl, comps[0].Identifiers["purl"])

	// The input is untouched: the raw VEX is what gets uploaded.
	assert.Nil(t, in[0].Aliases)
	assert.Equal(t, []string{"GHSA-2j39-qcjm-428w"}, in[0].Related)
	assert.Empty(t, in[0].Affects[0].SubComponents[0].Identifiers["fixed"])
}

// TestFoldAliasesAdoptedFirstSeenIsCloned guards the "input is not mutated"
// contract for FirstSeen: when the survivor adopts the folded twin's earlier
// timestamp, it must clone it rather than alias the caller's proto message.
func TestFoldAliasesAdoptedFirstSeenIsCloned(t *testing.T) {
	ts := timestamppb.New(time.Unix(1_600_000_000, 0).UTC())
	in := []*VulnerabilityExchange{
		// CVE survivor with no FirstSeen ...
		{Id: "CVE-2023-50164", Summary: "twin"},
		// ... GHSA twin carrying the timestamp the survivor will adopt.
		{Id: "GHSA-2j39-qcjm-428w", Summary: "twin", Upstream: []string{"CVE-2023-50164"}, FirstSeen: ts},
	}
	out := FoldAliases(in)
	require.Len(t, out, 1)

	require.NotNil(t, out[0].FirstSeen)
	assert.True(t, out[0].FirstSeen.AsTime().Equal(ts.AsTime()), "the earlier timestamp must be adopted")
	assert.NotSame(t, ts, out[0].FirstSeen, "the adopted timestamp must be a clone, not the caller's pointer")
	assert.Same(t, ts, in[1].FirstSeen, "the input timestamp pointer is untouched")
}

// TestFoldAliasesRelatedAloneDoesNotFold pins the accuracy boundary: two CVEs
// that only reference each other as related are two vulnerabilities, and
// folding them would drop a true positive.
func TestFoldAliasesRelatedAloneDoesNotFold(t *testing.T) {
	in := []*VulnerabilityExchange{
		{Id: "CVE-2021-44228", Summary: "Log4Shell", Related: []string{"CVE-2021-45046"}},
		{Id: "CVE-2021-45046", Summary: "Incomplete fix for Log4Shell", Related: []string{"CVE-2021-44228"}},
	}
	out := FoldAliases(in)
	require.Len(t, out, 2)
	assert.Equal(t, "CVE-2021-44228", out[0].Id)
	assert.Equal(t, "CVE-2021-45046", out[1].Id)
	assert.Empty(t, out[0].Aliases)
}

// TestFoldAliasesGhsaWithoutUpstreamStays: an advisory GitHub published with no
// CVE assigned has nothing to fold into and remains its own finding.
func TestFoldAliasesGhsaWithoutUpstreamStays(t *testing.T) {
	in := append(platformPair(), &VulnerabilityExchange{
		Id: "GHSA-r7wm-3cxj-wff9", Summary: "jackson-core async parser bypass",
	})
	out := FoldAliases(in)
	require.Len(t, out, 2)
	assert.Equal(t, "CVE-2023-50164", out[0].Id)
	assert.Equal(t, "GHSA-r7wm-3cxj-wff9", out[1].Id)
}

// TestFoldAliasesOneCveSeveralGhsa: one CVE published as separate GHSAs (one per
// ecosystem is common) folds into a single finding listing both.
func TestFoldAliasesOneCveSeveralGhsa(t *testing.T) {
	in := []*VulnerabilityExchange{
		{Id: "GHSA-aaaa-aaaa-aaaa", Upstream: []string{"CVE-2020-0001"}},
		{Id: "CVE-2020-0001"},
		{Id: "GHSA-bbbb-bbbb-bbbb", Upstream: []string{"CVE-2020-0001"}},
	}
	out := FoldAliases(in)
	require.Len(t, out, 1)
	assert.Equal(t, "CVE-2020-0001", out[0].Id)
	assert.Equal(t, []string{"GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"}, out[0].Aliases)
}

// TestFoldAliasesAliasesFieldLinksToo: a record using the OSV `aliases` field
// (rather than the platform's `upstream`) folds the same way.
func TestFoldAliasesAliasesFieldLinksToo(t *testing.T) {
	in := []*VulnerabilityExchange{
		{Id: "CVE-2020-0002", Aliases: []string{"GHSA-cccc-cccc-cccc"}},
		{Id: "GHSA-cccc-cccc-cccc"},
	}
	out := FoldAliases(in)
	require.Len(t, out, 1)
	assert.Equal(t, "CVE-2020-0002", out[0].Id)
	assert.Equal(t, []string{"GHSA-cccc-cccc-cccc"}, out[0].Aliases)
}

// TestFoldAliasesTwinNamingAnotherComponentIsUnioned: when the two records
// disagree on which components are affected, the survivor names both — the
// fold must never shrink the affected set.
func TestFoldAliasesTwinNamingAnotherComponentIsUnioned(t *testing.T) {
	other := "pkg:maven/org.apache.struts/struts2-rest-plugin@2.5.20"
	in := platformPair()
	in[1].Affects[0].SubComponents = append(in[1].Affects[0].SubComponents,
		&Component{Id: other, Identifiers: map[string]string{"purl": other}})
	out := FoldAliases(in)
	require.Len(t, out, 1)
	comps := AffectedComponents(out[0])
	require.Len(t, comps, 2)
	assert.Equal(t, strutsPurl, comps[0].Identifiers["purl"])
	assert.Equal(t, other, comps[1].Identifiers["purl"])
}

// TestFoldAliasesTolerantOfNilAndEmpty: the same tolerance the render helpers have.
func TestFoldAliasesTolerantOfNilAndEmpty(t *testing.T) {
	assert.Empty(t, FoldAliases(nil))
	out := FoldAliases([]*VulnerabilityExchange{nil, {Id: ""}, {Id: "CVE-1"}})
	require.Len(t, out, 1)
	assert.Equal(t, "CVE-1", out[0].Id)
}

// TestVulnRowsAfterFoldCarryOneRow is the end-to-end shape proving the wiring:
// VulnRows folds first, so the twin pair renders as ONE row keyed by the CVE
// (carrying the GHSA's severity and structured fix), where the same input
// rendered without the fold would be two rows — the double-count this removes.
func TestVulnRowsAfterFoldCarryOneRow(t *testing.T) {
	rows := VulnRows(platformPair())
	require.Len(t, rows, 1)
	assert.Equal(t, "CVE-2023-50164", rows[0].ID)
	assert.Equal(t, strutsPurl, rows[0].AffectedPurl)
	assert.Equal(t, "2.5.33", rows[0].FixedVersion)
	assert.Equal(t, SeverityCritical, rows[0].Severity)

	// Explicitly folding first and rendering the result is idempotent: still
	// one row, never re-split.
	assert.Len(t, VulnRows(FoldAliases(platformPair())), 1)
}
