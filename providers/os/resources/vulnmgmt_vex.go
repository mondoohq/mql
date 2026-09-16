// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/fex"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/sbomscan"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/sbom"
)

// getVexReport builds a PURL-native SBOM from the asset's local package
// inventory and scans it through the space-scoped uploaded-SBOM vulnerability
// path, returning the VEX documents the platform reports. It is the source of
// truth for incognito assets (no asset MRN, e.g. `cnspec shell`), which build
// their inventory locally anyway — sending it as an SBOM keeps the same source
// of truth while sourcing matches from package URLs.
func (v *mqlVulnmgmt) getVexReport() ([]*fex.VulnerabilityExchange, error) {
	mcc := v.MqlRuntime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		return nil, resources.MissingUpstreamError{}
	}

	bom, err := v.buildSbom()
	if err != nil {
		return nil, err
	}

	client, err := sbomscan.NewExtendedVulnMgmtClient(mcc.ApiEndpoint, mcc.HttpClient, mcc.Plugins...)
	if err != nil {
		return nil, err
	}

	// The scan is scoped to a space. The request field keeps the server's
	// historical asset_mrn name even though a space MRN is what is expected here.
	resp, err := client.ScanUploadedSbom(context.Background(), &sbomscan.ScanUploadedSbomRequest{
		AssetMrn: mcc.SpaceMrn,
		Sbom:     bom,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("no vulnerability report available")
	}

	// The platform returns one record per advisory source: a CVE-keyed record
	// and a GHSA-keyed record for the same weakness that name each other via
	// aliases/upstream. Fold those twins into one record per vulnerability so
	// the vuln.cve/vuln.advisory resources do not double-count a single
	// weakness. The raw VEX was already uploaded unchanged.
	return fex.FoldAliases(resp.Vex), nil
}

// buildSbom assembles a PURL-native SBOM from the asset's `packages` resource
// and platform metadata, mirroring the fields the SBOM generator emits so the
// platform can match both the package URLs and the operating-system context.
func (v *mqlVulnmgmt) buildSbom() (*sbom.Sbom, error) {
	pkgsRes, err := CreateResource(v.MqlRuntime, "packages", nil)
	if err != nil {
		return nil, err
	}
	pkgs := pkgsRes.(*mqlPackages)
	pkgsList := pkgs.GetList().Data

	bomPkgs := make([]*sbom.Package, 0, len(pkgsList))
	for _, p := range pkgsList {
		mqlPkg := p.(*mqlPackage)
		bomPkgs = append(bomPkgs, &sbom.Package{
			Name:         mqlPkg.Name.Data,
			Version:      mqlPkg.Version.Data,
			Architecture: mqlPkg.Arch.Data,
			Origin:       mqlPkg.Origin.Data,
			Type:         mqlPkg.Format.Data,
			Purl:         mqlPkg.Purl.Data,
		})
	}

	bom := &sbom.Sbom{
		Generator: &sbom.Generator{
			Vendor: "Mondoo, Inc.",
			Name:   "mql",
			Url:    "https://mondoo.com",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    sbom.Status_STATUS_SUCCEEDED,
		Packages:  bomPkgs,
	}

	if conn, ok := v.MqlRuntime.Connection.(shared.Connection); ok {
		if platform := conn.Asset().Platform; platform != nil {
			bom.Asset = &sbom.Asset{
				Name: platform.Name,
				Platform: &sbom.Platform{
					Name:    platform.Name,
					Version: platform.Version,
					Build:   platform.Build,
					Arch:    platform.Arch,
					Family:  platform.Family,
					Labels:  platform.Labels,
				},
			}
		}
	}

	return bom, nil
}

// populateFromVex maps the VEX documents onto the same vuln.cve /
// vuln.advisory / vuln.package / audit.cvss resources the compact-report path
// populates, so policies and the shell keep resolving. CVE ids become
// vuln.cve entries and every other id (distro/vendor advisories such as USN-,
// RHSA-, GHSA-, DLA-) becomes a vuln.advisory, mirroring the two separate
// lists the compact report returned.
func (v *mqlVulnmgmt) populateFromVex(vex []*fex.VulnerabilityExchange) error {
	mqlAdvisories := []any{}
	mqlCves := []any{}
	mqlPackages := []any{}

	// worst (highest) CVSS score across all findings, for the rolled-up stats.
	worstScore := float64(0)
	worstVector := ""

	// Affected packages, aggregated across all findings. A vuln.package's
	// identity is name+version, so only one `available` upgrade target can
	// survive per package. The fixed version is derived per vulnerability,
	// though, so the same installed package can be reported with different
	// targets by different vulnerabilities. Aggregate first and keep the most
	// conservative (highest) target, so the result is order-independent instead
	// of letting VEX ordering decide which target the user sees.
	type pkgKey struct{ name, version, arch string }
	pkgFixed := map[pkgKey]string{}
	pkgOrder := []pkgKey{}

	for _, vuln := range vex {
		if vuln == nil || vuln.Id == "" {
			continue
		}

		score, vector := vexWorstCvss(vuln)
		if score > worstScore {
			worstScore, worstVector = score, vector
		}

		worstCvss, err := v.createCvss(vuln.Id, score, vector)
		if err != nil {
			return err
		}

		published := vexPublished(vuln)
		modified := vexModified(vuln)

		if isCVE(vuln.Id) {
			cve, err := CreateResource(v.MqlRuntime, "vuln.cve", map[string]*llx.RawData{
				"id":         llx.StringData(vuln.Id),
				"worstScore": llx.ResourceData(worstCvss, "audit.cvss"),
				"state":      llx.StringData(vexStatusString(vuln)),
				"summary":    llx.StringData(vexSummary(vuln)),
				"published":  llx.TimeDataPtr(published),
				"modified":   llx.TimeDataPtr(modified),
			})
			if err != nil {
				return err
			}
			mqlCves = append(mqlCves, cve)
		} else {
			advisory, err := CreateResource(v.MqlRuntime, "vuln.advisory", map[string]*llx.RawData{
				"id":          llx.StringData(vuln.Id),
				"title":       llx.StringData(vexSummary(vuln)),
				"description": llx.StringData(vexDescription(vuln)),
				"published":   llx.TimeDataPtr(published),
				"modified":    llx.TimeDataPtr(modified),
				"worstScore":  llx.ResourceData(worstCvss, "audit.cvss"),
			})
			if err != nil {
				return err
			}
			mqlAdvisories = append(mqlAdvisories, advisory)
		}

		// Affected packages, PURL-native. The resolvable fixed version (if any)
		// becomes the `available` upgrade target.
		fixed := fex.FixedVersion(vuln)
		for _, c := range fex.AffectedComponents(vuln) {
			name, version, _ := fex.ComponentCoords(c)
			// A package needs both a name and a version to be identifiable; a
			// half-populated component would yield a malformed vuln.package
			// (its id is "name-version"), so drop it.
			if name == "" || version == "" {
				continue
			}
			arch := ""
			if c.Identifiers != nil {
				arch = c.Identifiers["arch"]
			}
			key := pkgKey{name: name, version: version, arch: arch}
			if prev, seen := pkgFixed[key]; seen {
				pkgFixed[key] = higherVersion(prev, fixed)
			} else {
				pkgFixed[key] = fixed
				pkgOrder = append(pkgOrder, key)
			}
		}
	}

	for _, key := range pkgOrder {
		pkg, err := CreateResource(v.MqlRuntime, "vuln.package", map[string]*llx.RawData{
			"name":      llx.StringData(key.name),
			"version":   llx.StringData(key.version),
			"available": llx.StringData(pkgFixed[key]),
			"arch":      llx.StringData(key.arch),
		})
		if err != nil {
			return err
		}
		mqlPackages = append(mqlPackages, pkg)
	}

	statsCvss, err := v.createCvss("stats", worstScore, worstVector)
	if err != nil {
		return err
	}

	v.Advisories = plugin.TValue[[]any]{Data: mqlAdvisories, State: plugin.StateIsSet}
	v.Cves = plugin.TValue[[]any]{Data: mqlCves, State: plugin.StateIsSet}
	v.Packages = plugin.TValue[[]any]{Data: mqlPackages, State: plugin.StateIsSet}
	v.Stats = plugin.TValue[*mqlAuditCvss]{Data: statsCvss.(*mqlAuditCvss), State: plugin.StateIsSet}

	return nil
}

// createCvss builds an audit.cvss resource. The id is scoped by the owning
// finding (a CVE/advisory id, or "stats" for the roll-up) as well as the score
// and vector: two findings can share an identical score+vector, and since
// CreateResource returns the cached instance for a repeated id, an unscoped id
// would make the second finding's worstScore silently alias the first's
// resource. The VEX Rating score is already a 0..10 CVSS base score, so it is
// used directly (unlike the compact report's 0..100 integer scale).
func (v *mqlVulnmgmt) createCvss(idScope string, score float64, vector string) (plugin.Resource, error) {
	id := fmt.Sprintf("%s-%.1f-%s", idScope, score, vector)
	return CreateResource(v.MqlRuntime, "audit.cvss", map[string]*llx.RawData{
		"__id":   llx.StringData(id),
		"score":  llx.FloatData(score),
		"vector": llx.StringData(vector),
	})
}

// vexWorstCvss returns the highest-scoring rating's score and vector.
func vexWorstCvss(v *fex.VulnerabilityExchange) (float64, string) {
	best := float64(0)
	vector := ""
	for _, r := range v.Ratings {
		if r == nil {
			continue
		}
		if s := float64(r.Score); s > best {
			best, vector = s, r.Vector
		}
	}
	return best, vector
}

// vexStatusString maps the VEX status enum onto the state string the vuln.cve
// resource exposes.
func vexStatusString(v *fex.VulnerabilityExchange) string {
	switch v.Status {
	case fex.Status_STATUS_NOT_AFFECTED:
		return "NOT_AFFECTED"
	case fex.Status_STATUS_AFFECTED:
		return "AFFECTED"
	case fex.Status_STATUS_FIXED:
		return "FIXED"
	case fex.Status_STATUS_UNDER_INVESTIGATION:
		return "UNDER_INVESTIGATION"
	case fex.Status_STATUS_FALSE_POSITIVE:
		return "FALSE_POSITIVE"
	case fex.Status_STATUS_WONT_FIX:
		return "WONT_FIX"
	default:
		return ""
	}
}

// vexSummary prefers the short summary and falls back to the detailed
// description.
func vexSummary(v *fex.VulnerabilityExchange) string {
	if s := strings.TrimSpace(v.Summary); s != "" {
		return s
	}
	if v.Details != nil {
		return strings.TrimSpace(v.Details.Details)
	}
	return ""
}

// vexDescription prefers the detailed description and falls back to the short
// summary.
func vexDescription(v *fex.VulnerabilityExchange) string {
	if v.Details != nil {
		if d := strings.TrimSpace(v.Details.Details); d != "" {
			return d
		}
	}
	return strings.TrimSpace(v.Summary)
}

// vexPublished returns the vulnerability's publication time, or nil.
func vexPublished(v *fex.VulnerabilityExchange) *time.Time {
	if v.Details != nil && v.Details.Published != nil {
		t := v.Details.Published.AsTime()
		return &t
	}
	return nil
}

// vexModified returns the vulnerability's last-updated time, or nil.
func vexModified(v *fex.VulnerabilityExchange) *time.Time {
	if v.Details != nil && v.Details.Updated != nil {
		t := v.Details.Updated.AsTime()
		return &t
	}
	return nil
}

// isCVE reports whether an id is a CVE identifier (vs a distro/vendor advisory).
func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-")
}

// higherVersion returns the more conservative (higher) of two version strings,
// so a package affected by several vulnerabilities reports the one upgrade
// target that clears them all. An empty string loses to any concrete version.
// The comparison is deterministic and independent of argument order.
func higherVersion(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if compareVersions(a, b) >= 0 {
		return a
	}
	return b
}

// versionSepRe splits a version into comparable segments. Package ecosystems
// disagree on separators (dots, dashes, tildes, epochs), so all are treated as
// segment boundaries for a best-effort ordering.
var versionSepRe = regexp.MustCompile(`[.\-_+~:]+`)

// compareVersions orders two version strings segment by segment: segments that
// are both numeric compare numerically (so "1.0.10" ranks above "1.0.2"),
// otherwise they compare lexically. It returns -1, 0, or 1. This is a
// best-effort, ecosystem-agnostic ordering — its only hard guarantees are that
// it is deterministic and total, which is what the aggregation needs to avoid
// order-dependent output.
func compareVersions(a, b string) int {
	as := versionSepRe.Split(strings.TrimPrefix(a, "v"), -1)
	bs := versionSepRe.Split(strings.TrimPrefix(b, "v"), -1)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		if xErr == nil && yErr == nil {
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
			continue
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
