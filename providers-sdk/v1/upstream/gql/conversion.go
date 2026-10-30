// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import "go.mondoo.com/mql/providers-sdk/v1/upstream/mvd"

func ConvertToMvdVulnReport(vulnReport *VulnReport) *mvd.VulnReport {
	if vulnReport == nil {
		return nil
	}
	mvdVulnReport := &mvd.VulnReport{
		Stats: &mvd.ReportStats{},
	}
	mvdVulnReport.Advisories = make([]*mvd.Advisory, len(vulnReport.Advisories))
	for i, advisory := range vulnReport.Advisories {
		mvdAdvisory := &mvd.Advisory{
			ID:          advisory.Id,
			Title:       advisory.Title,
			Description: advisory.Description,
			Fixed:       []*mvd.Package{},
			Affected:    []*mvd.Package{},
			Score:       int32(advisory.CvssScore.Value),
		}
		for _, fixed := range advisory.FixedByPackages {
			mvdAdvisory.Fixed = append(mvdAdvisory.Fixed, &mvd.Package{
				Name:      fixed.Name,
				Version:   fixed.Version,
				Available: fixed.Available,
			})
		}
		for _, affected := range advisory.AffectedPackages {
			mvdAdvisory.Affected = append(mvdAdvisory.Affected, &mvd.Package{
				Name:      affected.Name,
				Version:   affected.Version,
				Available: affected.Available,
				Affected:  true,
				Score:     int32(affected.Score.Value),
			})
		}
		mvdVulnReport.Advisories[i] = mvdAdvisory
	}
	mvdVulnReport.Packages = make([]*mvd.Package, len(vulnReport.Packages))
	for i, pkg := range vulnReport.Packages {
		mvdVulnReport.Packages[i] = &mvd.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Available: pkg.Available,
			Affected:  true,
			Score:     int32(pkg.Score.Value),
		}
	}

	if vulnReport.Stats != nil {
		mvdVulnReport.Stats = &mvd.ReportStats{
			Score: int32(vulnReport.Stats.Score.Value),
			Advisories: &mvd.ReportStatsAdvisories{
				Total:    int32(vulnReport.Stats.Advisories.Total),
				Critical: int32(vulnReport.Stats.Advisories.Critical),
				High:     int32(vulnReport.Stats.Advisories.High),
				Medium:   int32(vulnReport.Stats.Advisories.Medium),
				Low:      int32(vulnReport.Stats.Advisories.Low),
				None:     int32(vulnReport.Stats.Advisories.None),
				Unknown:  int32(vulnReport.Stats.Advisories.Unknown),
			},
			Cves: &mvd.ReportStatsCves{
				Total:    int32(vulnReport.Stats.Cves.Total),
				Critical: int32(vulnReport.Stats.Cves.Critical),
				High:     int32(vulnReport.Stats.Cves.High),
				Medium:   int32(vulnReport.Stats.Cves.Medium),
				Low:      int32(vulnReport.Stats.Cves.Low),
				None:     int32(vulnReport.Stats.Cves.None),
				Unknown:  int32(vulnReport.Stats.Cves.Unknown),
			},
			Packages: &mvd.ReportStatsPackages{
				Total:    int32(vulnReport.Stats.Packages.Total),
				Affected: int32(vulnReport.Stats.Packages.Affected),
				Critical: int32(vulnReport.Stats.Packages.Critical),
				High:     int32(vulnReport.Stats.Packages.High),
				Medium:   int32(vulnReport.Stats.Packages.Medium),
				Low:      int32(vulnReport.Stats.Packages.Low),
				None:     int32(vulnReport.Stats.Packages.None),
				Unknown:  int32(vulnReport.Stats.Packages.Unknown),
			},
			Exploits: &mvd.ReportStatsExploits{},
		}
	}

	return mvdVulnReport
}
