// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gql

import (
	"context"

	mondoogql "go.mondoo.com/mondoo-go"
)

// LastAssessment fetches the las update time of the packages query
// This is also the lst time the vuln report was updated
func (c *MondooClient) LastAssessment(mrn string) (string, error) {
	var m struct {
		AssetLastPackageUpdateTime struct {
			LastUpdated string
		} `graphql:"assetLastPackageUpdateTime(input: $input)"`
	}
	err := c.Query(context.Background(), &m, map[string]any{"input": mondoogql.AssetLastPackageUpdateTimeInput{Mrn: mondoogql.String(mrn)}})
	if err != nil {
		return "", err
	}
	return m.AssetLastPackageUpdateTime.LastUpdated, nil
}

type VulnReport struct {
	AssetMrn   string
	Advisories []*Advisory
	Cves       []*Cve
	Packages   []*Package
	Stats      *ReportStats
}

type ReportStats struct {
	Score struct {
		Id     string
		Value  int
		Type   int
		Vector string
		Source string
	}
	Cves struct {
		Total    int
		Critical int
		High     int
		Medium   int
		Low      int
		None     int
		Unknown  int
	}
	Packages struct {
		Total    int
		Affected int
		Critical int
		High     int
		Medium   int
		Low      int
		None     int
		Unknown  int
	}
	Advisories struct {
		Total    int
		Critical int
		High     int
		Medium   int
		Low      int
		None     int
		Unknown  int
	}
	Exploits struct {
		Total int
	}
}

type Cve struct {
	Id          string
	Title       string
	Description string
	Summary     string
	PublishedAt string
	ModifiedAt  string
	Url         string
	CvssScore   struct {
		Id     string
		Value  int
		Type   int
		Vector string
		Source string
	}
	CvssScores []struct {
		Id     string
		Value  int
		Type   int
		Vector string
		Source string
	}
	Cwe   string
	State string
}

// Advisory's fields are the GraphQL selection set. It deliberately does not
// select the deprecated Advisory.cves: the server resolves it with several MVD
// calls per advisory, and nothing here reads it. The report's top-level Cves
// carries the asset's CVEs.
type Advisory struct {
	Id          string
	Title       string
	Description string

	CvssScore struct {
		Id     string
		Value  int
		Type   int
		Vector string
		Source string
	}
	Vendorscore      int
	PublishedAt      string
	ModifiedAt       string
	AffectedPackages []struct {
		Package
	}
	FixedByPackages []struct {
		Package
	}
}

type Package struct {
	Id      string
	Name    string
	Version string
	Arch    string
	Format  string

	Namespace   string
	Description string
	Status      string
	Available   string
	Origin      string

	Score struct {
		Id     string
		Value  int
		Type   int
		Vector string
		Source string
	}
}

// GetVulnCompactReport fetches the compact vuln report for a given asset
func (c *MondooClient) GetVulnCompactReport(mrn string) (*VulnReport, error) {
	var m struct {
		AssetVulnerabilityReportResponse struct {
			AssetVulnerabilityCompactReport struct {
				AssetMrn   string
				Advisories []struct {
					Advisory
				}
				Cves []struct {
					Cve
				}
				Packages []struct {
					Package
				}
				Stats ReportStats
			} `graphql:"... on AssetVulnerabilityCompactReport"`
		} `graphql:"assetVulnerabilityCompactReport(input: $input)"`
	}
	err := c.Query(context.Background(), &m, map[string]any{"input": mondoogql.AssetVulnerabilityReportInput{AssetMrn: mondoogql.String(mrn)}})
	if err != nil {
		return nil, err
	}

	gqlVulnReport := &VulnReport{
		AssetMrn:   m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.AssetMrn,
		Advisories: make([]*Advisory, len(m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Advisories)),
		Cves:       make([]*Cve, len(m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Cves)),
		Packages:   make([]*Package, len(m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Packages)),
		Stats:      &m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Stats,
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Advisories {
		advisory := m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Advisories[i].Advisory
		gqlVulnReport.Advisories[i] = &advisory
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Cves {
		cve := m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Cves[i].Cve
		gqlVulnReport.Cves[i] = &cve
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Packages {
		pkg := m.AssetVulnerabilityReportResponse.AssetVulnerabilityCompactReport.Packages[i].Package
		gqlVulnReport.Packages[i] = &pkg
	}

	return gqlVulnReport, nil
}

// GetIncognitoVulnReport fetches the vuln report for an anonymous asset
// This is a special case were we don't have an MRN, like in cnspec shell
func (c *MondooClient) GetIncognitoVulnReport(platform mondoogql.PlatformInput, pkgs []mondoogql.PackageInput) (*VulnReport, error) {
	var m struct {
		AssetVulnerabilityReportResponse struct {
			AssetIncognitoVulnerabilityReport struct {
				Advisories []struct {
					Advisory
				}
				Cves []struct {
					Cve
				}
				Packages []struct {
					Package
				}
				Stats ReportStats
			} `graphql:"... on AssetIncognitoVulnerabilityReport"`
		} `graphql:"analyseIncognitoAssetVulnerabilities(input: $input)"`
	}
	gqlInput := mondoogql.AnalyseIncognitoAssetInput{
		Platform: platform,
		Packages: pkgs,
	}

	err := c.Query(context.Background(), &m, map[string]any{"input": gqlInput})
	if err != nil {
		return nil, err
	}

	gqlVulnReport := &VulnReport{
		Advisories: make([]*Advisory, len(m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Advisories)),
		Cves:       make([]*Cve, len(m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Cves)),
		Packages:   make([]*Package, len(m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Packages)),
		Stats:      &m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Stats,
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Advisories {
		advisory := m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Advisories[i].Advisory
		gqlVulnReport.Advisories[i] = &advisory
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Cves {
		cve := m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Cves[i].Cve
		gqlVulnReport.Cves[i] = &cve
	}

	for i := range m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Packages {
		pkg := m.AssetVulnerabilityReportResponse.AssetIncognitoVulnerabilityReport.Packages[i].Package
		gqlVulnReport.Packages[i] = &pkg
	}

	return gqlVulnReport, nil
}
