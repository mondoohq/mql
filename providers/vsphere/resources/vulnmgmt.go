// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/gql"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

type mqlVulnmgmtInternal struct {
	gqlClient         *gql.MondooClient
	warnedUnavailable bool
}

func (v *mqlVulnmgmt) lastAssessment() (*time.Time, error) {
	mcc := v.MqlRuntime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		return v.setUnavailableLastAssessment(resources.MissingUpstreamError{})
	}

	var mondooClient *gql.MondooClient
	var err error
	if v.gqlClient != nil {
		mondooClient = v.gqlClient
	} else {
		// get new gql client
		mondooClient, err = gql.NewClient(&mcc.UpstreamConfig, mcc.HttpClient, gql.WithProvider("vsphere"))
		if err != nil {
			return nil, err
		}
		v.gqlClient = mondooClient
	}

	if v.MqlRuntime.Upstream.AssetMrn == "" {
		return v.setUnavailableLastAssessment(errors.New("no asset mrn available"))
	}
	lastUpdate, err := mondooClient.LastAssessment(v.MqlRuntime.Upstream.AssetMrn)
	if err != nil {
		return v.setUnavailableLastAssessment(err)
	}

	log.Debug().Str("time", lastUpdate).Msg("search for package last update")
	if lastUpdate == "" {
		return v.setUnavailableLastAssessment(errors.New("no update time available"))
	}

	// lastUpdate is guaranteed non-empty here (the empty case returned above).
	parsedLastUpdateTime, err := time.Parse(time.RFC3339, lastUpdate)
	if err != nil {
		return nil, errors.New("could not parse last update time: " + lastUpdate)
	}

	return &parsedLastUpdateTime, nil
}

func (v *mqlVulnmgmt) cves() ([]any, error) {
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) warnUnavailable(err error) {
	if v.warnedUnavailable {
		return
	}

	v.warnedUnavailable = true
	log.Warn().Err(err).Msg("vulnmgmt unavailable, returning empty results")
}

func (v *mqlVulnmgmt) setUnavailableData(err error) {
	v.warnUnavailable(err)
	v.Advisories = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	v.Cves = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	v.Packages = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	v.Stats = plugin.TValue[*mqlAuditCvss]{State: plugin.StateIsSet | plugin.StateIsNull}
}

func (v *mqlVulnmgmt) setUnavailableLastAssessment(err error) (*time.Time, error) {
	v.warnUnavailable(err)
	v.LastAssessment = plugin.TValue[*time.Time]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil, nil
}

func (v *mqlVulnmgmt) advisories() ([]any, error) {
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) packages() ([]any, error) {
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) stats() (*mqlAuditCvss, error) {
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) populateData() error {
	vulnReport, err := v.getReport()
	if err != nil {
		v.setUnavailableData(err)
		return nil
	}

	mqlVulAdvisories := make([]any, len(vulnReport.Advisories))
	for i, a := range vulnReport.Advisories {
		parsedPublished, err := time.Parse(time.RFC3339, a.PublishedAt)
		if err != nil {
			return err
		}
		parsedModified, err := time.Parse(time.RFC3339, a.ModifiedAt)
		if err != nil {
			return err
		}
		id := fmt.Sprintf("%d-%s", a.CvssScore.Value, a.CvssScore.Vector)
		cvssScore, err := CreateResource(v.MqlRuntime, "audit.cvss", map[string]*llx.RawData{
			"__id":   llx.StringData(id),
			"score":  llx.FloatData(float64(a.CvssScore.Value) / 10),
			"vector": llx.StringData(a.CvssScore.Vector),
		})
		if err != nil {
			return err
		}
		mqlVulnAdvisory, err := CreateResource(v.MqlRuntime, "vuln.advisory", map[string]*llx.RawData{
			"id":          llx.StringData(a.Id),
			"title":       llx.StringData(a.Title),
			"description": llx.StringData(a.Description),
			"published":   llx.TimeData(parsedPublished),
			"modified":    llx.TimeData(parsedModified),
			"worstScore":  llx.ResourceData(cvssScore, "audit.cvss"),
		})
		if err != nil {
			return err
		}
		mqlVulAdvisories[i] = mqlVulnAdvisory
	}

	mqlVulnCves := make([]any, len(vulnReport.Cves))
	for i, c := range vulnReport.Cves {
		parsedPublished, err := time.Parse(time.RFC3339, c.PublishedAt)
		if err != nil {
			return err
		}
		parsedModified, err := time.Parse(time.RFC3339, c.ModifiedAt)
		if err != nil {
			return err
		}
		id := fmt.Sprintf("%d-%s", c.CvssScore.Value, c.CvssScore.Vector)
		cvssScore, err := CreateResource(v.MqlRuntime, "audit.cvss", map[string]*llx.RawData{
			"__id":   llx.StringData(id),
			"score":  llx.FloatData(float64(c.CvssScore.Value) / 10),
			"vector": llx.StringData(c.CvssScore.Vector),
		})
		if err != nil {
			return err
		}
		mqlVulnCve, err := CreateResource(v.MqlRuntime, "vuln.cve", map[string]*llx.RawData{
			"id":         llx.StringData(c.Id),
			"worstScore": llx.ResourceData(cvssScore, "audit.cvss"),
			"published":  llx.TimeData(parsedPublished),
			"modified":   llx.TimeData(parsedModified),
		})
		if err != nil {
			return err
		}
		mqlVulnCves[i] = mqlVulnCve
	}

	mqlVulnPackages := make([]any, len(vulnReport.Packages))
	for i, p := range vulnReport.Packages {
		mqlVulnPackage, err := CreateResource(v.MqlRuntime, "vuln.package", map[string]*llx.RawData{
			"name":      llx.StringData(p.Name),
			"version":   llx.StringData(p.Version),
			"available": llx.StringData(p.Available),
			"arch":      llx.StringData(p.Arch),
		})
		if err != nil {
			return err
		}
		mqlVulnPackages[i] = mqlVulnPackage
	}

	id := fmt.Sprintf("%d-%s", vulnReport.Stats.Score.Value, vulnReport.Stats.Score.Vector)
	res, err := CreateResource(v.MqlRuntime, "audit.cvss", map[string]*llx.RawData{
		"__id":   llx.StringData(id),
		"score":  llx.FloatData(float64(vulnReport.Stats.Score.Value) / 10),
		"vector": llx.StringData(vulnReport.Stats.Score.Vector),
	})
	if err != nil {
		return err
	}
	statsCvssScore := res.(*mqlAuditCvss)

	v.Advisories = plugin.TValue[[]any]{Data: mqlVulAdvisories, State: plugin.StateIsSet}
	v.Cves = plugin.TValue[[]any]{Data: mqlVulnCves, State: plugin.StateIsSet}
	v.Packages = plugin.TValue[[]any]{Data: mqlVulnPackages, State: plugin.StateIsSet}
	v.Stats = plugin.TValue[*mqlAuditCvss]{Data: statsCvssScore, State: plugin.StateIsSet}

	return nil
}

func (v *mqlVulnmgmt) getReport() (*gql.VulnReport, error) {
	mcc := v.MqlRuntime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		return nil, resources.MissingUpstreamError{}
	}

	var mondooClient *gql.MondooClient
	var err error
	if v.gqlClient != nil {
		mondooClient = v.gqlClient
	} else {
		// get new gql client
		mondooClient, err = gql.NewClient(&mcc.UpstreamConfig, mcc.HttpClient, gql.WithProvider("vsphere"))
		if err != nil {
			return nil, err
		}
		v.gqlClient = mondooClient
	}

	if v.MqlRuntime.Upstream.AssetMrn == "" {
		log.Debug().Msg("no asset mrn available")
		return v.getIncognitoReport(mondooClient)
	}
	gqlVulnReport, err := mondooClient.GetVulnCompactReport(v.MqlRuntime.Upstream.AssetMrn)
	if err != nil {
		return nil, err
	}

	log.Debug().Interface("gqlReport", gqlVulnReport).Msg("search for asset vuln report")
	if gqlVulnReport == nil {
		return nil, errors.New("no vulnerability report available")
	}

	return gqlVulnReport, nil
}

func (v *mqlVulnmgmt) getIncognitoReport(mondooClient *gql.MondooClient) (*gql.VulnReport, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	platform := conn.Asset().Platform

	gqlVulnReport, err := mondooClient.GetIncognitoVulnReport(mondoogql.PlatformInput{
		Name:    new(mondoogql.String(platform.Name)),
		Release: new(mondoogql.String(platform.Version)),
	}, []mondoogql.PackageInput{})
	if err != nil {
		return nil, err
	}

	log.Debug().Interface("gqlReport", gqlVulnReport).Msg("search for asset vuln report")
	if gqlVulnReport == nil {
		return nil, errors.New("no vulnerability report available")
	}

	return gqlVulnReport, nil
}

func (a *mqlVulnAdvisory) id() (string, error) {
	return a.Id.Data, a.Id.Error
}

func (c *mqlVulnCve) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// id keys each package by name+version. Without it every vuln.package would
// share the empty cache key "vuln.package\x00" and collapse onto the first
// package created (see mql CreateResource caching), so vulnmgmt.packages would
// report that one package once per row.
func (p *mqlVulnPackage) id() (string, error) {
	if err := p.Name.Error; err != nil {
		return "", err
	}
	if err := p.Version.Error; err != nil {
		return "", err
	}
	return p.Name.Data + "-" + p.Version.Data, nil
}
