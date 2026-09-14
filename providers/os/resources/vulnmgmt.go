// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/gql"
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
		mondooClient, err = gql.NewClient(&mcc.UpstreamConfig, mcc.HttpClient)
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

	var lastUpdateTime *time.Time
	if lastUpdate != "" {
		parsedLastUpdateTime, err := time.Parse(time.RFC3339, lastUpdate)
		if err != nil {
			return nil, errors.New("could not parse last update time: " + lastUpdate)
		}
		lastUpdateTime = &parsedLastUpdateTime
	} else {
		lastUpdateTime = &llx.NeverFutureTime
	}

	return lastUpdateTime, nil
}

func (v *mqlVulnmgmt) cves() ([]any, error) {
	// see command resource for reference
	// we ignore the return value because everything is set in populateData
	// `plugin.StateIsSet` is used to indicate that the data is available
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
	// see command resource for reference
	// we ignore the return value because everything is set in populateData
	// `plugin.StateIsSet` is used to indicate that the data is available
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) packages() ([]any, error) {
	// see command resource for reference
	// we ignore the return value because everything is set in populateData
	// `plugin.StateIsSet` is used to indicate that the data is available
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) stats() (*mqlAuditCvss, error) {
	// see command resource for reference
	// we ignore the return value because everything is set in populateData
	// `plugin.StateIsSet` is used to indicate that the data is available
	return nil, v.populateData()
}

func (v *mqlVulnmgmt) populateData() error {
	mcc := v.MqlRuntime.Upstream
	if mcc == nil || mcc.ApiEndpoint == "" {
		v.setUnavailableData(resources.MissingUpstreamError{})
		return nil
	}

	// Incognito assets (no asset MRN, e.g. `cnspec shell`) build their package
	// inventory locally. Scan that inventory as a PURL-native SBOM through the
	// uploaded-SBOM vulnerability path and map the returned VEX onto the same
	// vuln.* resources, so policies and the shell keep resolving — now sourced
	// from package URLs.
	//
	// Managed assets keep using the compact report for now: that report is
	// matched against the platform's own stored inventory for the asset, so
	// sending a locally-built SBOM instead would change which packages are
	// matched — and therefore the asset's score. Converting the managed path is
	// deliberately left as follow-up work.
	// TODO: move managed assets onto the uploaded-SBOM path once the scoring
	// impact of matching a locally-built inventory has been validated.
	if mcc.AssetMrn == "" {
		vex, err := v.getVexReport()
		if err != nil {
			v.setUnavailableData(err)
			return nil
		}
		// A mapping error can leave the vuln.* fields half-populated; fall back
		// to the empty, set-but-unavailable state so the resource stays
		// consistent rather than surfacing a partial report (matching every
		// other error path here).
		if err := v.populateFromVex(vex); err != nil {
			v.setUnavailableData(err)
			return nil
		}
		return nil
	}

	vulnReport, err := v.getReport()
	if err != nil {
		v.setUnavailableData(err)
		return nil
	}
	if err := v.populateFromReport(vulnReport); err != nil {
		v.setUnavailableData(err)
		return nil
	}
	return nil
}

func (v *mqlVulnmgmt) populateFromReport(vulnReport *gql.VulnReport) error {
	mqlVulAdvisories := make([]any, len(vulnReport.Advisories))
	for i, a := range vulnReport.Advisories {
		var parsedPublished *time.Time
		var parsedModified *time.Time
		var err error
		published, err := time.Parse(time.RFC3339, a.PublishedAt)
		if err != nil {
			log.Debug().Str("date", a.PublishedAt).Str("advisory", a.Id).Msg("could not parse published date")
		} else {
			parsedPublished = &published
		}
		modified, err := time.Parse(time.RFC3339, a.ModifiedAt)
		if err != nil {
			log.Debug().Str("date", a.ModifiedAt).Str("advisory", a.Id).Msg("could not parse modified date")
		} else {
			parsedModified = &modified
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
			"published":   llx.TimeDataPtr(parsedPublished),
			"modified":    llx.TimeDataPtr(parsedModified),
			"worstScore":  llx.ResourceData(cvssScore, "audit.cvss"),
		})
		if err != nil {
			return err
		}
		mqlVulAdvisories[i] = mqlVulnAdvisory
	}

	mqlVulnCves := make([]any, len(vulnReport.Cves))
	for i, c := range vulnReport.Cves {
		var parsedPublished *time.Time
		var parsedModified *time.Time
		var err error
		published, err := time.Parse(time.RFC3339, c.PublishedAt)
		if err != nil {
			log.Debug().Str("date", c.PublishedAt).Str("cve", c.Id).Msg("could not parse published date")
		} else {
			parsedPublished = &published
		}
		modified, err := time.Parse(time.RFC3339, c.ModifiedAt)
		if err != nil {
			log.Debug().Str("date", c.ModifiedAt).Str("cve", c.Id).Msg("could not parse modified date")
		} else {
			parsedModified = &modified
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
			"state":      llx.StringData(c.State),
			"summary":    llx.StringData(c.Summary),
			"published":  llx.TimeDataPtr(parsedPublished),
			"modified":   llx.TimeDataPtr(parsedModified),
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
		mondooClient, err = gql.NewClient(&mcc.UpstreamConfig, mcc.HttpClient)
		if err != nil {
			return nil, err
		}
		v.gqlClient = mondooClient
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

func (a *mqlVulnAdvisory) id() (string, error) {
	return a.Id.Data, a.Id.Error
}

func (c *mqlVulnCve) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (p *mqlVulnPackage) id() (string, error) {
	id := p.Name.Data + "-" + p.Version.Data
	return id, p.Name.Error
}
