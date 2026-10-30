// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

func parseScanTime(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

func (r *mqlDigitaloceanSecurityScan) id() (string, error) {
	return "digitalocean.securityScan/" + r.Id.Data, nil
}

func newMqlSecurityScan(runtime *plugin.Runtime, scan *godo.Scan) (*mqlDigitaloceanSecurityScan, error) {
	if scan == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "digitalocean.securityScan", map[string]*llx.RawData{
		"id":        llx.StringData(scan.ID),
		"status":    llx.StringData(scan.Status),
		"createdAt": llx.TimeDataPtr(parseScanTime(scan.CreatedAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanSecurityScan), nil
}

func (r *mqlDigitalocean) securityScans() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []any
	opt := &godo.ListOptions{PerPage: 200}
	for {
		scans, resp, err := client.Security.ListScans(context.Background(), opt)
		if err != nil {
			// CSPM scan endpoints 404 on accounts that have never run a scan;
			// treat that as an empty list rather than failing (mirrors the
			// container-registry accessors).
			if isDoNotFound(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, s := range scans {
			res, err := newMqlSecurityScan(r.MqlRuntime, s)
			if err != nil {
				return nil, err
			}
			if res != nil {
				all = append(all, res)
			}
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

func (r *mqlDigitalocean) latestSecurityScan() (*mqlDigitaloceanSecurityScan, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	scan, _, err := client.Security.GetLatestScan(context.Background(), nil)
	if err != nil {
		// 404 when no scan has ever run; return a null field rather than error.
		if isDoNotFound(err) {
			r.LatestSecurityScan.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if scan == nil {
		r.LatestSecurityScan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlSecurityScan(r.MqlRuntime, scan)
}

// findings fetches the scan's findings via GetScan. The scan list API
// returns scans without findings, so they are loaded on demand here.
func (r *mqlDigitaloceanSecurityScan) findings() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	// GetScan decodes into a struct that carries no pagination links, so
	// godo never populates resp.Links for this endpoint (unlike ListScans).
	// Drive pagination off the returned page size instead: keep advancing
	// while a full page comes back, bounded by maxPages so a misbehaving
	// cursor can't hang the scan.
	const perPage = 200
	const maxPages = 1000
	var all []any
	opt := &godo.ScanFindingsOptions{PerPage: perPage, Page: 1}
	for range maxPages {
		scan, _, err := client.Security.GetScan(context.Background(), r.Id.Data, opt)
		if err != nil {
			return nil, err
		}
		if scan == nil {
			break
		}
		for _, f := range scan.Findings {
			if f == nil {
				continue
			}
			mqlFinding, err := r.newFinding(f)
			if err != nil {
				return nil, err
			}
			all = append(all, mqlFinding)
		}
		if len(scan.Findings) < perPage {
			break
		}
		opt.Page++
	}
	return all, nil
}

type mqlDigitaloceanSecurityScanFindingInternal struct {
	scanUUID string
}

func (r *mqlDigitaloceanSecurityScan) newFinding(f *godo.ScanFinding) (*mqlDigitaloceanSecurityScanFinding, error) {
	steps := make([]any, 0, len(f.MitigationSteps))
	for _, s := range f.MitigationSteps {
		if s == nil {
			continue
		}
		steps = append(steps, map[string]any{
			"step":        int64(s.Step),
			"title":       s.Title,
			"description": s.Description,
		})
	}
	res, err := CreateResource(r.MqlRuntime, "digitalocean.securityScan.finding", map[string]*llx.RawData{
		"__id":                   llx.StringData(r.Id.Data + "/" + f.RuleUUID),
		"ruleUuid":               llx.StringData(f.RuleUUID),
		"name":                   llx.StringData(f.Name),
		"severity":               llx.StringData(f.Severity),
		"businessImpact":         llx.StringData(f.BusinessImpact),
		"details":                llx.StringData(f.Details),
		"technicalDetails":       llx.StringData(f.TechnicalDetails),
		"foundAt":                llx.TimeDataPtr(parseScanTime(f.FoundAt)),
		"affectedResourcesCount": llx.IntData(int64(f.AffectedResourcesCount)),
		"mitigationSteps":        llx.ArrayData(steps, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	finding := res.(*mqlDigitaloceanSecurityScanFinding)
	finding.scanUUID = r.Id.Data
	return finding, nil
}

func (r *mqlDigitaloceanSecurityScanFinding) affectedResources() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	req := &godo.ListFindingAffectedResourcesRequest{
		ScanUUID:    r.scanUUID,
		FindingUUID: r.RuleUuid.Data,
	}

	var all []any
	opt := &godo.ListOptions{PerPage: 200}
	for {
		resources, resp, err := client.Security.ListFindingAffectedResources(context.Background(), req, opt)
		if err != nil {
			return nil, err
		}
		for _, a := range resources {
			if a == nil {
				continue
			}
			all = append(all, map[string]any{
				"urn":  a.URN,
				"name": a.Name,
				"type": a.Type,
			})
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}
