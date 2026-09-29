// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"

	cdn "github.com/stackitcloud/stackit-sdk-go/services/cdn/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// cdnPageSize is the largest page ListDistributions accepts.
const cdnPageSize = 100

func (r *mqlStackitCdn) id() (string, error) {
	return "stackit.cdn/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackit) cdn() (*mqlStackitCdn, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.cdn")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitCdn), nil
}

type mqlStackitCdnDistributionInternal struct {
	// cacheDomains holds the domains the distribution listing carried.
	cacheDomains []cdn.Domain
}

// listAllCdnDistributions walks every page of ListDistributions. fetch is the
// single-page call, taking the page identifier ("" for the first page), so
// the walk can be tested without the API.
func listAllCdnDistributions(fetch func(page string) (*cdn.ListDistributionsResponse, error)) ([]cdn.Distribution, error) {
	var out []cdn.Distribution
	page := ""
	seen := map[string]bool{}
	for {
		resp, err := fetch(page)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return out, nil
		}
		out = append(out, resp.GetDistributions()...)
		next, ok := resp.GetNextPageIdentifierOk()
		if !ok || next == nil || *next == "" || seen[*next] {
			return out, nil
		}
		seen[*next] = true
		page = *next
	}
}

func (r *mqlStackitCdn) distributions() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.CDN()
	if err != nil {
		return nil, err
	}
	items, err := listAllCdnDistributions(func(page string) (*cdn.ListDistributionsResponse, error) {
		req := client.DefaultAPI.ListDistributions(bgctx(), c.ProjectID()).PageSize(cdnPageSize)
		if page != "" {
			req = req.PageIdentifier(page)
		}
		return req.Execute()
	})
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		// The CDN API answers 404 for a project that never enabled the service.
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.cdn.distribution", cdnDistributionArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		d := res.(*mqlStackitCdnDistribution)
		d.cacheDomains = items[i].GetDomains()
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitCdnDistribution) id() (string, error) {
	return "stackit.cdn.distribution/" + r.Id.Data, nil
}

// statusErrors reduces the service's status errors to their English text.
func statusErrors(in []cdn.StatusError) []any {
	out := make([]any, 0, len(in))
	for i := range in {
		if msg := in[i].GetEn(); msg != "" {
			out = append(out, msg)
		}
	}
	return out
}

// cdnDistributionArgs maps a distribution onto stackit.cdn.distribution.
//
// The HTTP origin's request headers are reduced to their names on purpose:
// the values are commonly a shared secret the origin uses to recognize the
// CDN. The log sink is reduced to its kind and push URL; its credentials are
// not part of the listing and would not be mapped if they were.
func cdnDistributionArgs(d *cdn.Distribution) map[string]*llx.RawData {
	cfg := d.GetConfig()

	var backendType, originUrl, bucketUrl, bucketRegion string
	headerNames := []any{}
	backend := cfg.GetBackend()
	switch {
	case backend.HttpBackend != nil:
		backendType = string(backend.HttpBackend.GetType())
		originUrl = backend.HttpBackend.GetOriginUrl()
		names := make([]string, 0, len(backend.HttpBackend.GetOriginRequestHeaders()))
		for name := range backend.HttpBackend.GetOriginRequestHeaders() {
			names = append(names, name)
		}
		slices.Sort(names)
		headerNames = strSlice(names)
	case backend.BucketBackend != nil:
		backendType = string(backend.BucketBackend.GetType())
		bucketUrl = backend.BucketBackend.GetBucketUrl()
		bucketRegion = backend.BucketBackend.GetRegion()
	}

	var sinkType, sinkUrl string
	if sink, ok := cfg.GetLogSinkOk(); ok && sink != nil {
		switch {
		case sink.LokiLogSink != nil:
			sinkType = string(sink.LokiLogSink.GetType())
			sinkUrl = sink.LokiLogSink.GetPushUrl()
		case sink.OtlpLogSink != nil:
			sinkType = string(sink.OtlpLogSink.GetType())
			sinkUrl = sink.OtlpLogSink.GetPushUrl()
		}
	}

	waf := cfg.GetWaf()
	var paranoia *string
	if p, ok := waf.GetParanoiaLevelOk(); ok && p != nil {
		s := string(*p)
		paranoia = &s
	}

	var limit *int64
	if v, ok := cfg.GetMonthlyLimitBytesOk(); ok && v != nil {
		limit = v
	}

	regions := make([]any, 0, len(cfg.GetRegions()))
	for _, reg := range cfg.GetRegions() {
		regions = append(regions, string(reg))
	}

	tls := cfg.GetTls()
	return map[string]*llx.RawData{
		"id":                           llx.StringData(d.GetId()),
		"status":                       llx.StringData(string(d.GetStatus())),
		"createdAt":                    llx.TimeDataPtr(timeOrNil(d.GetCreatedAtOk())),
		"updatedAt":                    llx.TimeDataPtr(timeOrNil(d.GetUpdatedAtOk())),
		"errors":                       llx.ArrayData(statusErrors(d.GetErrors()), types.String),
		"labels":                       stringMapData(cfg.GetLabels()),
		"backendType":                  llx.StringData(backendType),
		"originUrl":                    llx.StringData(originUrl),
		"originRequestHeaderNames":     llx.ArrayData(headerNames, types.String),
		"bucketUrl":                    llx.StringData(bucketUrl),
		"bucketRegion":                 llx.StringData(bucketRegion),
		"tls10Enabled":                 llx.BoolData(tls.GetEnableTls10()),
		"tls11Enabled":                 llx.BoolData(tls.GetEnableTls11()),
		"wafMode":                      llx.StringData(string(waf.GetMode())),
		"wafType":                      llx.StringData(string(waf.GetType())),
		"wafParanoiaLevel":             llx.StringDataPtr(paranoia),
		"wafDisabledRuleIds":           strSliceData(waf.GetDisabledRuleIds()),
		"wafDisabledRuleGroupIds":      strSliceData(waf.GetDisabledRuleGroupIds()),
		"wafDisabledRuleCollectionIds": strSliceData(waf.GetDisabledRuleCollectionIds()),
		"wafLogOnlyRuleIds":            strSliceData(waf.GetLogOnlyRuleIds()),
		"wafAllowedHttpMethods":        strSliceData(waf.GetAllowedHttpMethods()),
		"blockedCountries":             strSliceData(cfg.GetBlockedCountries()),
		"blockedIps":                   strSliceData(cfg.GetBlockedIps()),
		"regions":                      llx.ArrayData(regions, types.String),
		"logSinkType":                  llx.StringData(sinkType),
		"logSinkPushUrl":               llx.StringData(sinkUrl),
		"forwardHostHeader":            llx.BoolData(cfg.GetForwardHostHeader()),
		"monthlyLimitBytes":            llx.IntDataPtr(limit),
	}
}

func (r *mqlStackitCdnDistribution) domains() ([]any, error) {
	out := make([]any, 0, len(r.cacheDomains))
	for i := range r.cacheDomains {
		d := &r.cacheDomains[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.cdn.distribution.domain", map[string]*llx.RawData{
			"__id":            llx.StringData(qualifiedId("stackit.cdn.distribution.domain", r.Id.Data, d.GetName())),
			"name":            llx.StringData(d.GetName()),
			"type":            llx.StringData(string(d.GetType())),
			"status":          llx.StringData(string(d.GetStatus())),
			"certificateType": llx.StringData(string(d.GetCertificateType())),
			"errors":          llx.ArrayData(statusErrors(d.GetErrors()), types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
