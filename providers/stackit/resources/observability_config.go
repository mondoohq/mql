// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// Scrape jobs and retention settings of an Observability instance.

func (r *mqlStackitObservabilityInstance) scrapeConfigs() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListScrapeConfigs(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	jobs := resp.GetData()
	out := make([]any, 0, len(jobs))
	for i := range jobs {
		res, err := CreateResource(r.MqlRuntime, "stackit.observability.scrapeConfig", scrapeConfigArgs(r.Id.Data, &jobs[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// scrapeConfigArgs maps a scrape job. The job's basic-auth password, bearer
// token, and OAuth client secret are deliberately not mapped: only whether
// each mechanism is configured. The job's query params are left out too, since
// exporters commonly take credentials there.
func scrapeConfigArgs(instanceID string, job *observability.Job) map[string]*llx.RawData {
	var scheme *string
	if s, ok := job.GetSchemeOk(); ok && s != nil {
		v := string(*s)
		scheme = &v
	}
	var sampleLimit *int64
	if v, ok := job.GetSampleLimitOk(); ok && v != nil {
		n := int64(*v)
		sampleLimit = &n
	}
	var insecure *bool
	if tls, ok := job.GetTlsConfigOk(); ok && tls != nil {
		insecure = optBool(tls.GetInsecureSkipVerifyOk())
	}
	_, basicAuth := job.GetBasicAuthOk()
	bearer, bearerOk := job.GetBearerTokenOk()
	_, oauth2 := job.GetOauth2Ok()

	targets := []any{}
	for _, sc := range job.GetStaticConfigs() {
		for _, t := range sc.GetTargets() {
			targets = append(targets, t)
		}
	}
	sdUrls := []any{}
	for _, sd := range job.GetHttpSdConfigs() {
		if u := sd.GetUrl(); u != "" {
			sdUrls = append(sdUrls, u)
		}
	}

	return map[string]*llx.RawData{
		"__id":                  llx.StringData(qualifiedId("stackit.observability.scrapeConfig", instanceID, job.GetJobName())),
		"jobName":               llx.StringData(job.GetJobName()),
		"scheme":                llx.StringDataPtr(scheme),
		"metricsPath":           llx.StringDataPtr(strOrNil(job.GetMetricsPathOk())),
		"scrapeInterval":        llx.StringData(job.GetScrapeInterval()),
		"scrapeTimeout":         llx.StringData(job.GetScrapeTimeout()),
		"sampleLimit":           llx.IntDataPtr(sampleLimit),
		"honorLabels":           llx.BoolDataPtr(optBool(job.GetHonorLabelsOk())),
		"honorTimestamps":       llx.BoolDataPtr(optBool(job.GetHonorTimeStampsOk())),
		"insecureSkipVerify":    llx.BoolDataPtr(insecure),
		"basicAuthConfigured":   llx.BoolData(basicAuth),
		"bearerTokenConfigured": llx.BoolData(bearerOk && bearer != nil && *bearer != ""),
		"oauth2Configured":      llx.BoolData(oauth2),
		"targets":               llx.ArrayData(targets, types.String),
		"serviceDiscoveryUrls":  llx.ArrayData(sdUrls, types.String),
	}
}

// fetchRetention reads the metrics retention settings once for the three
// retention fields.
func (r *mqlStackitObservabilityInstance) fetchRetention() (*observability.GetMetricsStorageRetentionResponse, error) {
	if r.retentionFetched.Load() {
		return r.retention, nil
	}
	r.retentionLock.Lock()
	defer r.retentionLock.Unlock()
	if r.retentionFetched.Load() {
		return r.retention, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetMetricsStorageRetention(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.retentionFetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.retention = resp
	r.retentionFetched.Store(true)
	return r.retention, nil
}

// retentionValue reads one retention setting, null when the settings could
// not be read or carry no value.
func retentionValue(v string, field *plugin.TValue[string]) (string, error) {
	if v == "" {
		return nullString(field)
	}
	return v, nil
}

func (r *mqlStackitObservabilityInstance) metricsRetentionRaw() (string, error) {
	ret, err := r.fetchRetention()
	if err != nil {
		return "", err
	}
	if ret == nil {
		return nullString(&r.MetricsRetentionRaw)
	}
	return retentionValue(ret.GetMetricsRetentionTimeRaw(), &r.MetricsRetentionRaw)
}

func (r *mqlStackitObservabilityInstance) metricsRetention5m() (string, error) {
	ret, err := r.fetchRetention()
	if err != nil {
		return "", err
	}
	if ret == nil {
		return nullString(&r.MetricsRetention5m)
	}
	return retentionValue(ret.GetMetricsRetentionTime5m(), &r.MetricsRetention5m)
}

func (r *mqlStackitObservabilityInstance) metricsRetention1h() (string, error) {
	ret, err := r.fetchRetention()
	if err != nil {
		return "", err
	}
	if ret == nil {
		return nullString(&r.MetricsRetention1h)
	}
	return retentionValue(ret.GetMetricsRetentionTime1h(), &r.MetricsRetention1h)
}

func (r *mqlStackitObservabilityInstance) logsRetention() (string, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return "", err
	}
	resp, err := client.DefaultAPI.GetLogsConfigs(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return nullString(&r.LogsRetention)
			}
			return "", refusal(err)
		}
		return "", err
	}
	if resp == nil {
		return nullString(&r.LogsRetention)
	}
	cfg := resp.GetConfig()
	return retentionValue(cfg.GetRetention(), &r.LogsRetention)
}

func (r *mqlStackitObservabilityInstance) tracesRetention() (string, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Observability()
	if err != nil {
		return "", err
	}
	resp, err := client.DefaultAPI.GetTracesConfigs(bgctx(), r.Id.Data, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return nullString(&r.TracesRetention)
			}
			return "", refusal(err)
		}
		return "", err
	}
	if resp == nil {
		return nullString(&r.TracesRetention)
	}
	cfg := resp.GetConfig()
	return retentionValue(cfg.GetRetention(), &r.TracesRetention)
}
