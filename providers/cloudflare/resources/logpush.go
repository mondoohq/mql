// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

type mqlCloudflareZoneLogpushJobInternal struct {
	zoneID string
}

func (c *mqlCloudflareZoneLogpushJob) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return fmt.Sprintf("logpush@%s@%d", c.zoneID, c.Id.Data), nil
}

// logpushJob is the response shape of the zone logpush-jobs endpoint. We read it
// via the client's generic Get rather than the typed service because
// cloudflare-go marks the logpull_options and frequency fields deprecated on
// its typed struct; decoding the raw payload keeps those values available
// without referencing deprecated SDK symbols.
type logpushJob struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Dataset         string    `json:"dataset"`
	LogpullOptions  string    `json:"logpull_options"`
	DestinationConf string    `json:"destination_conf"`
	Frequency       string    `json:"frequency"`
	ErrorMessage    string    `json:"error_message"`
	Enabled         bool      `json:"enabled"`
	LastComplete    time.Time `json:"last_complete"`
	LastError       time.Time `json:"last_error"`
	// FilterAttackTraffic is nil when the job does not report the setting.
	FilterAttackTraffic *bool `json:"filter_attack_traffic"`
	// Kind is nil when the job does not report it.
	Kind *string `json:"kind"`
	// OutputOptions is nil when the job has no output options.
	OutputOptions *logpushOutputOptions `json:"output_options"`
}

// logpushOutputOptions holds the output options the schema exposes. Each value
// is nil when the job does not set it.
type logpushOutputOptions struct {
	SampleRate *float64 `json:"sample_rate"`
	FieldNames []string `json:"field_names"`
	// Cve2021_44228 is the API's switch for redacting Log4Shell JNDI patterns.
	Cve2021_44228 *bool `json:"CVE-2021-44228"`
}

// outputArgs maps a job's output options onto resource fields, all null when
// the job has none.
func (o *logpushOutputOptions) outputArgs() map[string]*llx.RawData {
	if o == nil {
		return map[string]*llx.RawData{
			"sampleRate":           llx.NilData,
			"fieldNames":           llx.NilData,
			"redactsLog4jPatterns": llx.NilData,
		}
	}
	sampleRate := llx.NilData
	if o.SampleRate != nil {
		sampleRate = llx.FloatData(*o.SampleRate)
	}
	return map[string]*llx.RawData{
		"sampleRate":           sampleRate,
		"fieldNames":           stringSliceOrNil(o.FieldNames),
		"redactsLog4jPatterns": llx.BoolDataPtr(o.Cve2021_44228),
	}
}

func (c *mqlCloudflareZone) logpushJobs() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result []logpushJob `json:"result"`
	}
	uri := fmt.Sprintf("zones/%s/logpush/jobs", c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		return nil, err
	}

	var result []any
	for i := range env.Result {
		rec := env.Result[i]

		args := rec.OutputOptions.outputArgs()
		// Pass __id explicitly: id() derives it from zoneID, but zoneID is
		// set on the Internal struct only AFTER NewResource returns, so
		// relying on id() would key every job as `logpush@@<id>` (empty
		// zone). An explicit __id is honored ahead of id().
		args["__id"] = llx.StringData(fmt.Sprintf("logpush@%s@%d", c.Id.Data, rec.ID))
		args["id"] = llx.IntData(rec.ID)
		args["name"] = llx.StringData(rec.Name)
		args["dataset"] = llx.StringData(rec.Dataset)
		args["logpullOptions"] = llx.StringData(rec.LogpullOptions)
		args["destinationConf"] = llx.StringData(rec.DestinationConf)
		args["frequency"] = llx.StringData(rec.Frequency)
		args["errorMessage"] = llx.StringData(rec.ErrorMessage)
		args["enabled"] = llx.BoolData(rec.Enabled)
		args["lastComplete"] = timeOrNil(rec.LastComplete)
		args["lastError"] = timeOrNil(rec.LastError)
		args["filterAttackTraffic"] = llx.BoolDataPtr(rec.FilterAttackTraffic)
		args["kind"] = llx.StringDataPtr(rec.Kind)

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.logpushJob", args)
		if err != nil {
			return nil, err
		}

		mqlJob := res.(*mqlCloudflareZoneLogpushJob)
		mqlJob.zoneID = c.Id.Data

		result = append(result, res)
	}

	return result, nil
}
