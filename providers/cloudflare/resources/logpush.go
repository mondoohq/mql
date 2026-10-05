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

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.logpushJob", map[string]*llx.RawData{
			// Pass __id explicitly: id() derives it from zoneID, but zoneID is
			// set on the Internal struct only AFTER NewResource returns, so
			// relying on id() would key every job as `logpush@@<id>` (empty
			// zone). An explicit __id is honored ahead of id().
			"__id":                llx.StringData(fmt.Sprintf("logpush@%s@%d", c.Id.Data, rec.ID)),
			"id":                  llx.IntData(rec.ID),
			"name":                llx.StringData(rec.Name),
			"dataset":             llx.StringData(rec.Dataset),
			"logpullOptions":      llx.StringData(rec.LogpullOptions),
			"destinationConf":     llx.StringData(rec.DestinationConf),
			"frequency":           llx.StringData(rec.Frequency),
			"errorMessage":        llx.StringData(rec.ErrorMessage),
			"enabled":             llx.BoolData(rec.Enabled),
			"lastComplete":        timeOrNil(rec.LastComplete),
			"lastError":           timeOrNil(rec.LastError),
			"filterAttackTraffic": llx.BoolDataPtr(rec.FilterAttackTraffic),
		})
		if err != nil {
			return nil, err
		}

		mqlJob := res.(*mqlCloudflareZoneLogpushJob)
		mqlJob.zoneID = c.Id.Data

		result = append(result, res)
	}

	return result, nil
}
