// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isControlTowerNotConfiguredError returns true if the error indicates that
// Control Tower is not set up in this account (e.g., missing AWSControlTowerAdmin role).
func isControlTowerNotConfiguredError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "AWSControlTowerAdmin")
}

func (a *mqlAwsControltower) id() (string, error) {
	return "aws.controltower", nil
}

// --- Landing Zones ---

func (a *mqlAwsControltower) landingZones() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	// An account has at most one landing zone, and the ListLandingZones API
	// returns it regardless of which region is queried. Use the default
	// region to avoid redundant calls across every enabled region.
	svc := conn.Controltower("")
	ctx := context.Background()
	res := []any{}

	paginator := controltower.NewListLandingZonesPaginator(svc, &controltower.ListLandingZonesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isControlTowerNotConfiguredError(err) {
				log.Debug().Msg("control tower is not configured in this account")
				return nil, nil
			}
			return nil, classifyAwsError(err, "controltower:ListLandingZones")
		}

		for _, lz := range page.LandingZones {
			mqlLZ, err := CreateResource(a.MqlRuntime, "aws.controltower.landingZone",
				map[string]*llx.RawData{
					"__id":   llx.StringDataPtr(lz.Arn),
					"arn":    llx.StringDataPtr(lz.Arn),
					"region": llx.StringData(conn.Region()),
				})
			if err != nil {
				return nil, err
			}
			mqlLZRes := mqlLZ.(*mqlAwsControltowerLandingZone)
			mqlLZRes.cacheRegion = conn.Region()
			res = append(res, mqlLZ)
		}
	}
	return res, nil
}

type mqlAwsControltowerLandingZoneInternal struct {
	cacheRegion string
	fetched     bool
	lock        sync.Mutex
	detail      *controltower.GetLandingZoneOutput
}

func (a *mqlAwsControltowerLandingZone) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsControltowerLandingZone) fetchDetail() (*controltower.GetLandingZoneOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Controltower(a.cacheRegion)
	ctx := context.Background()

	arn := a.Arn.Data
	resp, err := svc.GetLandingZone(ctx, &controltower.GetLandingZoneInput{
		LandingZoneIdentifier: &arn,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.LandingZone == nil {
		return nil, fmt.Errorf("get landing zone returned empty response for %q", arn)
	}
	a.fetched = true
	a.detail = resp
	return resp, nil
}

func (a *mqlAwsControltowerLandingZone) version() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.LandingZone.Version), nil
}

func (a *mqlAwsControltowerLandingZone) latestAvailableVersion() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.LandingZone.LatestAvailableVersion), nil
}

func (a *mqlAwsControltowerLandingZone) driftStatus() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.LandingZone.DriftStatus != nil {
		return string(resp.LandingZone.DriftStatus.Status), nil
	}
	return "", nil
}

func (a *mqlAwsControltowerLandingZone) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.LandingZone.Status), nil
}

// --- Enabled Baselines ---

func (a *mqlAwsControltower) enabledBaselines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEnabledBaselines(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsControltower) getEnabledBaselines(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Controltower(region)
			ctx := context.Background()
			res := []any{}

			paginator := controltower.NewListEnabledBaselinesPaginator(svc, &controltower.ListEnabledBaselinesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("control tower is not available in region")
						return res, nil
					}
					if isControlTowerNotConfiguredError(err) {
						log.Debug().Str("region", region).Msg("control tower is not configured in this account")
						return res, nil
					}
					return nil, err
				}

				for _, eb := range page.EnabledBaselines {
					var status string
					if eb.StatusSummary != nil {
						status = string(eb.StatusSummary.Status)
					}
					driftStatus, _ := convert.JsonToDict(eb.DriftStatusSummary)

					mqlEB, err := CreateResource(a.MqlRuntime, "aws.controltower.enabledBaseline",
						map[string]*llx.RawData{
							"__id":               llx.StringDataPtr(eb.Arn),
							"arn":                llx.StringDataPtr(eb.Arn),
							"region":             llx.StringData(region),
							"baselineIdentifier": llx.StringDataPtr(eb.BaselineIdentifier),
							"targetIdentifier":   llx.StringDataPtr(eb.TargetIdentifier),
							"baselineVersion":    llx.StringDataPtr(eb.BaselineVersion),
							"status":             llx.StringData(status),
							"driftStatus":        llx.DictData(driftStatus),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEB)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsControltowerEnabledBaseline) id() (string, error) {
	return a.Arn.Data, nil
}
