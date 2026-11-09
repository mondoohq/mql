// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/athena"
	athena_types "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsAthena) systemTableConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}

	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("athena>getSystemTableConfiguration>calling aws with region %s", region)
			svc := conn.Athena(region)
			resp, err := svc.GetSystemTableConfiguration(context.Background(), &athena.GetSystemTableConfigurationInput{
				TableName: athena_types.SystemTableNameAll,
			})
			if err != nil && !athenaSystemTablesNotConfigured(err) {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return nil, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Warn().Str("region", region).Msg("Athena system tables are not available in region")
					return nil, nil
				}
				return nil, err
			}
			if err != nil {
				// No configuration means system tables are off in this region.
				resp = nil
			}
			res, err := newMqlAwsAthenaSystemTableConfiguration(a.MqlRuntime, conn.AccountId(), region, resp)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult([]any{res}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}

	poolOfJobs := jobpool.CreatePool(tasks, 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	res := []any{}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

// athenaSystemTablesNotConfigured reports whether GetSystemTableConfiguration
// failed because the account has no system tables configuration in the region,
// which the API documents as a ResourceNotFoundException.
func athenaSystemTablesNotConfigured(err error) bool {
	var nf *athena_types.ResourceNotFoundException
	return errors.As(err, &nf)
}

func newMqlAwsAthenaSystemTableConfiguration(runtime *plugin.Runtime, accountID, region string, cfg *athena.GetSystemTableConfigurationOutput) (*mqlAwsAthenaSystemTableConfiguration, error) {
	args := map[string]*llx.RawData{
		"__id":           llx.StringData("aws.athena.systemTableConfiguration/" + accountID + "/" + region),
		"region":         llx.StringData(region),
		"enabled":        llx.BoolData(cfg != nil),
		"createdAt":      llx.NilData,
		"lastModifiedAt": llx.NilData,
	}
	kmsKeyArn := ""
	if cfg != nil {
		args["createdAt"] = llx.TimeDataPtr(cfg.CreatedAt)
		args["lastModifiedAt"] = llx.TimeDataPtr(cfg.LastModifiedAt)
		kmsKeyArn = convert.ToValue(cfg.KmsKeyArn)
	}
	res, err := CreateResource(runtime, "aws.athena.systemTableConfiguration", args)
	if err != nil {
		return nil, err
	}
	mqlCfg := res.(*mqlAwsAthenaSystemTableConfiguration)
	mqlCfg.cacheKmsKeyArn = kmsKeyArn
	return mqlCfg, nil
}

type mqlAwsAthenaSystemTableConfigurationInternal struct {
	cacheKmsKeyArn string
}

func (a *mqlAwsAthenaSystemTableConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn":    llx.StringData(a.cacheKmsKeyArn),
		"region": llx.StringData(a.Region.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsAthenaSystemTableConfiguration) tables() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Athena(a.Region.Data)
	ctx := context.Background()

	statuses := []athena_types.SystemTableStatus{}
	paginator := athena.NewListSystemTableStatusesPaginator(svc, &athena.ListSystemTableStatusesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, llx.Forbidden(err, llx.WithPermissions("athena:ListSystemTableStatuses"))
			}
			return nil, err
		}
		statuses = append(statuses, page.Items...)
	}
	return athenaSystemTableStatusMap(statuses), nil
}

// athenaSystemTableStatusMap keys each system table's enablement by its name.
// A status without an Enabled value is left out rather than reported as false.
func athenaSystemTableStatusMap(statuses []athena_types.SystemTableStatus) map[string]any {
	res := make(map[string]any, len(statuses))
	for _, s := range statuses {
		if s.TableName == "" || s.Enabled == nil {
			continue
		}
		res[string(s.TableName)] = *s.Enabled
	}
	return res
}
