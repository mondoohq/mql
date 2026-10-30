// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/securitylake"
	sltypes "github.com/aws/aws-sdk-go-v2/service/securitylake/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsSecuritylake) id() (string, error) {
	return "aws.securitylake", nil
}

func (a *mqlAwsSecuritylake) dataLakes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDataLakes(conn), 5)
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

func (a *mqlAwsSecuritylake) getDataLakes(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Securitylake(region)
			ctx := context.Background()
			res := []any{}

			// ListDataLakes is not paginated
			resp, err := svc.ListDataLakes(ctx, &securitylake.ListDataLakesInput{
				Regions: []string{region},
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("security lake is not available in region")
					return res, nil
				}
				return nil, err
			}

			for _, dl := range resp.DataLakes {
				mqlDL, err := newMqlSecuritylakeDataLake(a.MqlRuntime, dl)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlDL)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlSecuritylakeDataLake(runtime *plugin.Runtime, dl sltypes.DataLakeResource) (*mqlAwsSecuritylakeDataLake, error) {
	var lifecycleConfig any
	if dl.LifecycleConfiguration != nil {
		lifecycleConfig, _ = convert.JsonToDict(dl.LifecycleConfiguration)
	}
	var replicationConfig any
	if dl.ReplicationConfiguration != nil {
		replicationConfig, _ = convert.JsonToDict(dl.ReplicationConfiguration)
	}

	var kmsKeyId *string
	if dl.EncryptionConfiguration != nil {
		kmsKeyId = dl.EncryptionConfiguration.KmsKeyId
	}

	res, err := CreateResource(runtime, "aws.securitylake.dataLake",
		map[string]*llx.RawData{
			"__id":                     llx.StringDataPtr(dl.DataLakeArn),
			"dataLakeArn":              llx.StringDataPtr(dl.DataLakeArn),
			"region":                   llx.StringDataPtr(dl.Region),
			"createStatus":             llx.StringData(string(dl.CreateStatus)),
			"lifecycleConfiguration":   llx.DictData(lifecycleConfig),
			"replicationConfiguration": llx.DictData(replicationConfig),
		})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsSecuritylakeDataLake).cacheS3BucketArn = convert.ToValue(dl.S3BucketArn)
	mqlDL := res.(*mqlAwsSecuritylakeDataLake)
	mqlDL.cacheKmsKeyId = kmsKeyId
	return mqlDL, nil
}

type mqlAwsSecuritylakeDataLakeInternal struct {
	cacheS3BucketArn string
	cacheKmsKeyId    *string
}

func (a *mqlAwsSecuritylakeDataLake) id() (string, error) {
	return a.DataLakeArn.Data, nil
}

func (a *mqlAwsSecuritylakeDataLake) encryptionKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.EncryptionKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// The EncryptionConfiguration.KmsKeyId field can be a key ID, alias, or ARN.
	// initAwsKmsKey requires a valid ARN, so skip non-ARN values.
	if !strings.HasPrefix(*a.cacheKmsKeyId, "arn:") {
		log.Warn().Str("kmsKeyId", *a.cacheKmsKeyId).Msg("security lake encryption key is not an ARN, cannot resolve as typed resource")
		a.EncryptionKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSecuritylakeDataLake) s3Bucket() (*mqlAwsS3Bucket, error) {
	arn := a.cacheS3BucketArn
	if arn == "" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsSecuritylake) subscribers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSubscribers(conn), 5)
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

func (a *mqlAwsSecuritylake) getSubscribers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Securitylake(region)
			ctx := context.Background()
			res := []any{}

			paginator := securitylake.NewListSubscribersPaginator(svc, &securitylake.ListSubscribersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("security lake is not available in region")
						return res, nil
					}
					if IsSecurityLakeNotEnabledError(err) {
						log.Debug().Str("region", region).Msg("security lake is not enabled for this account")
						return res, nil
					}
					return nil, err
				}

				for _, sub := range page.Subscribers {
					mqlSub, err := newMqlSecuritylakeSubscriber(a.MqlRuntime, sub)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSub)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlSecuritylakeSubscriber(runtime *plugin.Runtime, sub sltypes.SubscriberResource) (*mqlAwsSecuritylakeSubscriber, error) {
	sources, _ := convert.JsonToDictSlice(sub.Sources)

	var identity any
	if sub.SubscriberIdentity != nil {
		identity, _ = convert.JsonToDict(sub.SubscriberIdentity)
	}

	res, err := CreateResource(runtime, "aws.securitylake.subscriber",
		map[string]*llx.RawData{
			"__id":               llx.StringDataPtr(sub.SubscriberArn),
			"subscriberArn":      llx.StringDataPtr(sub.SubscriberArn),
			"subscriberId":       llx.StringDataPtr(sub.SubscriberId),
			"subscriberName":     llx.StringDataPtr(sub.SubscriberName),
			"subscriberIdentity": llx.DictData(identity),
			"sources":            llx.ArrayData(sources, types.Dict),
			"accessTypes":        llx.ArrayData(enumSliceToAny(sub.AccessTypes), types.String),
			"subscriberStatus":   llx.StringData(string(sub.SubscriberStatus)),
			"createdAt":          llx.TimeDataPtr(sub.CreatedAt),
		})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsSecuritylakeSubscriber).cacheRoleArn = convert.ToValue(sub.RoleArn)
	res.(*mqlAwsSecuritylakeSubscriber).cacheS3BucketArn = convert.ToValue(sub.S3BucketArn)
	return res.(*mqlAwsSecuritylakeSubscriber), nil
}

func (a *mqlAwsSecuritylakeSubscriber) id() (string, error) {
	return a.SubscriberArn.Data, nil
}

func (a *mqlAwsSecuritylakeSubscriber) iamRole() (*mqlAwsIamRole, error) {
	arn := a.cacheRoleArn
	if arn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSecuritylakeSubscriber) s3Bucket() (*mqlAwsS3Bucket, error) {
	arn := a.cacheS3BucketArn
	if arn == "" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

type mqlAwsSecuritylakeSubscriberInternal struct {
	cacheRoleArn     string
	cacheS3BucketArn string
}
