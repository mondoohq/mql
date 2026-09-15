// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

func (a *mqlAwsSecretsmanager) id() (string, error) {
	return "aws.secretsmanager", nil
}

func (a *mqlAwsSecretsmanager) secrets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSecrets(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSecretsmanagerSecret) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsSecretsmanagerSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSecretsmanagerSecret); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch secretsmanager secret")
	}

	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsSecretsmanagerSecret, arnVal); cached != nil {
		return args, cached, nil
	}

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		// Returning (args, nil, nil) here would let the runtime create a
		// resource whose fields are all unset, which surfaces as malformed
		// nil data when those fields are queried.
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Secretsmanager(region)
	ctx := context.Background()

	resp, err := svc.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: &arnVal})
	if err != nil {
		return nil, nil, err
	}

	args["arn"] = llx.StringDataPtr(resp.ARN)
	args["region"] = llx.StringData(region)
	args["createdAt"] = llx.TimeDataPtr(resp.CreatedDate)
	args["description"] = llx.StringDataPtr(resp.Description)
	args["lastAccessedDate"] = llx.TimeDataPtr(resp.LastAccessedDate)
	args["lastChangedDate"] = llx.TimeDataPtr(resp.LastChangedDate)
	args["lastRotatedDate"] = llx.TimeDataPtr(resp.LastRotatedDate)
	args["name"] = llx.StringDataPtr(resp.Name)
	args["nextRotationDate"] = llx.TimeDataPtr(resp.NextRotationDate)
	args["owningService"] = llx.StringDataPtr(resp.OwningService)
	args["primaryRegion"] = llx.StringDataPtr(resp.PrimaryRegion)
	args["rotationEnabled"] = llx.BoolData(convert.ToValue(resp.RotationEnabled))
	args["tags"] = llx.MapData(secretTagsToMap(resp.Tags), types.String)

	if resp.KmsKeyId != nil {
		mqlKey, err := NewResource(runtime, ResourceAwsKmsKey, map[string]*llx.RawData{
			"arn":    llx.StringDataPtr(resp.KmsKeyId),
			"region": llx.StringData(region),
		})
		if err != nil {
			args["kmsKey"] = &llx.RawData{Type: types.Resource(ResourceAwsKmsKey), Error: err}
		} else {
			k := mqlKey.(*mqlAwsKmsKey)
			args["kmsKey"] = llx.ResourceData(k, k.MqlName())
		}
	} else {
		args["kmsKey"] = llx.NilData
	}

	if resp.RotationLambdaARN != nil {
		mqlLambda, err := NewResource(runtime, ResourceAwsLambdaFunction, map[string]*llx.RawData{
			"arn": llx.StringDataPtr(resp.RotationLambdaARN),
		})
		if err != nil {
			args["rotationLambda"] = &llx.RawData{Type: types.Resource(ResourceAwsLambdaFunction), Error: err}
		} else {
			l := mqlLambda.(*mqlAwsLambdaFunction)
			args["rotationLambda"] = llx.ResourceData(l, l.MqlName())
		}
	} else {
		args["rotationLambda"] = llx.NilData
	}

	if resp.RotationRules != nil {
		var automaticallyAfterDays int64
		if resp.RotationRules.AutomaticallyAfterDays != nil {
			automaticallyAfterDays = *resp.RotationRules.AutomaticallyAfterDays
		}
		mqlRotationRules, err := CreateResource(runtime, ResourceAwsSecretsmanagerSecretRotationRules, map[string]*llx.RawData{
			"__id":                   llx.StringData(convert.ToValue(resp.ARN) + "/rotationRules"),
			"automaticallyAfterDays": llx.IntData(automaticallyAfterDays),
			"duration":               llx.StringDataPtr(resp.RotationRules.Duration),
			"scheduleExpression":     llx.StringDataPtr(resp.RotationRules.ScheduleExpression),
		})
		if err != nil {
			args["rotationRules"] = &llx.RawData{Type: types.Resource(ResourceAwsSecretsmanagerSecretRotationRules), Error: err}
		} else {
			r := mqlRotationRules.(*mqlAwsSecretsmanagerSecretRotationRules)
			args["rotationRules"] = llx.ResourceData(r, r.MqlName())
		}
	} else {
		args["rotationRules"] = llx.NilData
	}

	mqlSecret, err := CreateResource(runtime, ResourceAwsSecretsmanagerSecret, args)
	if err != nil {
		return nil, nil, err
	}
	mqlSecretRes := mqlSecret.(*mqlAwsSecretsmanagerSecret)
	mqlSecretRes.cacheRegion = region
	mqlSecretRes.cacheType = convert.ToValue(resp.Type)
	mqlSecretRes.cacheExternalRotationRoleArn = resp.ExternalSecretRotationRoleArn
	mqlSecretRes.DeletedAt = plugin.TValue[*time.Time]{Data: resp.DeletedDate, State: plugin.StateIsSet}

	// We already have the replication status from DescribeSecret; populate
	// ReplicaRegions directly to avoid a redundant DescribeSecret call.
	replicaRegions, err := buildSecretReplicaRegions(runtime, convert.ToValue(resp.ARN), resp.ReplicationStatus)
	if err != nil {
		return nil, nil, err
	}
	mqlSecretRes.ReplicaRegions = plugin.TValue[[]any]{Data: replicaRegions, State: plugin.StateIsSet}

	return args, mqlSecretRes, nil
}

func buildSecretReplicaRegions(runtime *plugin.Runtime, arn string, replicas []secretstypes.ReplicationStatusType) ([]any, error) {
	res := make([]any, 0, len(replicas))
	for _, replica := range replicas {
		mqlReplica, err := CreateResource(runtime, "aws.secretsmanager.secret.replicaRegion",
			map[string]*llx.RawData{
				"__id":             llx.StringData(arn + "/replica/" + convert.ToValue(replica.Region)),
				"id":               llx.StringData(arn + "/replica/" + convert.ToValue(replica.Region)),
				"region":           llx.StringDataPtr(replica.Region),
				"status":           llx.StringData(string(replica.Status)),
				"statusMessage":    llx.StringDataPtr(replica.StatusMessage),
				"lastAccessedDate": llx.TimeDataPtr(replica.LastAccessedDate),
			})
		if err != nil {
			return nil, err
		}
		mqlReplica.(*mqlAwsSecretsmanagerSecretReplicaRegion).cacheKmsKeyId = convert.ToValue(replica.KmsKeyId)
		res = append(res, mqlReplica)
	}
	return res, nil
}

func (a *mqlAwsSecretsmanagerSecret) kmsKey() (*mqlAwsKmsKey, error) {
	return a.KmsKey.Data, nil
}

func (a *mqlAwsSecretsmanager) getSecrets(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Secretsmanager(region)
			ctx := context.Background()

			res := []any{}

			// Secrets scheduled for deletion are excluded by default, but during
			// the recovery window they still exist and still hold live
			// credentials -- and aws.secretsmanager.secret(arn:) resolves them,
			// so the collection and the single lookup disagreed. This is also
			// what makes the deletedAt field reachable from the collection.
			params := &secretsmanager.ListSecretsInput{IncludePlannedDeletion: aws.Bool(true)}
			paginator := secretsmanager.NewListSecretsPaginator(svc, params)
			for paginator.HasMorePages() {
				secrets, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, secret := range secrets.SecretList {
					// ListSecrets already carries the tags, so the discovery tag
					// filter costs nothing extra here.
					if conn.Filters.General.HasTags() &&
						conn.Filters.General.IsFilteredOutByTags(secretTagsToStringMap(secret.Tags)) {
						log.Debug().Str("secret", convert.ToValue(secret.ARN)).
							Msg("excluding secret due to filters")
						continue
					}
					args := map[string]*llx.RawData{
						"arn":              llx.StringDataPtr(secret.ARN),
						"region":           llx.StringData(region),
						"createdAt":        llx.TimeDataPtr(secret.CreatedDate),
						"description":      llx.StringDataPtr(secret.Description),
						"lastAccessedDate": llx.TimeDataPtr(secret.LastAccessedDate),
						"lastChangedDate":  llx.TimeDataPtr(secret.LastChangedDate),
						"lastRotatedDate":  llx.TimeDataPtr(secret.LastRotatedDate),
						"name":             llx.StringDataPtr(secret.Name),
						"nextRotationDate": llx.TimeDataPtr(secret.NextRotationDate),
						"owningService":    llx.StringDataPtr(secret.OwningService),
						"primaryRegion":    llx.StringDataPtr(secret.PrimaryRegion),
						"rotationEnabled":  llx.BoolData(convert.ToValue(secret.RotationEnabled)),
						"tags":             llx.MapData(secretTagsToMap(secret.Tags), types.String),
					}

					// add kms key if there is one
					if secret.KmsKeyId != nil {
						mqlKeyResource, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
							map[string]*llx.RawData{
								"arn":    llx.StringDataPtr(secret.KmsKeyId),
								"region": llx.StringData(region),
							})
						if err != nil {
							args["kmsKey"] = &llx.RawData{Type: types.Resource(ResourceAwsKmsKey), Error: err}
						} else {
							mqlKey := mqlKeyResource.(*mqlAwsKmsKey)
							args["kmsKey"] = llx.ResourceData(mqlKey, mqlKey.MqlName())
						}
					} else {
						args["kmsKey"] = llx.NilData
					}

					// add rotation lambda if there is one
					if secret.RotationLambdaARN != nil {
						mqlLambdaResource, err := NewResource(a.MqlRuntime, ResourceAwsLambdaFunction,
							map[string]*llx.RawData{
								"arn": llx.StringDataPtr(secret.RotationLambdaARN),
							})
						if err != nil {
							args["rotationLambda"] = &llx.RawData{Type: types.Resource(ResourceAwsLambdaFunction), Error: err}
						} else {
							mqlLambda := mqlLambdaResource.(*mqlAwsLambdaFunction)
							args["rotationLambda"] = llx.ResourceData(mqlLambda, mqlLambda.MqlName())
						}
					} else {
						args["rotationLambda"] = llx.NilData
					}

					// add rotation rules if configured
					if secret.RotationRules != nil {
						var automaticallyAfterDays int64
						if secret.RotationRules.AutomaticallyAfterDays != nil {
							automaticallyAfterDays = *secret.RotationRules.AutomaticallyAfterDays
						}
						mqlRotationRules, err := CreateResource(a.MqlRuntime, ResourceAwsSecretsmanagerSecretRotationRules,
							map[string]*llx.RawData{
								"__id":                   llx.StringData(convert.ToValue(secret.ARN) + "/rotationRules"),
								"automaticallyAfterDays": llx.IntData(automaticallyAfterDays),
								"duration":               llx.StringDataPtr(secret.RotationRules.Duration),
								"scheduleExpression":     llx.StringDataPtr(secret.RotationRules.ScheduleExpression),
							})
						if err != nil {
							args["rotationRules"] = &llx.RawData{Type: types.Resource(ResourceAwsSecretsmanagerSecretRotationRules), Error: err}
						} else {
							mqlRules := mqlRotationRules.(*mqlAwsSecretsmanagerSecretRotationRules)
							args["rotationRules"] = llx.ResourceData(mqlRules, mqlRules.MqlName())
						}
					} else {
						args["rotationRules"] = llx.NilData
					}

					mqlSecret, err := CreateResource(a.MqlRuntime, ResourceAwsSecretsmanagerSecret, args)
					if err != nil {
						return nil, err
					}
					mqlSecretRes := mqlSecret.(*mqlAwsSecretsmanagerSecret)
					mqlSecretRes.cacheRegion = region
					mqlSecretRes.cacheType = convert.ToValue(secret.Type)
					mqlSecretRes.cacheExternalRotationRoleArn = secret.ExternalSecretRotationRoleArn
					mqlSecretRes.DeletedAt = plugin.TValue[*time.Time]{Data: secret.DeletedDate, State: plugin.StateIsSet}
					res = append(res, mqlSecret)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSecretsmanagerSecret) resourcePolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := a.Arn.Data
	region := a.cacheRegion
	svc := conn.Secretsmanager(region)
	ctx := context.Background()

	resp, err := svc.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
		SecretId: &arn,
	})
	if err != nil {
		return "", err
	}
	if resp.ResourcePolicy == nil {
		return "", nil
	}
	return *resp.ResourcePolicy, nil
}

func (a *mqlAwsSecretsmanagerSecret) replicaRegions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.cacheRegion
	svc := conn.Secretsmanager(region)
	ctx := context.Background()

	arn := a.Arn.Data
	resp, err := svc.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: &arn,
	})
	if err != nil {
		return nil, err
	}

	return buildSecretReplicaRegions(a.MqlRuntime, arn, resp.ReplicationStatus)
}

type mqlAwsSecretsmanagerSecretInternal struct {
	cacheRegion                  string
	cacheType                    string
	cacheExternalRotationRoleArn *string
}

func (a *mqlAwsSecretsmanagerSecret) externalRotationRole() (*mqlAwsIamRole, error) {
	if a.cacheExternalRotationRoleArn == nil || *a.cacheExternalRotationRoleArn == "" {
		a.ExternalRotationRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheExternalRotationRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSecretsmanagerSecret) compute_type() (string, error) {
	return a.cacheType, nil
}

func (a *mqlAwsSecretsmanagerSecret) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.cacheRegion
	svc := conn.Secretsmanager(region)
	ctx := context.Background()
	arn := a.Arn.Data

	res := []any{}
	paginator := secretsmanager.NewListSecretVersionIdsPaginator(svc, &secretsmanager.ListSecretVersionIdsInput{
		SecretId: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, v := range page.Versions {
			stages := []any{}
			for _, s := range v.VersionStages {
				stages = append(stages, s)
			}
			kmsKeyIds := []any{}
			for _, k := range v.KmsKeyIds {
				kmsKeyIds = append(kmsKeyIds, k)
			}
			mqlVersion, err := CreateResource(a.MqlRuntime, "aws.secretsmanager.secret.version",
				map[string]*llx.RawData{
					"__id":             llx.StringData(arn + "/version/" + convert.ToValue(v.VersionId)),
					"versionId":        llx.StringDataPtr(v.VersionId),
					"versionStages":    llx.ArrayData(stages, types.String),
					"createdDate":      llx.TimeDataPtr(v.CreatedDate),
					"lastAccessedDate": llx.TimeDataPtr(v.LastAccessedDate),
					"kmsKeyIds":        llx.ArrayData(kmsKeyIds, types.String),
				})
			if err != nil {
				return nil, err
			}
			mqlVersion.(*mqlAwsSecretsmanagerSecretVersion).region = region
			mqlVersion.(*mqlAwsSecretsmanagerSecretVersion).accountID = conn.AccountId()
			res = append(res, mqlVersion)
		}
	}
	return res, nil
}

type mqlAwsSecretsmanagerSecretVersionInternal struct {
	region    string
	accountID string
}

func (a *mqlAwsSecretsmanagerSecretVersion) kmsKeys() ([]any, error) {
	res := []any{}
	for _, idAny := range a.KmsKeyIds.Data {
		keyID, ok := idAny.(string)
		if !ok || keyID == "" {
			continue
		}
		// Versions encrypted with the AWS-managed secrets manager key report the
		// literal "DefaultEncryptionKey" sentinel rather than a resolvable key id.
		if keyID == "DefaultEncryptionKey" {
			continue
		}
		// KmsKeyIds may be full ARNs, bare key ids, or aliases.
		mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
			kmsKeyRefArgs(a.region, a.accountID, keyID))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// deletedAt is eagerly populated from ListSecrets during creation.
// This stub exists for the code generator; it is never called at runtime.
func (a *mqlAwsSecretsmanagerSecret) deletedAt() (*time.Time, error) {
	return nil, nil
}

func (a *mqlAwsSecretsmanagerSecretReplicaRegion) kmsKey() (*mqlAwsKmsKey, error) {
	kmsKeyId := a.cacheKmsKeyId
	if kmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId can be an ARN, key ID, or alias. initAwsKmsKey requires a full ARN.
	if !strings.HasPrefix(kmsKeyId, "arn:") {
		log.Warn().Str("kmsKeyId", kmsKeyId).Msg("replica region KMS key is not an ARN, cannot resolve as typed resource")
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringData(kmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func secretTagsToMap(tags []secretstypes.Tag) map[string]any {
	return tagsToMap(tags, func(t secretstypes.Tag) *string { return t.Key }, func(t secretstypes.Tag) *string { return t.Value })
}

// secretTagsToStringMap is secretTagsToMap in the shape the discovery filters
// evaluate against.
func secretTagsToStringMap(tags []secretstypes.Tag) map[string]string {
	return tagsToStringMap(tags, func(t secretstypes.Tag) *string { return t.Key }, func(t secretstypes.Tag) *string { return t.Value })
}

type mqlAwsSecretsmanagerSecretReplicaRegionInternal struct {
	cacheKmsKeyId string
}
