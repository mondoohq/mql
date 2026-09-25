// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudwatch) logDestinations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLogDestinations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getLogDestinations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()
			res := []any{}

			paginator := cloudwatchlogs.NewDescribeDestinationsPaginator(svc, &cloudwatchlogs.DescribeDestinationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather cloudwatch log destinations")
				}
				for _, dest := range page.Destinations {
					mqlDest, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.logDestination",
						map[string]*llx.RawData{
							"name":         llx.StringDataPtr(dest.DestinationName),
							"arn":          llx.StringDataPtr(dest.Arn),
							"region":       llx.StringData(region),
							"targetArn":    llx.StringDataPtr(dest.TargetArn),
							"accessPolicy": llx.StringDataPtr(dest.AccessPolicy),
							"createdAt":    llx.TimeDataPtr(int64MillisToTime(dest.CreationTime)),
						})
					if err != nil {
						return nil, err
					}
					mqlDest.(*mqlAwsCloudwatchLogDestination).cacheRoleArn = convert.ToValue(dest.RoleArn)
					res = append(res, mqlDest)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchLogDestination) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudwatchLogDestination) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsCloudwatch) logInsightQueries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLogInsightQueries(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getLogInsightQueries(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeQueryDefinitions(ctx, &cloudwatchlogs.DescribeQueryDefinitionsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather cloudwatch log insight queries")
				}

				for _, qd := range resp.QueryDefinitions {
					logGroupNames := make([]any, 0, len(qd.LogGroupNames))
					for _, lgn := range qd.LogGroupNames {
						logGroupNames = append(logGroupNames, lgn)
					}

					mqlQuery, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.logInsightQuery",
						map[string]*llx.RawData{
							"id":            llx.StringDataPtr(qd.QueryDefinitionId),
							"name":          llx.StringDataPtr(qd.Name),
							"region":        llx.StringData(region),
							"queryString":   llx.StringDataPtr(qd.QueryString),
							"logGroupNames": llx.ArrayData(logGroupNames, types.String),
							"modifiedAt":    llx.TimeDataPtr(int64MillisToTime(qd.LastModified)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlQuery)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchLogInsightQuery) id() (string, error) {
	return a.Region.Data + "/" + a.Id.Data, nil
}

// dataProtectionPolicy fetches the log group's PII masking policy on demand.
// Returns nil when the log group has no policy attached.
func (a *mqlAwsCloudwatchLoggroup) dataProtectionPolicy() (any, error) {
	if a.DataProtectionStatus.Data == "" {
		return nil, nil
	}

	region, _ := parseLogGroupArn(a.Arn.Data)
	if region == "" {
		region = a.Region.Data
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudwatchLogs(region)
	ctx := context.Background()

	arnVal := strings.TrimSuffix(a.Arn.Data, ":*")
	resp, err := svc.GetDataProtectionPolicy(ctx, &cloudwatchlogs.GetDataProtectionPolicyInput{
		LogGroupIdentifier: &arnVal,
	})
	if err != nil {
		return nil, errors.Wrap(classifyAwsError(err, "logs:GetDataProtectionPolicy"), "could not gather data protection policy")
	}
	if resp.PolicyDocument == nil || *resp.PolicyDocument == "" {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(*resp.PolicyDocument), &parsed); err != nil {
		log.Warn().Err(err).Str("logGroup", a.Name.Data).Msg("could not parse data protection policy")
		return nil, nil
	}
	return parsed, nil
}

// resourcePolicy returns the account-level CloudWatch Logs resource policy
// whose resourceArn matches this log group's ARN. Other policies that apply
// to this group via broader account-scope rules are reachable through
// aws.cloudwatch.resourcePolicies and aws.cloudwatch.accountPolicies.
func (a *mqlAwsCloudwatchLoggroup) resourcePolicy() (*mqlAwsCloudwatchResourcepolicy, error) {
	obj, err := CreateResource(a.MqlRuntime, "aws.cloudwatch", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	cw := obj.(*mqlAwsCloudwatch)
	raw := cw.GetResourcePolicies()
	if raw.Error != nil {
		return nil, raw.Error
	}

	groupArn := a.Arn.Data
	groupArnNoStar := trimLogGroupArnSuffix(groupArn)
	for _, p := range raw.Data {
		rp := p.(*mqlAwsCloudwatchResourcepolicy)
		if rp.ResourceArn.Data == "" {
			continue
		}
		if rp.ResourceArn.Data == groupArn || trimLogGroupArnSuffix(rp.ResourceArn.Data) == groupArnNoStar {
			return rp, nil
		}
	}

	a.ResourcePolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func trimLogGroupArnSuffix(arnVal string) string {
	if len(arnVal) >= 2 && arnVal[len(arnVal)-2:] == ":*" {
		return arnVal[:len(arnVal)-2]
	}
	return arnVal
}

// accountPolicies returns all CloudWatch Logs account-level policies across
// every policy type (data protection, subscription filter, field index,
// transformer, metric extraction) for every enabled region.
func (a *mqlAwsCloudwatch) accountPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAccountPolicies(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

// allCloudwatchLogsPolicyTypes is iterated by accountPolicies because
// DescribeAccountPolicies requires the caller to specify a policyType. The
// list mirrors the cloudwatchlogs.PolicyType enum and will need extending if
// the SDK gains new policy types.
var allCloudwatchLogsPolicyTypes = []cwltypes.PolicyType{
	cwltypes.PolicyTypeDataProtectionPolicy,
	cwltypes.PolicyTypeSubscriptionFilterPolicy,
	cwltypes.PolicyTypeFieldIndexPolicy,
	cwltypes.PolicyTypeTransformerPolicy,
	cwltypes.PolicyTypeMetricExtractionPolicy,
}

func (a *mqlAwsCloudwatch) getAccountPolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()
			res := []any{}

			for _, ptype := range allCloudwatchLogsPolicyTypes {
				resp, err := svc.DescribeAccountPolicies(ctx, &cloudwatchlogs.DescribeAccountPoliciesInput{
					PolicyType: ptype,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Str("policyType", string(ptype)).Msg("access denied describing account policies")
						continue
					}
					return nil, errors.Wrap(err, "could not gather cloudwatch log account policies")
				}
				for _, p := range resp.AccountPolicies {
					var doc any
					if p.PolicyDocument != nil && *p.PolicyDocument != "" {
						if jsonErr := json.Unmarshal([]byte(*p.PolicyDocument), &doc); jsonErr != nil {
							log.Warn().Err(jsonErr).Str("policyName", convert.ToValue(p.PolicyName)).Msg("could not parse account policy document")
						}
					}

					mqlPolicy, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.logAccountPolicy",
						map[string]*llx.RawData{
							"policyName":        llx.StringDataPtr(p.PolicyName),
							"policyType":        llx.StringData(string(p.PolicyType)),
							"policyDocument":    llx.DictData(doc),
							"lastUpdatedTime":   llx.TimeDataPtr(int64MillisToTime(p.LastUpdatedTime)),
							"scope":             llx.StringData(string(p.Scope)),
							"selectionCriteria": llx.StringDataPtr(p.SelectionCriteria),
							"accountId":         llx.StringDataPtr(p.AccountId),
							"region":            llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPolicy)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchLogAccountPolicy) id() (string, error) {
	return a.Region.Data + "/" + a.PolicyType.Data + "/" + a.PolicyName.Data, nil
}

// anomalyDetectors returns the CloudWatch Logs anomaly detectors in every
// enabled region.
func (a *mqlAwsCloudwatch) anomalyDetectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAnomalyDetectors(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudwatch) getAnomalyDetectors(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.CloudwatchLogs(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListLogAnomalyDetectors(ctx, &cloudwatchlogs.ListLogAnomalyDetectorsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather cloudwatch log anomaly detectors")
				}

				for _, d := range resp.AnomalyDetectors {
					logGroupArns := make([]any, 0, len(d.LogGroupArnList))
					for _, lg := range d.LogGroupArnList {
						logGroupArns = append(logGroupArns, lg)
					}

					args := map[string]*llx.RawData{
						"anomalyDetectorArn":    llx.StringDataPtr(d.AnomalyDetectorArn),
						"detectorName":          llx.StringDataPtr(d.DetectorName),
						"anomalyDetectorStatus": llx.StringData(string(d.AnomalyDetectorStatus)),
						"evaluationFrequency":   llx.StringData(string(d.EvaluationFrequency)),
						"filterPattern":         llx.StringDataPtr(d.FilterPattern),
						"anomalyVisibilityTime": llx.IntDataDefault(d.AnomalyVisibilityTime, 0),
						"logGroupArnList":       llx.ArrayData(logGroupArns, types.String),
						"creationTimeStamp":     llx.TimeDataPtr(int64MillisToTime(&d.CreationTimeStamp)),
						"lastModifiedTimeStamp": llx.TimeDataPtr(int64MillisToTime(&d.LastModifiedTimeStamp)),
						"region":                llx.StringData(region),
					}

					if d.KmsKeyId != nil && *d.KmsKeyId != "" {
						mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
							map[string]*llx.RawData{"arn": llx.StringDataPtr(d.KmsKeyId)})
						if err != nil {
							args["kmsKey"] = llx.NilData
						} else {
							k := mqlKey.(*mqlAwsKmsKey)
							args["kmsKey"] = llx.ResourceData(k, k.MqlName())
						}
					} else {
						args["kmsKey"] = llx.NilData
					}

					mqlDetector, err := CreateResource(a.MqlRuntime, "aws.cloudwatch.logAnomalyDetector", args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDetector)
				}

				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsCloudwatchLogAnomalyDetector) id() (string, error) {
	return a.AnomalyDetectorArn.Data, nil
}

func (a *mqlAwsCloudwatchLogAnomalyDetector) kmsKey() (*mqlAwsKmsKey, error) {
	a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

type mqlAwsCloudwatchLogDestinationInternal struct {
	cacheRoleArn string
}
