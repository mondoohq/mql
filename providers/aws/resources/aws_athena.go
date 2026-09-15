// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/athena"
	athena_types "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsAthena) id() (string, error) {
	return "aws.athena", nil
}

func (a *mqlAwsAthena) workgroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWorkgroups(conn), 5)
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

func (a *mqlAwsAthena) getWorkgroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("athena>getWorkgroups>calling aws with region %s", region)

			svc := conn.Athena(region)
			ctx := context.Background()
			res := []any{}

			paginator := athena.NewListWorkGroupsPaginator(svc, &athena.ListWorkGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, wgSummary := range page.WorkGroups {
					mqlWg, err := newMqlAwsAthenaWorkgroupFromSummary(a.MqlRuntime, region, conn.AccountId(), &wgSummary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlWg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// initAwsAthenaWorkgroup resolves a single Athena workgroup. When invoked
// for a discovered asset (aws-athena-workgroup platform), no args are passed,
// so the workgroup ARN is read from the connection's asset identifier and used
// to select the matching workgroup from the parent collection.
func initAwsAthenaWorkgroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformAthenaWorkgroup); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil && args["name"] == nil {
		return args, nil, fmt.Errorf("arn or name required to fetch athena workgroup")
	}

	obj, err := CreateResource(runtime, "aws.athena", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	wgs := obj.(*mqlAwsAthena).GetWorkgroups()
	if wgs.Error != nil {
		return nil, nil, wgs.Error
	}

	var wantArn, wantName string
	if args["arn"] != nil {
		wantArn = args["arn"].Value.(string)
	}
	if args["name"] != nil {
		wantName = args["name"].Value.(string)
	}
	for _, r := range wgs.Data {
		wg := r.(*mqlAwsAthenaWorkgroup)
		if (wantArn != "" && wg.Arn.Data == wantArn) || (wantName != "" && wg.Name.Data == wantName) {
			return args, wg, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.athena.workgroup with arn %q or name %q not found", wantArn, wantName)
}

func newMqlAwsAthenaWorkgroupFromSummary(runtime *plugin.Runtime, region string, accountID string, wg *athena_types.WorkGroupSummary) (*mqlAwsAthenaWorkgroup, error) {
	if wg == nil {
		return nil, fmt.Errorf("workgroup summary is nil")
	}
	arn := fmt.Sprintf("arn:aws:athena:%s:%s:workgroup/%s", region, accountID, convert.ToValue(wg.Name))

	resource, err := CreateResource(runtime, "aws.athena.workgroup",
		map[string]*llx.RawData{
			"__id":        llx.StringData(arn),
			"arn":         llx.StringData(arn),
			"name":        llx.StringDataPtr(wg.Name),
			"state":       llx.StringData(string(wg.State)),
			"description": llx.StringDataPtr(wg.Description),
			"createdAt":   llx.TimeDataPtr(wg.CreationTime),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaWorkgroup), nil
}

type mqlAwsAthenaWorkgroupInternal struct {
	fetched                   bool
	cachedEnforce             bool
	cachedPublish             bool
	cachedRequester           bool
	cachedBytesCutoff         int64
	cachedEngineVer           any
	cachedResultCfg           any
	cachedEncOption           string
	cachedKmsKeyRef           string
	cachedOutputLoc           string
	cachedMinEncEnforced      bool
	cachedExpectedBucketOwner string
	cachedAclOption           string
	cachedExecutionRole       string
	cachedCustomerKmsKey      string
	cachedAdditionalConfig    string
	lock                      sync.Mutex
}

func (a *mqlAwsAthenaWorkgroup) fetchConfig() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Athena(a.Region.Data)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := svc.GetWorkGroup(ctx, &athena.GetWorkGroupInput{
		WorkGroup: &name,
	})
	if err != nil {
		return err
	}
	if resp.WorkGroup != nil && resp.WorkGroup.Configuration != nil {
		cfg := resp.WorkGroup.Configuration
		if cfg.EnforceWorkGroupConfiguration != nil {
			a.cachedEnforce = *cfg.EnforceWorkGroupConfiguration
		}
		if cfg.PublishCloudWatchMetricsEnabled != nil {
			a.cachedPublish = *cfg.PublishCloudWatchMetricsEnabled
		}
		if cfg.RequesterPaysEnabled != nil {
			a.cachedRequester = *cfg.RequesterPaysEnabled
		}
		if cfg.BytesScannedCutoffPerQuery != nil {
			a.cachedBytesCutoff = *cfg.BytesScannedCutoffPerQuery
		}
		if cfg.EnableMinimumEncryptionConfiguration != nil {
			a.cachedMinEncEnforced = *cfg.EnableMinimumEncryptionConfiguration
		}
		a.cachedAdditionalConfig = convert.ToValue(cfg.AdditionalConfiguration)
		a.cachedExecutionRole = convert.ToValue(cfg.ExecutionRole)
		if cc := cfg.CustomerContentEncryptionConfiguration; cc != nil {
			a.cachedCustomerKmsKey = convert.ToValue(cc.KmsKey)
		}
		var err2 error
		a.cachedEngineVer, err2 = convert.JsonToDict(cfg.EngineVersion)
		if err2 != nil {
			return err2
		}
		a.cachedResultCfg, err2 = convert.JsonToDict(cfg.ResultConfiguration)
		if err2 != nil {
			return err2
		}
		if rc := cfg.ResultConfiguration; rc != nil {
			if rc.OutputLocation != nil {
				a.cachedOutputLoc = *rc.OutputLocation
			}
			a.cachedExpectedBucketOwner = convert.ToValue(rc.ExpectedBucketOwner)
			if rc.AclConfiguration != nil {
				a.cachedAclOption = string(rc.AclConfiguration.S3AclOption)
			}
			if rc.EncryptionConfiguration != nil {
				a.cachedEncOption = string(rc.EncryptionConfiguration.EncryptionOption)
				if rc.EncryptionConfiguration.KmsKey != nil {
					a.cachedKmsKeyRef = *rc.EncryptionConfiguration.KmsKey
				}
			}
		}
	}
	a.fetched = true
	return nil
}

func (a *mqlAwsAthenaWorkgroup) enforceWorkGroupConfiguration() (bool, error) {
	if err := a.fetchConfig(); err != nil {
		return false, err
	}
	return a.cachedEnforce, nil
}

func (a *mqlAwsAthenaWorkgroup) publishCloudWatchMetricsEnabled() (bool, error) {
	if err := a.fetchConfig(); err != nil {
		return false, err
	}
	return a.cachedPublish, nil
}

func (a *mqlAwsAthenaWorkgroup) bytesScannedCutoffPerQuery() (int64, error) {
	if err := a.fetchConfig(); err != nil {
		return 0, err
	}
	return a.cachedBytesCutoff, nil
}

func (a *mqlAwsAthenaWorkgroup) requesterPaysEnabled() (bool, error) {
	if err := a.fetchConfig(); err != nil {
		return false, err
	}
	return a.cachedRequester, nil
}

func (a *mqlAwsAthenaWorkgroup) engineVersion() (any, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	return a.cachedEngineVer, nil
}

func (a *mqlAwsAthenaWorkgroup) resultConfiguration() (any, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	return a.cachedResultCfg, nil
}

func (a *mqlAwsAthenaWorkgroup) resultOutputLocation() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cachedOutputLoc, nil
}

func (a *mqlAwsAthenaWorkgroup) resultEncryptionOption() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cachedEncOption, nil
}

func (a *mqlAwsAthenaWorkgroup) encrypted() (bool, error) {
	if err := a.fetchConfig(); err != nil {
		return false, err
	}
	return a.cachedEncOption != "", nil
}

func (a *mqlAwsAthenaWorkgroup) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	if a.cachedKmsKeyRef == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn":    llx.StringData(a.cachedKmsKeyRef),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsAthenaWorkgroup) minimumEncryptionEnforced() (bool, error) {
	if err := a.fetchConfig(); err != nil {
		return false, err
	}
	return a.cachedMinEncEnforced, nil
}

func (a *mqlAwsAthenaWorkgroup) expectedResultBucketOwner() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cachedExpectedBucketOwner, nil
}

func (a *mqlAwsAthenaWorkgroup) resultAclOption() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cachedAclOption, nil
}

func (a *mqlAwsAthenaWorkgroup) additionalConfiguration() (string, error) {
	if err := a.fetchConfig(); err != nil {
		return "", err
	}
	return a.cachedAdditionalConfig, nil
}

func (a *mqlAwsAthenaWorkgroup) resultBucket() (*mqlAwsS3Bucket, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	bucket := athenaBucketFromS3Location(a.cachedOutputLoc)
	if bucket == "" {
		a.ResultBucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{
			"name": llx.StringData(bucket),
		})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsAthenaWorkgroup) executionRole() (*mqlAwsIamRole, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	if a.cachedExecutionRole == "" {
		a.ExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cachedExecutionRole),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsAthenaWorkgroup) customerContentKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchConfig(); err != nil {
		return nil, err
	}
	if a.cachedCustomerKmsKey == "" {
		a.CustomerContentKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn":    llx.StringData(a.cachedCustomerKmsKey),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// athenaBucketFromS3Location extracts the bucket name from an Athena result
// output location such as "s3://my-results-bucket/prefix/".
func athenaBucketFromS3Location(location string) string {
	trimmed := strings.TrimPrefix(location, "s3://")
	if trimmed == location {
		return ""
	}
	return strings.SplitN(trimmed, "/", 2)[0]
}

func (a *mqlAwsAthena) dataCatalogs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDataCatalogs(conn), 5)
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

func (a *mqlAwsAthena) getDataCatalogs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("athena>getDataCatalogs>calling aws with region %s", region)

			svc := conn.Athena(region)
			ctx := context.Background()
			res := []any{}

			paginator := athena.NewListDataCatalogsPaginator(svc, &athena.ListDataCatalogsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, catalog := range page.DataCatalogsSummary {
					mqlCatalog, err := newMqlAwsAthenaDataCatalog(a.MqlRuntime, region, catalog)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCatalog)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsAthenaDataCatalog(runtime *plugin.Runtime, region string, catalog athena_types.DataCatalogSummary) (*mqlAwsAthenaDataCatalog, error) {
	id := fmt.Sprintf("aws.athena.dataCatalog/%s/%s", region, convert.ToValue(catalog.CatalogName))

	resource, err := CreateResource(runtime, "aws.athena.dataCatalog",
		map[string]*llx.RawData{
			"__id":           llx.StringData(id),
			"name":           llx.StringDataPtr(catalog.CatalogName),
			"type":           llx.StringData(string(catalog.Type)),
			"status":         llx.StringData(string(catalog.Status)),
			"connectionType": llx.StringData(string(catalog.ConnectionType)),
			"error":          llx.StringDataPtr(catalog.Error),
			"region":         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaDataCatalog), nil
}

type mqlAwsAthenaDataCatalogInternal struct {
	fetchedDetail bool
	cachedDesc    string
	cachedParams  map[string]any
	lock          sync.Mutex
}

const athenaDataCatalogArnPattern = "arn:aws:athena:%s:%s:datacatalog/%s"

func (a *mqlAwsAthenaDataCatalog) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(athenaDataCatalogArnPattern, a.Region.Data, conn.AccountId(), a.Name.Data), nil
}

func (a *mqlAwsAthenaDataCatalog) fetchDetail() error {
	if a.fetchedDetail {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetchedDetail {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Athena(a.Region.Data)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := svc.GetDataCatalog(ctx, &athena.GetDataCatalogInput{
		Name: &name,
	})
	if err != nil {
		return err
	}
	if resp.DataCatalog != nil {
		a.cachedDesc = convert.ToValue(resp.DataCatalog.Description)
		if resp.DataCatalog.Parameters != nil {
			params := make(map[string]any, len(resp.DataCatalog.Parameters))
			for k, v := range resp.DataCatalog.Parameters {
				params[k] = v
			}
			a.cachedParams = params
		}
	}
	a.fetchedDetail = true
	return nil
}

func (a *mqlAwsAthenaDataCatalog) description() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.cachedDesc, nil
}

func (a *mqlAwsAthenaDataCatalog) parameters() (map[string]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.cachedParams, nil
}

// lambdaFunction resolves the Lambda function backing a LAMBDA or FEDERATED
// metadata connector. Athena stores it under the "function" parameter, or as a
// pair of "metadata-function"/"record-function" parameters for split
// connectors; the metadata function is used when present.
func (a *mqlAwsAthenaDataCatalog) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	arn := athenaLambdaArnFromParams(a.cachedParams)
	if arn == "" {
		a.LambdaFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlFn, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{
			"arn": llx.StringData(arn),
		})
	if err != nil {
		return nil, err
	}
	return mqlFn.(*mqlAwsLambdaFunction), nil
}

// athenaLambdaArnFromParams returns the Lambda function ARN from a data-catalog
// parameter map, preferring the single "function" key and falling back to
// "metadata-function". Returns "" when no Lambda ARN is present.
func athenaLambdaArnFromParams(params map[string]any) string {
	for _, key := range []string{"function", "metadata-function"} {
		if v, ok := params[key]; ok {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "arn:") {
				return s
			}
		}
	}
	return ""
}

// namedQueries lists every saved query in the account.
//
// A named query belongs to exactly one workgroup, and ListNamedQueries returns
// the saved queries of a single workgroup: the one named in the request, or
// primary when the request names none. Listing without a workgroup therefore
// reports only the primary workgroup's queries, and an account that keeps its
// analytics in a named workgroup - which is what workgroup separation is for -
// reported none at all.
//
// The workgroups come from the workgroups field rather than a fresh
// ListWorkGroups call, so a scan that reads both collections lists them once.
func (a *mqlAwsAthena) namedQueries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	workgroups := a.GetWorkgroups()
	if workgroups.Error != nil {
		return nil, workgroups.Error
	}

	workgroupsByRegion := map[string][]string{}
	for _, raw := range workgroups.Data {
		wg, ok := raw.(*mqlAwsAthenaWorkgroup)
		if !ok {
			continue
		}
		// A disabled workgroup still holds its saved queries, and they are still
		// worth auditing, so state is deliberately not filtered on here.
		if name := wg.Name.Data; name != "" {
			workgroupsByRegion[wg.Region.Data] = append(workgroupsByRegion[wg.Region.Data], name)
		}
	}

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getNamedQueries(conn, workgroupsByRegion), 5)
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

// listNamedQueryIDs lists the saved query ids in one workgroup.
//
// A workgroup that cannot be read contributes nothing rather than failing the
// region. ListNamedQueries requires access to the specific workgroup, so a role
// scoped to some workgroups can legitimately see a workgroup in ListWorkGroups
// and be denied its queries; and a workgroup deleted between the two calls
// comes back as an invalid request rather than an empty list.
func listNamedQueryIDs(ctx context.Context, svc *athena.Client, region, workgroup string) ([]string, error) {
	var queryIds []string
	paginator := athena.NewListNamedQueriesPaginator(svc, &athena.ListNamedQueriesInput{
		WorkGroup: &workgroup,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Str("workgroup", workgroup).
					Msg("not permitted to list the named queries of this workgroup")
				return nil, nil
			}
			var invalid *athena_types.InvalidRequestException
			if errors.As(err, &invalid) {
				log.Debug().Str("region", region).Str("workgroup", workgroup).
					Msg("workgroup no longer available while listing named queries")
				return nil, nil
			}
			return nil, err
		}
		queryIds = append(queryIds, page.NamedQueryIds...)
	}
	return queryIds, nil
}

func (a *mqlAwsAthena) getNamedQueries(conn *connection.AwsConnection, workgroupsByRegion map[string][]string) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0, len(workgroupsByRegion))

	for region, workgroupNames := range workgroupsByRegion {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Int("workgroups", len(workgroupNames)).
				Msg("athena>getNamedQueries>calling aws")

			svc := conn.Athena(region)
			ctx := context.Background()
			res := []any{}

			for _, workgroup := range workgroupNames {
				queryIds, err := listNamedQueryIDs(ctx, svc, region, workgroup)
				if err != nil {
					return nil, err
				}

				// Batch get named queries (max 50 per call)
				for chunk := range slices.Chunk(queryIds, 50) {
					batch, err := svc.BatchGetNamedQuery(ctx, &athena.BatchGetNamedQueryInput{
						NamedQueryIds: chunk,
					})
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Str("workgroup", workgroup).
								Msg("not permitted to read the named queries of this workgroup")
							break
						}
						return nil, err
					}
					for _, nq := range batch.NamedQueries {
						mqlNQ, err := newMqlAwsAthenaNamedQuery(a.MqlRuntime, region, workgroup, nq)
						if err != nil {
							return nil, err
						}
						res = append(res, mqlNQ)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsAthenaNamedQuery(runtime *plugin.Runtime, region, workgroup string, nq athena_types.NamedQuery) (*mqlAwsAthenaNamedQuery, error) {
	id := fmt.Sprintf("aws.athena.namedQuery/%s/%s", region, convert.ToValue(nq.NamedQueryId))

	// BatchGetNamedQuery does not always report the workgroup, but the query was
	// listed under a known one, so fall back to that rather than leaving the
	// reference unset.
	queryWorkgroup := convert.ToValue(nq.WorkGroup)
	if queryWorkgroup == "" {
		queryWorkgroup = workgroup
	}

	resource, err := CreateResource(runtime, "aws.athena.namedQuery",
		map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"id":          llx.StringDataPtr(nq.NamedQueryId),
			"name":        llx.StringDataPtr(nq.Name),
			"database":    llx.StringDataPtr(nq.Database),
			"queryString": llx.StringDataPtr(nq.QueryString),
			"description": llx.StringDataPtr(nq.Description),
			"workGroup":   llx.StringData(queryWorkgroup),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaNamedQuery), nil
}

func (a *mqlAwsAthenaNamedQuery) queryWorkgroup() (*mqlAwsAthenaWorkgroup, error) {
	name := a.WorkGroup.Data
	if name == "" {
		a.QueryWorkgroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := fmt.Sprintf("arn:aws:athena:%s:%s:workgroup/%s", a.Region.Data, conn.AccountId(), name)
	mqlWg, err := NewResource(a.MqlRuntime, "aws.athena.workgroup",
		map[string]*llx.RawData{
			"arn": llx.StringData(arn),
		})
	if err != nil {
		return nil, err
	}
	return mqlWg.(*mqlAwsAthenaWorkgroup), nil
}

func (a *mqlAwsAthenaWorkgroup) tags() (map[string]any, error) {
	if a.Arn.Error != nil {
		return nil, a.Arn.Error
	}
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	arn := a.Arn.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Athena(region)
	ctx := context.Background()

	tags := make(map[string]any)
	var nextToken *string
	for {
		resp, err := svc.ListTagsForResource(ctx, &athena.ListTagsForResourceInput{
			ResourceARN: &arn,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, tag := range resp.Tags {
			if tag.Key != nil && tag.Value != nil {
				tags[*tag.Key] = *tag.Value
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return tags, nil
}

func (a *mqlAwsAthena) capacityReservations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCapacityReservations(conn), 5)
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

func (a *mqlAwsAthena) getCapacityReservations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("athena>getCapacityReservations>calling aws with region %s", region)

			svc := conn.Athena(region)
			ctx := context.Background()
			res := []any{}

			paginator := athena.NewListCapacityReservationsPaginator(svc, &athena.ListCapacityReservationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cr := range page.CapacityReservations {
					mqlCr, err := newMqlAwsAthenaCapacityReservation(a.MqlRuntime, region, conn.AccountId(), cr)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCr)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsAthenaCapacityReservation(runtime *plugin.Runtime, region string, accountID string, cr athena_types.CapacityReservation) (*mqlAwsAthenaCapacityReservation, error) {
	arn := fmt.Sprintf("arn:aws:athena:%s:%s:capacity-reservation/%s", region, accountID, convert.ToValue(cr.Name))

	resource, err := CreateResource(runtime, "aws.athena.capacityReservation",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(arn),
			"arn":                        llx.StringData(arn),
			"name":                       llx.StringDataPtr(cr.Name),
			"status":                     llx.StringData(string(cr.Status)),
			"allocatedDpus":              llx.IntDataPtr(cr.AllocatedDpus),
			"targetDpus":                 llx.IntDataPtr(cr.TargetDpus),
			"createdAt":                  llx.TimeDataPtr(cr.CreationTime),
			"lastSuccessfulAllocationAt": llx.TimeDataPtr(cr.LastSuccessfulAllocationTime),
			"region":                     llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaCapacityReservation), nil
}

func (a *mqlAwsAthenaDataCatalog) databases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Athena(a.Region.Data)
	ctx := context.Background()

	catalogName := a.Name.Data
	res := []any{}
	paginator := athena.NewListDatabasesPaginator(svc, &athena.ListDatabasesInput{
		CatalogName: &catalogName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("catalog", catalogName).Msg("error listing Athena databases")
				return res, nil
			}
			return nil, err
		}
		for _, db := range page.DatabaseList {
			mqlDb, err := newMqlAwsAthenaDatabase(a.MqlRuntime, a.Region.Data, catalogName, db)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDb)
		}
	}
	return res, nil
}

func newMqlAwsAthenaDatabase(runtime *plugin.Runtime, region string, catalogName string, db athena_types.Database) (*mqlAwsAthenaDatabase, error) {
	id := fmt.Sprintf("aws.athena.database/%s/%s/%s", region, catalogName, convert.ToValue(db.Name))

	resource, err := CreateResource(runtime, "aws.athena.database",
		map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"name":        llx.StringDataPtr(db.Name),
			"catalogName": llx.StringData(catalogName),
			"description": llx.StringDataPtr(db.Description),
			"parameters":  llx.MapData(stringMapToAny(db.Parameters), types.String),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaDatabase), nil
}

func (a *mqlAwsAthenaDatabase) tables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Athena(a.Region.Data)
	ctx := context.Background()

	catalogName := a.CatalogName.Data
	dbName := a.Name.Data
	res := []any{}
	paginator := athena.NewListTableMetadataPaginator(svc, &athena.ListTableMetadataInput{
		CatalogName:  &catalogName,
		DatabaseName: &dbName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("catalog", catalogName).Str("database", dbName).Msg("error listing Athena table metadata")
				return res, nil
			}
			return nil, err
		}
		for _, tbl := range page.TableMetadataList {
			mqlTbl, err := newMqlAwsAthenaTable(a.MqlRuntime, a.Region.Data, catalogName, dbName, tbl)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTbl)
		}
	}
	return res, nil
}

func newMqlAwsAthenaTable(runtime *plugin.Runtime, region, catalogName, dbName string, tbl athena_types.TableMetadata) (*mqlAwsAthenaTable, error) {
	id := fmt.Sprintf("aws.athena.table/%s/%s/%s/%s", region, catalogName, dbName, convert.ToValue(tbl.Name))

	resource, err := CreateResource(runtime, "aws.athena.table",
		map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"name":          llx.StringDataPtr(tbl.Name),
			"tableType":     llx.StringDataPtr(tbl.TableType),
			"createdAt":     llx.TimeDataPtr(tbl.CreateTime),
			"lastAccessAt":  llx.TimeDataPtr(tbl.LastAccessTime),
			"columns":       llx.ArrayData(athenaColumnsToDict(tbl.Columns), types.Dict),
			"partitionKeys": llx.ArrayData(athenaColumnsToDict(tbl.PartitionKeys), types.Dict),
			"parameters":    llx.MapData(stringMapToAny(tbl.Parameters), types.String),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsAthenaTable), nil
}

// athenaColumnsToDict converts Athena column metadata to a list of dicts, each
// carrying the column name, data type, and comment.
func athenaColumnsToDict(cols []athena_types.Column) []any {
	res := make([]any, 0, len(cols))
	for _, c := range cols {
		res = append(res, map[string]any{
			"name":    convert.ToValue(c.Name),
			"type":    convert.ToValue(c.Type),
			"comment": convert.ToValue(c.Comment),
		})
	}
	return res
}
