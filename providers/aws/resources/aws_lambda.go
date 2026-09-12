// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go/transport/http"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsLambda) id() (string, error) {
	return "aws.lambda", nil
}

func (a *mqlAwsLambda) functions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFunctions(conn), 5)
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

func (a *mqlAwsLambda) getFunctions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lambda>getFunctions>calling aws with region %s", region)

			svc := conn.Lambda(region)
			ctx := context.Background()
			res := []any{}
			params := &lambda.ListFunctionsInput{}
			paginator := lambda.NewListFunctionsPaginator(svc, params)
			for paginator.HasMorePages() {
				functionsResp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws lambda functions")
				}
				// Pre-fetch tags in parallel when tag-based filters are configured.
				// Lambda's ListTags has no batch endpoint, so this turns a sequential
				// per-function call into bounded concurrent calls.
				var tagsByArn map[string]map[string]string
				if conn.Filters.General.HasTags() {
					arns := make([]string, 0, len(functionsResp.Functions))
					for _, function := range functionsResp.Functions {
						if function.FunctionArn != nil {
							arns = append(arns, *function.FunctionArn)
						}
					}
					tagsByArn = fetchTagsConcurrently(ctx, arns, func(ctx context.Context, functionArn string) (map[string]string, error) {
						resp, err := svc.ListTags(ctx, &lambda.ListTagsInput{Resource: &functionArn})
						if err != nil {
							return nil, err
						}
						if resp == nil {
							return nil, errors.New("empty ListTags response")
						}
						return resp.Tags, nil
					})
				}
				for _, function := range functionsResp.Functions {
					var tags map[string]string
					var fetched bool
					if conn.Filters.General.HasTags() {
						// An absent entry means the ListTags call failed for this
						// function; IsFilteredOutByTags treats the resulting nil
						// identically to an empty map (no include-filter match →
						// drop), preserving the pre-parallelization best-effort
						// behavior.
						tags, fetched = tagsByArn[convert.ToValue(function.FunctionArn)]
						if conn.Filters.General.IsFilteredOutByTags(tags) {
							log.Debug().Interface("function", function.FunctionArn).Msg("excluding function due to filters")
							continue
						}
					}

					f, err := newLambdaFunctionResource(a.MqlRuntime, region, conn.AccountId(), function)
					if err != nil {
						return nil, err
					}
					// Only cache a tag set we actually read. Caching for a function
					// whose ListTags call failed would report "no tags" as fact;
					// leaving tagsFetched false lets the accessor retry and surface
					// the real error.
					if fetched {
						f.cacheTags = tags
						f.tagsFetched = true
					}
					res = append(res, f)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func getLambdaArn(name string, region string, accountId string) string {
	return arn.ARN{
		Region:    region,
		Partition: "aws",
		Service:   "lambda",
		AccountID: accountId,
		Resource:  "function:" + name,
	}.String()
}

// newLambdaFunctionResource maps an SDK FunctionConfiguration into an
// aws.lambda.function resource, building its sub-resources (loggingConfig,
// layers) and priming every Internal cache (role ARN, region, account, VPC)
// that the lazy accessors depend on. Shared by the list path and the targeted
// init lookup.
func newLambdaFunctionResource(runtime *plugin.Runtime, region string, accountID string, function lambdatypes.FunctionConfiguration) (*mqlAwsLambdaFunction, error) {
	// A function with no dead-letter config has no target ARN; reporting ""
	// would assert "not configured" as a measured value.
	var dlqTarget *string
	if function.DeadLetterConfig != nil {
		dlqTarget = function.DeadLetterConfig.TargetArn
	}

	// Convert architectures to []any
	architectures := make([]any, len(function.Architectures))
	for i, arch := range function.Architectures {
		architectures[i] = string(arch)
	}

	// Get ephemeral storage size (defaults to 512 MB if not set)
	var ephemeralStorageSize int64 = 512
	if function.EphemeralStorage != nil && function.EphemeralStorage.Size != nil {
		ephemeralStorageSize = int64(*function.EphemeralStorage.Size)
	}

	var tracingMode string
	if function.TracingConfig != nil {
		tracingMode = string(function.TracingConfig.Mode)
	}

	var lastModifiedAt *time.Time
	if function.LastModified != nil {
		if t, err := time.Parse("2006-01-02T15:04:05.000-0700", *function.LastModified); err == nil {
			lastModifiedAt = &t
		}
	}

	// Extract SnapStart fields
	var snapStartApplyOn, snapStartOptimizationStatus string
	if function.SnapStart != nil {
		snapStartApplyOn = string(function.SnapStart.ApplyOn)
		snapStartOptimizationStatus = string(function.SnapStart.OptimizationStatus)
	}

	// Extract environment variables
	envVars := map[string]any{}
	if function.Environment != nil && function.Environment.Variables != nil {
		for k, v := range function.Environment.Variables {
			envVars[k] = v
		}
	}

	// Convert file system configs to dict slice
	fileSystemConfigs, err := convert.JsonToDictSlice(function.FileSystemConfigs)
	if err != nil {
		return nil, err
	}

	funcArn := convert.ToValue(function.FunctionArn)

	// Create logging config sub-resource
	var loggingConfigResource plugin.Resource
	if function.LoggingConfig != nil {
		lc, err := CreateResource(runtime, "aws.lambda.function.loggingConfig",
			map[string]*llx.RawData{
				"__id":                llx.StringData(funcArn + "/loggingConfig"),
				"logFormat":           llx.StringData(string(function.LoggingConfig.LogFormat)),
				"applicationLogLevel": llx.StringData(string(function.LoggingConfig.ApplicationLogLevel)),
				"systemLogLevel":      llx.StringData(string(function.LoggingConfig.SystemLogLevel)),
				"logGroup":            llx.StringDataPtr(function.LoggingConfig.LogGroup),
			})
		if err != nil {
			return nil, err
		}
		loggingConfigResource = lc.(plugin.Resource)
	}

	// Create layer sub-resources
	layers := make([]any, 0, len(function.Layers))
	for _, layer := range function.Layers {
		mqlLayer, err := CreateResource(runtime, "aws.lambda.function.layer",
			map[string]*llx.RawData{
				"__id":                     llx.StringDataPtr(layer.Arn),
				"arn":                      llx.StringDataPtr(layer.Arn),
				"codeSize":                 llx.IntData(layer.CodeSize),
				"signingJobArn":            llx.StringDataPtr(layer.SigningJobArn),
				"signingProfileVersionArn": llx.StringDataPtr(layer.SigningProfileVersionArn),
			})
		if err != nil {
			return nil, err
		}
		layers = append(layers, mqlLayer)
	}

	args := map[string]*llx.RawData{
		"arn":                         llx.StringDataPtr(function.FunctionArn),
		"name":                        llx.StringDataPtr(function.FunctionName),
		"runtime":                     llx.StringData(string(function.Runtime)),
		"dlqTargetArn":                llx.StringDataPtr(dlqTarget),
		"region":                      llx.StringData(region),
		"architectures":               llx.ArrayData(architectures, types.String),
		"ephemeralStorageSize":        llx.IntData(ephemeralStorageSize),
		"memorySize":                  llx.IntDataDefault(function.MemorySize, 0),
		"timeout":                     llx.IntDataDefault(function.Timeout, 3),
		"handler":                     llx.StringDataPtr(function.Handler),
		"tracingMode":                 llx.StringData(tracingMode),
		"packageType":                 llx.StringData(string(function.PackageType)),
		"codeSha256":                  llx.StringDataPtr(function.CodeSha256),
		"revisionId":                  llx.StringDataPtr(function.RevisionId),
		"description":                 llx.StringDataPtr(function.Description),
		"lastModifiedAt":              llx.TimeDataPtr(lastModifiedAt),
		"codeSize":                    llx.IntData(function.CodeSize),
		"environment":                 llx.MapData(envVars, types.String),
		"snapStartApplyOn":            llx.StringData(snapStartApplyOn),
		"snapStartOptimizationStatus": llx.StringData(snapStartOptimizationStatus),
		"fileSystemConfigs":           llx.ArrayData(fileSystemConfigs, types.Dict),
		"signingProfileVersionArn":    llx.StringDataPtr(function.SigningProfileVersionArn),
		"signingJobArn":               llx.StringDataPtr(function.SigningJobArn),
		"layers":                      llx.ArrayData(layers, types.Resource("aws.lambda.function.layer")),
		"masterArn":                   llx.StringDataPtr(function.MasterArn),
	}

	if function.DurableConfig != nil {
		args["durableExecutionTimeout"] = llx.IntDataPtr(function.DurableConfig.ExecutionTimeout)
		args["durableExecutionRetentionDays"] = llx.IntDataPtr(function.DurableConfig.RetentionPeriodInDays)
	} else {
		args["durableExecutionTimeout"] = llx.NilData
		args["durableExecutionRetentionDays"] = llx.NilData
	}

	if loggingConfigResource != nil {
		args["loggingConfig"] = llx.ResourceData(loggingConfigResource, "aws.lambda.function.loggingConfig")
	} else {
		args["loggingConfig"] = llx.NilData
	}

	mqlFunc, err := CreateResource(runtime, "aws.lambda.function", args)
	if err != nil {
		return nil, err
	}
	mqlFunc.(*mqlAwsLambdaFunction).cacheKmsKeyArn = convert.ToValue(function.KMSKeyArn)
	f := mqlFunc.(*mqlAwsLambdaFunction)
	// A GetFunction lookup already carries the lifecycle fields, so seeding the
	// memo here spares that path the extra GetFunctionConfiguration call. A
	// ListFunctions summary carries none of them and seeds nothing, leaving the
	// accessors to read them.
	if status := lambdaStatusFromConfiguration(&function); status != nil {
		f.status = status
		f.statusFetched.Store(true)
	}
	f.cacheRoleArn = function.Role
	f.region = region
	f.accountID = accountID
	if function.DurableConfig != nil {
		f.cacheDurableExecutionKmsKeyArn = function.DurableConfig.KMSKeyArn
	}
	if function.VpcConfig != nil {
		f.cacheVpcId = function.VpcConfig.VpcId
		f.cacheSubnetIds = function.VpcConfig.SubnetIds
		var sgArns []string
		for _, sgId := range function.VpcConfig.SecurityGroupIds {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sgId))
		}
		f.setSecurityGroupArns(sgArns)
	}
	return f, nil
}

func initAwsLambdaFunction(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformLambdaFunction); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	nameArg := args["name"]
	regionArg := args["region"]

	var arnVal string
	if args["arn"] == nil {
		if nameArg == nil {
			return nil, nil, errors.New("name required to fetch lambda function")
		}
		if regionArg == nil {
			return nil, nil, errors.New("region required to fetch lambda function")
		}
		// Read the values, not their display form: RawData.String() renders a
		// string wrapped in quote characters, which would go straight into the
		// composed ARN and match nothing.
		name, _ := nameArg.Value.(string)
		regionVal, _ := regionArg.Value.(string)
		if name == "" || regionVal == "" {
			return nil, nil, errors.New("name and region required to fetch lambda function")
		}
		conn := runtime.Connection.(*connection.AwsConnection)
		arnVal = getLambdaArn(name, regionVal, conn.AccountId())
		if arnVal == "" {
			return nil, nil, errors.New("arn required to fetch lambda function")
		}
	} else {
		arnVal = args["arn"].Value.(string)
	}

	if cached := cachedByArn(runtime, ResourceAwsLambdaFunction, arnVal); cached != nil {
		return args, cached, nil
	}

	// Targeted lookup: derive the region + function name from the ARN and fetch
	// just this one function instead of listing every function in every region.
	region := ""
	funcName := ""
	if parsed, parseErr := arn.Parse(arnVal); parseErr == nil && strings.HasPrefix(parsed.Resource, "function:") {
		region = parsed.Region
		funcName = strings.TrimPrefix(parsed.Resource, "function:")
	}
	if regionArg != nil {
		if r, ok := regionArg.Value.(string); ok && r != "" {
			region = r
		}
	}
	if nameArg != nil {
		if n, ok := nameArg.Value.(string); ok && n != "" {
			funcName = n
		}
	}
	if region != "" && funcName != "" {
		conn := runtime.Connection.(*connection.AwsConnection)
		svc := conn.Lambda(region)
		resp, err := svc.GetFunction(context.Background(), &lambda.GetFunctionInput{FunctionName: &funcName})
		if err != nil {
			// Fall through to the list-scan fallback on not-found / access-denied;
			// surface any other error.
			if !isResourceNotFoundError(err) && !Is400AccessDeniedError(err) {
				return nil, nil, err
			}
		} else if resp.Configuration != nil {
			f, err := newLambdaFunctionResource(runtime, region, conn.AccountId(), *resp.Configuration)
			if err != nil {
				return nil, nil, err
			}
			return args, f, nil
		}
	}

	// Fallback: scan all functions (e.g. cross-account references or when the
	// ARN carries no usable region).
	obj, err := CreateResource(runtime, "aws.lambda", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	l := obj.(*mqlAwsLambda)

	rawResources := l.GetFunctions()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	for _, rawResource := range rawResources.Data {
		fn := rawResource.(*mqlAwsLambdaFunction)
		if fn.Arn.Data == arnVal {
			return args, fn, nil
		}
	}
	return nil, nil, errors.New("lambda function does not exist")
}

func (a *mqlAwsLambdaFunction) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsLambdaFunctionInternal struct {
	cacheKmsKeyArn string
	securityGroupIdHandler
	cacheRoleArn          *string
	cacheTags             map[string]string
	tagsFetched           bool
	tagsLock              sync.Mutex
	cacheVpcId            *string
	cacheSubnetIds        []string
	region                string
	accountID             string
	imageDataFetched      bool
	imageDataLock         sync.Mutex
	cacheImageUri         *string
	cacheResolvedImageUri *string
	cacheSourceKmsKeyArn  *string

	cacheDurableExecutionKmsKeyArn *string

	runtimeMgmtOnce sync.Once
	runtimeMgmtResp *lambda.GetRuntimeManagementConfigOutput
	runtimeMgmtErr  error

	statusFetched atomic.Bool
	statusLock    sync.Mutex
	status        *lambdaFunctionStatus
}

// lambdaFunctionStatus carries the lifecycle values that only a per-function
// configuration lookup reports. The ListFunctions summary omits every one of
// them, so a function reached through the list has to read them separately.
type lambdaFunctionStatus struct {
	state                  string
	stateReason            *string
	lastUpdateStatus       string
	lastUpdateStatusReason *string
	runtimeVersionArn      *string
}

// State reports the function lifecycle state, empty when nothing was read.
func (s *lambdaFunctionStatus) State() string {
	if s == nil {
		return ""
	}
	return s.state
}

// StateReason reports why the function is in its current state, empty when
// nothing was read or AWS gave no reason.
func (s *lambdaFunctionStatus) StateReason() string {
	if s == nil {
		return ""
	}
	return convert.ToValue(s.stateReason)
}

// LastUpdateStatus reports the outcome of the most recent update, empty when
// nothing was read.
func (s *lambdaFunctionStatus) LastUpdateStatus() string {
	if s == nil {
		return ""
	}
	return s.lastUpdateStatus
}

// LastUpdateStatusReason reports why the most recent update ended the way it
// did, empty when nothing was read or AWS gave no reason.
func (s *lambdaFunctionStatus) LastUpdateStatusReason() string {
	if s == nil {
		return ""
	}
	return convert.ToValue(s.lastUpdateStatusReason)
}

// RuntimeVersionArn reports the patched managed-runtime build the function
// runs on, empty when nothing was read or the runtime has no versioned build.
func (s *lambdaFunctionStatus) RuntimeVersionArn() string {
	if s == nil {
		return ""
	}
	return convert.ToValue(s.runtimeVersionArn)
}

// lambdaStatusFromConfiguration reads the lifecycle values off a function
// configuration, returning nil when the configuration carries none of them.
// ListFunctions returns a summary with State, StateReason, LastUpdateStatus,
// LastUpdateStatusReason and RuntimeVersionConfig all absent; treating that
// summary as a status would report "" for every function in every account.
// A real configuration always names a state.
func lambdaStatusFromConfiguration(cfg *lambdatypes.FunctionConfiguration) *lambdaFunctionStatus {
	if cfg == nil || cfg.State == "" {
		return nil
	}
	status := &lambdaFunctionStatus{
		state:                  string(cfg.State),
		stateReason:            cfg.StateReason,
		lastUpdateStatus:       string(cfg.LastUpdateStatus),
		lastUpdateStatusReason: cfg.LastUpdateStatusReason,
	}
	if cfg.RuntimeVersionConfig != nil {
		status.runtimeVersionArn = cfg.RuntimeVersionConfig.RuntimeVersionArn
	}
	return status
}

// lambdaStatusFromConfigurationOutput reads the lifecycle values off a
// GetFunctionConfiguration response, which flattens the same fields the
// FunctionConfiguration struct nests.
func lambdaStatusFromConfigurationOutput(resp *lambda.GetFunctionConfigurationOutput) *lambdaFunctionStatus {
	if resp == nil {
		return nil
	}
	return lambdaStatusFromConfiguration(&lambdatypes.FunctionConfiguration{
		State:                  resp.State,
		StateReason:            resp.StateReason,
		LastUpdateStatus:       resp.LastUpdateStatus,
		LastUpdateStatusReason: resp.LastUpdateStatusReason,
		RuntimeVersionConfig:   resp.RuntimeVersionConfig,
	})
}

// nullOnEmpty reports value, marking the field null when the value is empty.
// The callers read values that AWS either names or omits entirely, so an empty
// string means the value was never read and must not be asserted as measured.
func nullOnEmpty(field *plugin.TValue[string], value string) (string, error) {
	if value == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return value, nil
}

// fetchStatus resolves the lifecycle values a ListFunctions summary omits,
// with one GetFunctionConfiguration call shared by every field derived from
// it. A 404 or an access denial leaves the status absent, so those fields read
// as null rather than as an empty string.
func (a *mqlAwsLambdaFunction) fetchStatus() (*lambdaFunctionStatus, error) {
	if a.statusFetched.Load() {
		return a.status, nil
	}
	a.statusLock.Lock()
	defer a.statusLock.Unlock()
	if a.statusFetched.Load() {
		return a.status, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Lambda(a.Region.Data)
	funcName := a.Name.Data
	resp, err := svc.GetFunctionConfiguration(context.Background(), &lambda.GetFunctionConfigurationInput{
		FunctionName: &funcName,
	})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.statusFetched.Store(true)
			return nil, nil
		}
		if Is400AccessDeniedError(err) {
			a.statusFetched.Store(true)
			return nil, nil
		}
		return nil, err
	}

	a.status = lambdaStatusFromConfigurationOutput(resp)
	a.statusFetched.Store(true)
	return a.status, nil
}

func (a *mqlAwsLambdaFunction) state() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		return "", err
	}
	return nullOnEmpty(&a.State, status.State())
}

func (a *mqlAwsLambdaFunction) stateReason() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		return "", err
	}
	return nullOnEmpty(&a.StateReason, status.StateReason())
}

func (a *mqlAwsLambdaFunction) lastUpdateStatus() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		return "", err
	}
	return nullOnEmpty(&a.LastUpdateStatus, status.LastUpdateStatus())
}

func (a *mqlAwsLambdaFunction) lastUpdateStatusReason() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		return "", err
	}
	return nullOnEmpty(&a.LastUpdateStatusReason, status.LastUpdateStatusReason())
}

// fetchImageData resolves the container image URIs for Image package type
// functions via a GetFunction call, caching the result with double-check
// locking. Zip functions leave the cached URIs nil.
func (a *mqlAwsLambdaFunction) fetchImageData() error {
	if a.imageDataFetched {
		return nil
	}
	a.imageDataLock.Lock()
	defer a.imageDataLock.Unlock()
	if a.imageDataFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Lambda(a.Region.Data)
	ctx := context.Background()

	funcName := a.Name.Data
	resp, err := svc.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: &funcName})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.imageDataFetched = true
			return nil
		}
		return err
	}
	if resp.Code != nil {
		a.cacheImageUri = resp.Code.ImageUri
		a.cacheResolvedImageUri = resp.Code.ResolvedImageUri
		a.cacheSourceKmsKeyArn = resp.Code.SourceKMSKeyArn
	}
	a.imageDataFetched = true
	return nil
}

// sourceKmsKey resolves the KMS key used to encrypt the function's deployment
// package, when one is configured. Backed by the same GetFunction call as the
// image URIs.
func (a *mqlAwsLambdaFunction) sourceKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchImageData(); err != nil {
		return nil, err
	}
	if a.cacheSourceKmsKeyArn == nil || *a.cacheSourceKmsKeyArn == "" {
		a.SourceKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSourceKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// durableExecutionKmsKey resolves the customer-managed KMS key that encrypts a
// durable function's execution payload data, when one is configured. Cached
// from the durable config at creation time.
func (a *mqlAwsLambdaFunction) durableExecutionKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheDurableExecutionKmsKeyArn == nil || *a.cacheDurableExecutionKmsKeyArn == "" {
		a.DurableExecutionKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheDurableExecutionKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// masterFunction resolves the master function this Lambda was configured from,
// when present in this account (set for replicated functions such as
// Lambda@Edge replicas).
func (a *mqlAwsLambdaFunction) masterFunction() (*mqlAwsLambdaFunction, error) {
	if !a.MasterArn.IsSet() || a.MasterArn.Data == "" {
		a.MasterFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(a.MasterArn.Data)})
	if err != nil {
		a.MasterFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsLambdaFunction) imageUri() (string, error) {
	if err := a.fetchImageData(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheImageUri), nil
}

func (a *mqlAwsLambdaFunction) resolvedImageUri() (string, error) {
	if err := a.fetchImageData(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheResolvedImageUri), nil
}

func (a *mqlAwsLambdaFunction) tags() (map[string]any, error) {
	if a.tagsFetched {
		return toInterfaceMap(a.cacheTags), nil
	}
	a.tagsLock.Lock()
	defer a.tagsLock.Unlock()
	if a.tagsFetched {
		return toInterfaceMap(a.cacheTags), nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Lambda(a.Region.Data)
	ctx := context.Background()

	funcArn := a.Arn.Data
	tagsResp, err := svc.ListTags(ctx, &lambda.ListTagsInput{Resource: &funcArn})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.tagsFetched = true
			return nil, nil
		}
		return nil, err
	}
	a.cacheTags = tagsResp.Tags
	a.tagsFetched = true
	return toInterfaceMap(tagsResp.Tags), nil
}

func (a *mqlAwsLambdaFunction) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheKmsKeyArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsLambdaFunction) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	vpcArn := fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsLambdaFunction) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return nil, nil
	}
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsLambdaFunction) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsLambdaFunction) recursiveLoop() (string, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	cfg, err := svc.GetFunctionRecursionConfig(ctx, &lambda.GetFunctionRecursionConfigInput{FunctionName: &funcName})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "", nil
		}
		return "", errors.Wrap(err, "could not gather aws lambda function recursion config")
	}
	return string(cfg.RecursiveLoop), nil
}

func (a *mqlAwsLambdaFunction) concurrency() (int64, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	// no pagination required
	functionConcurrency, err := svc.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{FunctionName: &funcName})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.Concurrency.State = plugin.StateIsSet | plugin.StateIsNull
			return 0, nil
		}
		return 0, errors.Wrap(err, "could not gather aws lambda function concurrency")
	}
	return reservedConcurrency(&a.Concurrency, functionConcurrency.ReservedConcurrentExecutions)
}

// reservedConcurrency reports a function's reserved concurrency, keeping an
// absent reservation distinct from a reservation of zero. They are opposite
// postures: no reservation draws on the account's unreserved pool, while a
// reservation of zero throttles the function so it cannot be invoked at all.
func reservedConcurrency(field *plugin.TValue[int64], reserved *int32) (int64, error) {
	if reserved == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*reserved), nil
}

func (a *mqlAwsLambdaFunction) policy() (any, error) {
	funcArn := a.Arn.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	// no pagination required
	functionPolicy, err := svc.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: &funcArn})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			return nil, nil
		}
		return nil, err
	}
	if functionPolicy != nil && functionPolicy.Policy != nil {
		// Unmarshal into a plain any, matching SNS/SQS/ECR. Decoding into a
		// hand-written struct dropped Condition, NotPrincipal, NotAction and
		// NotResource, so isPublic/allowsPublicAccess could never see a scoping
		// condition -- an org-scoped Function URL read as fully public. The
		// struct also typed Action as a string, so any array-valued Action
		// failed to unmarshal and errored the whole field.
		var policyDoc any
		if err := json.Unmarshal([]byte(*functionPolicy.Policy), &policyDoc); err != nil {
			return nil, err
		}
		return policyDoc, nil
	}

	return nil, nil
}

// allowsPublicAccess reports whether the function's resource policy grants a
// wildcard principal access through an Allow statement that lacks a scoping
// condition on aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID. It is
// false when the function has no resource policy.
func (a *mqlAwsLambdaFunction) allowsPublicAccess() (bool, error) {
	stmts, err := a.policyStatements()
	if err != nil {
		return false, err
	}
	return statementsAllowPublic(stmts)
}

// hasWildcardPrincipal reports whether a parsed policy-statement principal map
// grants access to the `*` wildcard under any principal type.
func hasWildcardPrincipal(principals any) bool {
	m, ok := principals.(map[string]any)
	if !ok {
		return false
	}
	for _, v := range m {
		list, ok := v.([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

// hasSourceScopingCondition reports whether a statement condition map scopes
// access with a non-wildcard aws:SourceArn, aws:SourceAccount,
// aws:SourceOwner, or aws:PrincipalOrgID value.
func hasSourceScopingCondition(conditions any) bool {
	m, ok := conditions.(map[string]any)
	if !ok {
		return false
	}
	for op, opVal := range m {
		// The operator decides whether a condition narrows or widens the grant.
		// StringNotEquals on aws:PrincipalOrgID means "allow everyone OUTSIDE my
		// org" and Null means "allow principals for which the key is absent" --
		// both strictly worse than an unconditional public grant, yet the
		// operator-blind version read them as "scoped" and reported not-public.
		if !isRestrictingConditionOperator(op) {
			continue
		}
		keys, ok := opVal.(map[string]any)
		if !ok {
			continue
		}
		for key, val := range keys {
			if isSourceScopingKey(key) && !conditionValueIsWildcard(val) {
				return true
			}
		}
	}
	return false
}

// isRestrictingConditionOperator reports whether an IAM condition operator
// narrows a grant. Negated forms (StringNotEquals, ArnNotLike, ...) and Null
// widen it, so a scoping key under one of those must not count as scoped.
// The ForAllValues:/ForAnyValue: set qualifiers and the IfExists suffix are
// stripped first; IfExists still restricts when the key is present.
func isRestrictingConditionOperator(op string) bool {
	o := strings.ToLower(op)
	o = strings.TrimPrefix(o, "forallvalues:")
	o = strings.TrimPrefix(o, "foranyvalue:")
	o = strings.TrimSuffix(o, "ifexists")
	switch o {
	case "stringequals", "stringlike", "stringequalsignorecase",
		"arnequals", "arnlike":
		return true
	}
	return false
}

// isSourceScopingKey reports whether a condition key pins a wildcard principal
// to a specific caller. aws:SourceOwner is the account-ID form SNS uses, and is
// what the AWS-generated default topic policy carries; it scopes a grant
// exactly as aws:SourceAccount does.
func isSourceScopingKey(key string) bool {
	switch strings.ToLower(key) {
	case "aws:sourcearn", "aws:sourceaccount", "aws:sourceowner", "aws:principalorgid",
		// Additional keys that genuinely confine a wildcard principal. Without
		// these, AWS's own service-linked KMS grants (kms:CallerAccount +
		// kms:ViaService) and VPC-endpoint-restricted buckets reported public.
		"aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
		"aws:sourceorgid", "aws:sourceorgpaths", "aws:resourceorgid",
		"aws:sourcevpc", "aws:sourcevpce",
		"kms:calleraccount":
		return true
	}
	return false
}

func conditionValueIsWildcard(val any) bool {
	switch v := val.(type) {
	case string:
		return v == "*"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

func (a *mqlAwsLambdaFunction) urlConfig() (*mqlAwsLambdaFunctionUrlConfig, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	resp, err := svc.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: &funcName})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.UrlConfig.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	var corsAllowOrigins, corsAllowMethods, corsAllowHeaders, corsExposeHeaders []any
	var corsAllowCredentials bool
	var corsMaxAge int64
	if resp.Cors != nil {
		corsAllowOrigins = toInterfaceArr(resp.Cors.AllowOrigins)
		corsAllowMethods = toInterfaceArr(resp.Cors.AllowMethods)
		corsAllowHeaders = toInterfaceArr(resp.Cors.AllowHeaders)
		corsExposeHeaders = toInterfaceArr(resp.Cors.ExposeHeaders)
		if resp.Cors.AllowCredentials != nil {
			corsAllowCredentials = *resp.Cors.AllowCredentials
		}
		if resp.Cors.MaxAge != nil {
			corsMaxAge = int64(*resp.Cors.MaxAge)
		}
	}

	res, err := CreateResource(a.MqlRuntime, "aws.lambda.function.urlConfig",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Arn.Data + "/urlConfig"),
			"functionUrl":          llx.StringDataPtr(resp.FunctionUrl),
			"authType":             llx.StringData(string(resp.AuthType)),
			"corsAllowOrigins":     llx.ArrayData(corsAllowOrigins, types.String),
			"corsAllowMethods":     llx.ArrayData(corsAllowMethods, types.String),
			"corsAllowHeaders":     llx.ArrayData(corsAllowHeaders, types.String),
			"corsAllowCredentials": llx.BoolData(corsAllowCredentials),
			"corsExposeHeaders":    llx.ArrayData(corsExposeHeaders, types.String),
			"corsMaxAge":           llx.IntData(corsMaxAge),
			"createdAt":            llx.TimeDataPtr(parseAwsTimestampPtr(resp.CreationTime)),
			"lastModifiedAt":       llx.TimeDataPtr(parseAwsTimestampPtr(resp.LastModifiedTime)),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunctionUrlConfig), nil
}

// urlConfigAuthType exposes the function URL's authentication type directly on
// the function, returning "" when no URL is configured. Reading it avoids
// dereferencing the nullable urlConfig sub-resource, so a policy can check URL
// auth without a null-dereference on functions that have no URL.
func (a *mqlAwsLambdaFunction) urlConfigAuthType() (string, error) {
	cfg := a.GetUrlConfig()
	if cfg.Error != nil {
		return "", cfg.Error
	}
	if cfg.Data == nil {
		return "", nil
	}
	authType := cfg.Data.GetAuthType()
	if authType.Error != nil {
		return "", authType.Error
	}
	return authType.Data, nil
}

func (a *mqlAwsLambdaFunctionUrlConfig) id() (string, error) {
	return a.FunctionUrl.Data, nil
}

func (a *mqlAwsLambdaFunction) role() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.Role.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheRoleArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsLambdaFunctionLoggingConfig) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsLambdaFunctionLayer) id() (string, error) {
	return a.Arn.Data, nil
}

// ==================== Top-Level Layers ====================

func (a *mqlAwsLambda) layers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLayers(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsLambda) getLayers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lambda>getLayers>calling aws with region %s", region)

			svc := conn.Lambda(region)
			ctx := context.Background()
			res := []any{}

			paginator := lambda.NewListLayersPaginator(svc, &lambda.ListLayersInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws lambda layers")
				}
				for _, layer := range resp.Layers {
					var latestVersionArn, description, licenseInfo string
					var latestVersion int64
					var createdDate *time.Time
					compatibleRuntimes := []any{}
					compatibleArchitectures := []any{}

					if layer.LatestMatchingVersion != nil {
						v := layer.LatestMatchingVersion
						latestVersionArn = convert.ToValue(v.LayerVersionArn)
						description = convert.ToValue(v.Description)
						licenseInfo = convert.ToValue(v.LicenseInfo)
						latestVersion = v.Version
						createdDate = parseAwsTimestampPtr(v.CreatedDate)
						for _, rt := range v.CompatibleRuntimes {
							compatibleRuntimes = append(compatibleRuntimes, string(rt))
						}
						for _, arch := range v.CompatibleArchitectures {
							compatibleArchitectures = append(compatibleArchitectures, string(arch))
						}
					}

					mqlLayer, err := CreateResource(a.MqlRuntime, "aws.lambda.layer",
						map[string]*llx.RawData{
							"arn":                     llx.StringDataPtr(layer.LayerArn),
							"name":                    llx.StringDataPtr(layer.LayerName),
							"latestVersionArn":        llx.StringData(latestVersionArn),
							"latestVersion":           llx.IntData(latestVersion),
							"description":             llx.StringData(description),
							"compatibleRuntimes":      llx.ArrayData(compatibleRuntimes, types.String),
							"compatibleArchitectures": llx.ArrayData(compatibleArchitectures, types.String),
							"createdDate":             llx.TimeDataPtr(createdDate),
							"licenseInfo":             llx.StringData(licenseInfo),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlLayer)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsLambdaLayer) id() (string, error) {
	return a.Arn.Data, nil
}

// ==================== Top-Level Event Source Mappings ====================

func (a *mqlAwsLambda) eventSourceMappings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEventSourceMappings(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsLambda) getEventSourceMappings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("lambda>getEventSourceMappings>calling aws with region %s", region)

			svc := conn.Lambda(region)
			ctx := context.Background()
			res := []any{}

			paginator := lambda.NewListEventSourceMappingsPaginator(svc, &lambda.ListEventSourceMappingsInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws lambda event source mappings")
				}
				for _, esm := range resp.EventSourceMappings {
					mqlEsm, err := createEventSourceMappingResource(a.MqlRuntime, esm, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEsm)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// createEventSourceMappingResource creates an aws.lambda.eventSourceMapping resource from SDK data.
// Shared between top-level listing and per-function listing to ensure cache reuse via UUID-based __id.
func createEventSourceMappingResource(runtime *plugin.Runtime, esm lambdatypes.EventSourceMappingConfiguration, region string) (*mqlAwsLambdaEventSourceMapping, error) {
	args, err := eventSourceMappingArgs(esm, region)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "aws.lambda.eventSourceMapping", args)
	if err != nil {
		return nil, err
	}
	mqlEsm := res.(*mqlAwsLambdaEventSourceMapping)
	mqlEsm.cacheFunctionArn = convert.ToValue(esm.FunctionArn)
	mqlEsm.cacheArn = convert.ToValue(esm.EventSourceMappingArn)
	return mqlEsm, nil
}

// eventSourceMappingArgs maps an SDK event source mapping into resource
// arguments. Settings the mapping does not carry stay null: zero is outside
// the valid range of parallelizationFactor (1-10) and maximumConcurrency
// (2-1000), so reporting it would name a value that cannot exist. The -1
// fallbacks on maximumRetryAttempts and maximumRecordAgeInSeconds are the
// documented "retry forever" and "no maximum age" sentinels, not stand-ins.
func eventSourceMappingArgs(esm lambdatypes.EventSourceMappingConfiguration, region string) (map[string]*llx.RawData, error) {
	var onFailureDestinationArn *string
	if esm.DestinationConfig != nil && esm.DestinationConfig.OnFailure != nil {
		onFailureDestinationArn = esm.DestinationConfig.OnFailure.Destination
	}

	filterCriteria, err := convert.JsonToDict(esm.FilterCriteria)
	if err != nil {
		return nil, err
	}

	var maximumConcurrency *int32
	if esm.ScalingConfig != nil {
		maximumConcurrency = esm.ScalingConfig.MaximumConcurrency
	}

	// StartingPosition is only meaningful for stream and Kafka sources; an SQS
	// mapping has none, and "" is not one of its documented values.
	startingPosition := llx.NilData
	if esm.StartingPosition != "" {
		startingPosition = llx.StringData(string(esm.StartingPosition))
	}

	return map[string]*llx.RawData{
		"__id":                           llx.StringDataPtr(esm.UUID),
		"uuid":                           llx.StringDataPtr(esm.UUID),
		"eventSourceArn":                 llx.StringDataPtr(esm.EventSourceArn),
		"region":                         llx.StringData(region),
		"state":                          llx.StringDataPtr(esm.State),
		"stateTransitionReason":          llx.StringDataPtr(esm.StateTransitionReason),
		"batchSize":                      llx.IntDataDefault(esm.BatchSize, 0),
		"maximumBatchingWindowInSeconds": llx.IntDataDefault(esm.MaximumBatchingWindowInSeconds, 0),
		"parallelizationFactor":          llx.IntDataPtr(esm.ParallelizationFactor),
		"maximumRetryAttempts":           llx.IntDataDefault(esm.MaximumRetryAttempts, -1),
		"maximumRecordAgeInSeconds":      llx.IntDataDefault(esm.MaximumRecordAgeInSeconds, -1),
		"bisectBatchOnFunctionError":     llx.BoolDataPtr(esm.BisectBatchOnFunctionError),
		"lastModified":                   llx.TimeDataPtr(esm.LastModified),
		"lastProcessingResult":           llx.StringDataPtr(esm.LastProcessingResult),
		"topics":                         llx.ArrayData(toInterfaceArr(esm.Topics), types.String),
		"queues":                         llx.ArrayData(toInterfaceArr(esm.Queues), types.String),
		"tumblingWindowInSeconds":        llx.IntDataPtr(esm.TumblingWindowInSeconds),
		"startingPosition":               startingPosition,
		"onFailureDestinationArn":        llx.StringDataPtr(onFailureDestinationArn),
		"filterCriteria":                 llx.DictData(filterCriteria),
		"maximumConcurrency":             llx.IntDataPtr(maximumConcurrency),
	}, nil
}

func (a *mqlAwsLambdaEventSourceMapping) id() (string, error) {
	return a.Uuid.Data, nil
}

const lambdaEventSourceMappingArnPattern = "arn:aws:lambda:%s:%s:event-source-mapping:%s"

// eventSourceMappingArn prefers the ARN the API returns. The composed fallback
// hardcodes the `aws` partition, which is wrong in GovCloud (`aws-us-gov`) and
// China (`aws-cn`); it is kept only for a response that names no ARN.
func eventSourceMappingArn(sdkArn string, region string, accountID string, uuid string) string {
	if sdkArn != "" {
		return sdkArn
	}
	return fmt.Sprintf(lambdaEventSourceMappingArnPattern, region, accountID, uuid)
}

func (a *mqlAwsLambdaEventSourceMapping) arn() (string, error) {
	accountID := ""
	if a.cacheArn == "" {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		accountID = conn.AccountId()
	}
	return eventSourceMappingArn(a.cacheArn, a.Region.Data, accountID, a.Uuid.Data), nil
}

func (a *mqlAwsLambdaEventSourceMapping) function() (*mqlAwsLambdaFunction, error) {
	arnVal := a.cacheFunctionArn
	if arnVal == "" {
		a.Function.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

// ==================== Per-Function Event Source Mappings ====================

func (a *mqlAwsLambdaFunction) eventSourceMappings() ([]any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()
	res := []any{}

	paginator := lambda.NewListEventSourceMappingsPaginator(svc,
		&lambda.ListEventSourceMappingsInput{FunctionName: &funcName})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather lambda event source mappings")
		}
		for _, esm := range resp.EventSourceMappings {
			mqlEsm, err := createEventSourceMappingResource(a.MqlRuntime, esm, region)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEsm)
		}
	}
	return res, nil
}

// ==================== Per-Function Aliases ====================

func (a *mqlAwsLambdaFunction) aliases() ([]any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()
	res := []any{}

	paginator := lambda.NewListAliasesPaginator(svc,
		&lambda.ListAliasesInput{FunctionName: &funcName})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather lambda aliases")
		}
		for _, alias := range resp.Aliases {
			var routingWeights map[string]any
			if alias.RoutingConfig != nil && alias.RoutingConfig.AdditionalVersionWeights != nil {
				routingWeights = make(map[string]any)
				for k, v := range alias.RoutingConfig.AdditionalVersionWeights {
					routingWeights[k] = v
				}
			}

			mqlAlias, err := CreateResource(a.MqlRuntime, "aws.lambda.function.alias",
				map[string]*llx.RawData{
					"__id":                 llx.StringDataPtr(alias.AliasArn),
					"arn":                  llx.StringDataPtr(alias.AliasArn),
					"name":                 llx.StringDataPtr(alias.Name),
					"functionVersion":      llx.StringDataPtr(alias.FunctionVersion),
					"description":          llx.StringDataPtr(alias.Description),
					"revisionId":           llx.StringDataPtr(alias.RevisionId),
					"routingConfigWeights": llx.MapData(routingWeights, types.Float),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAlias)
		}
	}
	return res, nil
}

func (a *mqlAwsLambdaFunctionAlias) id() (string, error) {
	return a.Arn.Data, nil
}

// ==================== Per-Function Provisioned Concurrency ====================

func (a *mqlAwsLambdaFunction) provisionedConcurrencyConfigs() ([]any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()
	res := []any{}

	paginator := lambda.NewListProvisionedConcurrencyConfigsPaginator(svc,
		&lambda.ListProvisionedConcurrencyConfigsInput{FunctionName: &funcName})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not gather lambda provisioned concurrency configs")
		}
		for _, pcc := range resp.ProvisionedConcurrencyConfigs {
			mqlPcc, err := CreateResource(a.MqlRuntime, "aws.lambda.function.provisionedConcurrencyConfig",
				map[string]*llx.RawData{
					"__id":                          llx.StringDataPtr(pcc.FunctionArn),
					"functionArn":                   llx.StringDataPtr(pcc.FunctionArn),
					"requestedConcurrentExecutions": llx.IntDataDefault(pcc.RequestedProvisionedConcurrentExecutions, 0),
					"allocatedConcurrentExecutions": llx.IntDataDefault(pcc.AllocatedProvisionedConcurrentExecutions, 0),
					"availableConcurrentExecutions": llx.IntDataDefault(pcc.AvailableProvisionedConcurrentExecutions, 0),
					"status":                        llx.StringData(string(pcc.Status)),
					"statusReason":                  llx.StringDataPtr(pcc.StatusReason),
					"lastModified":                  llx.TimeDataPtr(parseAwsTimestampPtr(pcc.LastModified)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPcc)
		}
	}
	return res, nil
}

func (a *mqlAwsLambdaFunctionProvisionedConcurrencyConfig) id() (string, error) {
	return a.FunctionArn.Data, nil
}

// ==================== Per-Function Code Signing Config ====================

func (a *mqlAwsLambdaFunction) codeSigningConfig() (*mqlAwsLambdaCodeSigningConfig, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	// Step 1: Get the code signing config ARN for this function
	cscResp, err := svc.GetFunctionCodeSigningConfig(ctx,
		&lambda.GetFunctionCodeSigningConfigInput{FunctionName: &funcName})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.CodeSigningConfig.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	if cscResp.CodeSigningConfigArn == nil || *cscResp.CodeSigningConfigArn == "" {
		a.CodeSigningConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// Step 2: Get the full code signing config details
	configResp, err := svc.GetCodeSigningConfig(ctx,
		&lambda.GetCodeSigningConfigInput{CodeSigningConfigArn: cscResp.CodeSigningConfigArn})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.CodeSigningConfig.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, errors.Wrap(err, "could not get code signing config")
	}

	if configResp.CodeSigningConfig == nil {
		a.CodeSigningConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	csc := configResp.CodeSigningConfig

	allowedArns := []any{}
	if csc.AllowedPublishers != nil {
		for _, publisherArn := range csc.AllowedPublishers.SigningProfileVersionArns {
			allowedArns = append(allowedArns, publisherArn)
		}
	}

	var untrustedAction string
	if csc.CodeSigningPolicies != nil {
		untrustedAction = string(csc.CodeSigningPolicies.UntrustedArtifactOnDeployment)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.lambda.codeSigningConfig",
		map[string]*llx.RawData{
			"arn":                           llx.StringDataPtr(csc.CodeSigningConfigArn),
			"id":                            llx.StringDataPtr(csc.CodeSigningConfigId),
			"description":                   llx.StringDataPtr(csc.Description),
			"allowedPublisherProfileArns":   llx.ArrayData(allowedArns, types.String),
			"untrustedArtifactOnDeployment": llx.StringData(untrustedAction),
			"lastModified":                  llx.TimeDataPtr(parseAwsTimestampPtr(csc.LastModified)),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaCodeSigningConfig), nil
}

func (a *mqlAwsLambdaCodeSigningConfig) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsLambdaFunction) eventInvokeConfig() (any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	resp, err := svc.GetFunctionEventInvokeConfig(ctx, &lambda.GetFunctionEventInvokeConfigInput{
		FunctionName: &funcName,
	})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			return map[string]any{}, nil
		}
		if Is400AccessDeniedError(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}

	result := map[string]any{}
	if resp.MaximumRetryAttempts != nil {
		result["maximumRetryAttempts"] = int64(*resp.MaximumRetryAttempts)
	}
	if resp.MaximumEventAgeInSeconds != nil {
		result["maximumEventAgeInSeconds"] = int64(*resp.MaximumEventAgeInSeconds)
	}
	if resp.DestinationConfig != nil {
		destConfig := map[string]any{}
		if resp.DestinationConfig.OnSuccess != nil {
			destConfig["onSuccess"] = convert.ToValue(resp.DestinationConfig.OnSuccess.Destination)
		}
		if resp.DestinationConfig.OnFailure != nil {
			destConfig["onFailure"] = convert.ToValue(resp.DestinationConfig.OnFailure.Destination)
		}
		result["destinationConfig"] = destConfig
	}
	return result, nil
}

// runtimeVersionArn resolves the exact patched managed-runtime build the
// function runs on. The ListFunctions summary omits RuntimeVersionConfig, so
// it shares the per-function configuration lookup with the lifecycle fields.
// It stays empty for runtimes that have no versioned build, and reads null
// when the configuration could not be read at all.
func (a *mqlAwsLambdaFunction) runtimeVersionArn() (string, error) {
	status, err := a.fetchStatus()
	if err != nil {
		return "", err
	}
	if status == nil {
		a.RuntimeVersionArn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return status.RuntimeVersionArn(), nil
}

func (a *mqlAwsLambdaFunction) runtimeManagementConfig() (any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()

	resp, err := svc.GetRuntimeManagementConfig(ctx, &lambda.GetRuntimeManagementConfigInput{
		FunctionName: &funcName,
	})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			return map[string]any{}, nil
		}
		if Is400AccessDeniedError(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}

	result := map[string]any{
		"updateRuntimeOn": string(resp.UpdateRuntimeOn),
	}
	if resp.RuntimeVersionArn != nil {
		result["runtimeVersionArn"] = *resp.RuntimeVersionArn
	}
	return result, nil
}

// fetchRuntimeManagementConfig reads the function's runtime management
// configuration once and hands it to every field derived from it. A 404 or an
// access denial leaves it absent rather than failing, matching what the
// deprecated dict already did.
func (a *mqlAwsLambdaFunction) fetchRuntimeManagementConfig() (*lambda.GetRuntimeManagementConfigOutput, error) {
	a.runtimeMgmtOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Lambda(a.Region.Data)
		funcName := a.Name.Data
		resp, err := svc.GetRuntimeManagementConfig(context.Background(), &lambda.GetRuntimeManagementConfigInput{
			FunctionName: &funcName,
		})
		if err != nil {
			var respErr *http.ResponseError
			if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
				return
			}
			if Is400AccessDeniedError(err) {
				return
			}
			a.runtimeMgmtErr = err
			return
		}
		a.runtimeMgmtResp = resp
	})
	return a.runtimeMgmtResp, a.runtimeMgmtErr
}

func (a *mqlAwsLambdaFunction) runtimeManagement() (*mqlAwsLambdaRuntimeManagementConfig, error) {
	resp, err := a.fetchRuntimeManagementConfig()
	if err != nil {
		return nil, err
	}
	if resp == nil {
		a.RuntimeManagement.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "aws.lambda.runtimeManagementConfig",
		runtimeManagementArgs(a.Arn.Data, resp))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaRuntimeManagementConfig), nil
}

// runtimeManagementArgs maps a runtime management response into resource
// arguments. AWS omits the pinned version for a function on Auto updates, so
// runtimeVersionArn stays null there rather than claiming an empty ARN, which
// is what the deprecated dict this resource replaces already did.
func runtimeManagementArgs(functionArn string, resp *lambda.GetRuntimeManagementConfigOutput) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData(functionArn + "/runtimeManagementConfig"),
		"updateRuntimeOn":   llx.StringData(string(resp.UpdateRuntimeOn)),
		"runtimeVersionArn": llx.StringDataPtr(resp.RuntimeVersionArn),
	}
}

// ==================== Types ====================

// ==================== Per-Function Versions ====================

func (a *mqlAwsLambdaFunction) versions() ([]any, error) {
	funcName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()
	res := []any{}

	paginator := lambda.NewListVersionsByFunctionPaginator(svc,
		&lambda.ListVersionsByFunctionInput{FunctionName: &funcName})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not list lambda function versions")
		}
		for _, v := range resp.Versions {
			var lastModifiedAt *time.Time
			if v.LastModified != nil {
				if t, err := time.Parse("2006-01-02T15:04:05.000-0700", *v.LastModified); err == nil {
					lastModifiedAt = &t
				}
			}

			mqlVer, err := CreateResource(a.MqlRuntime, "aws.lambda.function.version",
				map[string]*llx.RawData{
					"__id":           llx.StringData(convert.ToValue(v.FunctionArn)),
					"arn":            llx.StringDataPtr(v.FunctionArn),
					"version":        llx.StringDataPtr(v.Version),
					"runtime":        llx.StringData(string(v.Runtime)),
					"handler":        llx.StringDataPtr(v.Handler),
					"codeSha256":     llx.StringDataPtr(v.CodeSha256),
					"description":    llx.StringDataPtr(v.Description),
					"memorySize":     llx.IntDataDefault(v.MemorySize, 0),
					"timeout":        llx.IntDataDefault(v.Timeout, 3),
					"lastModifiedAt": llx.TimeDataPtr(lastModifiedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVer)
		}
	}
	return res, nil
}

func (a *mqlAwsLambdaFunctionVersion) id() (string, error) {
	return a.Arn.Data, nil
}

// lambdaRegionFromArn pulls the region out of a Lambda ARN, returning "" when
// the value is not a parseable ARN.
func lambdaRegionFromArn(value string) string {
	parsed, err := arn.Parse(value)
	if err != nil {
		return ""
	}
	return parsed.Region
}

// state resolves the version's lifecycle state. ListVersionsByFunction omits
// State on every entry it returns, so the version is read by its own
// qualified ARN. It reads null when the state could not be read at all.
func (a *mqlAwsLambdaFunctionVersion) state() (string, error) {
	versionArn := a.Arn.Data
	region := lambdaRegionFromArn(versionArn)
	if region == "" {
		a.State.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}

	// One call per version, and there is no cheaper shape: ListVersionsByFunction
	// omits State, which is the defect this accessor exists to fix, and Lambda
	// offers no batch equivalent. GetOrCompute caches the result per version
	// resource, so the cost is one call per version read, not per access.
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Lambda(region)
	resp, err := svc.GetFunctionConfiguration(context.Background(), &lambda.GetFunctionConfigurationInput{
		FunctionName: &versionArn,
	})
	if err != nil {
		var respErr *http.ResponseError
		if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 404 {
			a.State.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		if Is400AccessDeniedError(err) {
			a.State.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		return "", err
	}
	return nullOnEmpty(&a.State, string(resp.State))
}

// ==================== Per-Layer Versions ====================

func (a *mqlAwsLambdaLayer) versions() ([]any, error) {
	layerArn := a.Arn.Data
	parsedArn, err := arn.Parse(layerArn)
	if err != nil {
		return nil, err
	}
	region := parsedArn.Region
	layerName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Lambda(region)
	ctx := context.Background()
	res := []any{}

	paginator := lambda.NewListLayerVersionsPaginator(svc,
		&lambda.ListLayerVersionsInput{LayerName: &layerName})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, errors.Wrap(err, "could not list lambda layer versions")
		}
		for _, lv := range resp.LayerVersions {
			compatRuntimes := make([]any, len(lv.CompatibleRuntimes))
			for i, rt := range lv.CompatibleRuntimes {
				compatRuntimes[i] = string(rt)
			}
			compatArchs := make([]any, len(lv.CompatibleArchitectures))
			for i, arch := range lv.CompatibleArchitectures {
				compatArchs[i] = string(arch)
			}

			mqlVer, err := CreateResource(a.MqlRuntime, "aws.lambda.layer.version",
				map[string]*llx.RawData{
					"__id":                    llx.StringDataPtr(lv.LayerVersionArn),
					"layerVersionArn":         llx.StringDataPtr(lv.LayerVersionArn),
					"version":                 llx.IntData(lv.Version),
					"description":             llx.StringDataPtr(lv.Description),
					"createdDate":             llx.TimeDataPtr(parseAwsTimestampPtr(lv.CreatedDate)),
					"compatibleRuntimes":      llx.ArrayData(compatRuntimes, types.String),
					"compatibleArchitectures": llx.ArrayData(compatArchs, types.String),
					"licenseInfo":             llx.StringDataPtr(lv.LicenseInfo),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVer)
		}
	}
	return res, nil
}

func (a *mqlAwsLambdaLayerVersion) id() (string, error) {
	return a.LayerVersionArn.Data, nil
}

type mqlAwsLambdaEventSourceMappingInternal struct {
	cacheFunctionArn string
	cacheArn         string
}
