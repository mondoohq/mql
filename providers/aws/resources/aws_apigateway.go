// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	mqltypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsApigateway) id() (string, error) {
	return "aws.apigateway", nil
}

func (a *mqlAwsApigateway) restApis() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRestApis(conn), 5)
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

func (a *mqlAwsApigateway) getRestApis(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("gateway>getRestApis>calling AWS with region %s", region)

			svc := conn.Apigateway(region)
			ctx := context.Background()

			res := []any{}
			var position *string
			for {
				restApisResp, err := svc.GetRestApis(ctx, &apigateway.GetRestApisInput{Position: position})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather AWS API Gateway REST APIs")
				}

				for _, restApi := range restApisResp.Items {
					if conn.Filters.General.IsFilteredOutByTags(restApi.Tags) {
						log.Debug().Interface("restApi", restApi.Name).Msg("skipping api gateway restapi due to filters")
						continue
					}

					endpointTypes := []any{}
					endpointVpcEndpointIds := []any{}
					if restApi.EndpointConfiguration != nil {
						for _, t := range restApi.EndpointConfiguration.Types {
							endpointTypes = append(endpointTypes, string(t))
						}
						for _, v := range restApi.EndpointConfiguration.VpcEndpointIds {
							endpointVpcEndpointIds = append(endpointVpcEndpointIds, v)
						}
					}

					mqlRestApi, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayRestapi,
						map[string]*llx.RawData{
							"arn":                       llx.StringData(fmt.Sprintf(apiArnPattern, region, conn.AccountId(), convert.ToValue(restApi.Id))),
							"id":                        llx.StringData(convert.ToValue(restApi.Id)),
							"name":                      llx.StringData(convert.ToValue(restApi.Name)),
							"description":               llx.StringData(convert.ToValue(restApi.Description)),
							"createdDate":               llx.TimeDataPtr(restApi.CreatedDate),
							"region":                    llx.StringData(region),
							"tags":                      llx.MapData(toInterfaceMap(restApi.Tags), mqltypes.String),
							"apiKeySource":              llx.StringData(string(restApi.ApiKeySource)),
							"disableExecuteApiEndpoint": llx.BoolData(restApi.DisableExecuteApiEndpoint),
							"minimumCompressionSize":    llx.IntDataDefault(restApi.MinimumCompressionSize, -1),
							"binaryMediaTypes":          llx.ArrayData(convert.SliceAnyToInterface(restApi.BinaryMediaTypes), mqltypes.String),
							"version":                   llx.StringData(convert.ToValue(restApi.Version)),
							"securityPolicy":            llx.StringData(string(restApi.SecurityPolicy)),
							"policy":                    llx.StringData(convert.ToValue(restApi.Policy)),
							"endpointTypes":             llx.ArrayData(endpointTypes, mqltypes.String),
							"endpointVpcEndpointIds":    llx.ArrayData(endpointVpcEndpointIds, mqltypes.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRestApi)
				}
				if restApisResp.Position == nil {
					break
				}
				position = restApisResp.Position
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsApigatewayRestapi(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformGatewayRestapi); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch gateway restapi")
	}

	obj, err := CreateResource(runtime, ResourceAwsApigateway, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	gw := obj.(*mqlAwsApigateway)

	rawResources := gw.GetRestApis()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		restApi := rawResource.(*mqlAwsApigatewayRestapi)
		if restApi.Arn.Data == arnVal {
			return args, restApi, nil
		}
	}
	return nil, nil, errors.New("gateway restapi does not exist")
}

func (a *mqlAwsApigatewayRestapi) stages() ([]any, error) {
	restApiId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Apigateway(region)
	ctx := context.Background()

	// no pagination required
	stagesResp, err := svc.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: &restApiId})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather AWS API Gateway stages")
	}
	res := []any{}
	for _, stage := range stagesResp.Item {
		if conn.Filters.General.IsFilteredOutByTags(stage.Tags) {
			log.Debug().Interface("stage", stage.StageName).Msg("skipping api gateway stage due to filters")
			continue
		}

		dictMethodSettings, err := convert.JsonToDict(stage.MethodSettings)
		if err != nil {
			return nil, err
		}
		// CacheDataEncrypted is configured per method; the "*/*" key holds the
		// stage-wide default that applies unless a specific method overrides it.
		cacheDataEncrypted := false
		if ms, ok := stage.MethodSettings["*/*"]; ok {
			cacheDataEncrypted = ms.CacheDataEncrypted
		}
		stageArn := fmt.Sprintf(apiStageArnPattern, region, conn.AccountId(), restApiId, convert.ToValue(stage.StageName))
		// Nil when access logging is off, which leaves the reference null, so
		// `accessLog == null` is the test for "logging is not configured".
		accessLog := llx.NilData
		if stage.AccessLogSettings != nil {
			accessLog, err = newMqlApigatewayAccessLog(a.MqlRuntime, "aws.apigateway.stage.accessLogConfiguration", stageArn,
				convert.ToValue(stage.AccessLogSettings.DestinationArn), convert.ToValue(stage.AccessLogSettings.Format))
			if err != nil {
				return nil, err
			}
		}
		mqlStage, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayStage,
			map[string]*llx.RawData{
				"arn":                  llx.StringData(stageArn),
				"name":                 llx.StringData(convert.ToValue(stage.StageName)),
				"description":          llx.StringData(convert.ToValue(stage.Description)),
				"tracingEnabled":       llx.BoolData(stage.TracingEnabled),
				"deploymentId":         llx.StringData(convert.ToValue(stage.DeploymentId)),
				"methodSettings":       llx.MapData(dictMethodSettings, mqltypes.Any),
				"cacheClusterEnabled":  llx.BoolData(stage.CacheClusterEnabled),
				"cacheClusterSize":     llx.StringData(string(stage.CacheClusterSize)),
				"cacheClusterStatus":   llx.StringData(string(stage.CacheClusterStatus)),
				"cacheDataEncrypted":   llx.BoolData(cacheDataEncrypted),
				"accessLog":            accessLog,
				"clientCertificateId":  llx.StringData(convert.ToValue(stage.ClientCertificateId)),
				"createdAt":            llx.TimeDataPtr(stage.CreatedDate),
				"lastUpdatedAt":        llx.TimeDataPtr(stage.LastUpdatedDate),
				"documentationVersion": llx.StringData(convert.ToValue(stage.DocumentationVersion)),
				"variables":            llx.MapData(toInterfaceMap(stage.Variables), mqltypes.String),
				"tags":                 llx.MapData(toInterfaceMap(stage.Tags), mqltypes.String),
			})
		if err != nil {
			return nil, err
		}
		mqlStage.(*mqlAwsApigatewayStage).cacheWebAclArn = convert.ToValue(stage.WebAclArn)
		res = append(res, mqlStage)
	}
	return res, nil
}

func (a *mqlAwsApigatewayRestapi) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApigatewayStage) id() (string, error) {
	return a.Arn.Data, nil
}

// newMqlApigatewayAccessLog builds a stage's access-log configuration. REST
// and HTTP API stages return the same two members through separate SDK types,
// so the resource name says which of the two identical sub-resources to build.
func newMqlApigatewayAccessLog(runtime *plugin.Runtime, resourceName, stageArn, destinationArn, format string) (*llx.RawData, error) {
	res, err := CreateResource(runtime, resourceName, map[string]*llx.RawData{
		"__id":           llx.StringData(stageArn + "/accessLogSettings"),
		"destinationArn": llx.StringData(destinationArn),
		"format":         llx.StringData(format),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resourceName), nil
}

func (a *mqlAwsApigatewayStageAccessLogConfiguration) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return resolveAccessLogGroup(a.MqlRuntime, a.DestinationArn.Data, &a.LogGroup.State)
}

// resolveAccessLogGroup turns an API Gateway access-log destination into a log
// group resource. The destination is either a CloudWatch Logs log group or a
// Kinesis Data Firehose delivery stream, so anything that is not a logs ARN
// resolves to null rather than to a log group that does not exist.
func resolveAccessLogGroup(runtime *plugin.Runtime, destinationArn string, state *plugin.State) (*mqlAwsCloudwatchLoggroup, error) {
	if destinationArn == "" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parsed, err := arn.Parse(destinationArn)
	if err != nil || parsed.Service != "logs" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{
		"arn": llx.StringData(destinationArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsApigatewayStage) webAcl() (*mqlAwsWafAcl, error) {
	arnVal := a.cacheWebAclArn
	if arnVal == "" {
		a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.waf.acl",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAcl), nil
}

// Authorizers — fetched per restApi.

func (a *mqlAwsApigatewayRestapi) authorizers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	restApiId := a.Id.Data
	svc := conn.Apigateway(region)
	ctx := context.Background()

	res := []any{}
	var position *string
	for {
		resp, err := svc.GetAuthorizers(ctx, &apigateway.GetAuthorizersInput{RestApiId: &restApiId, Position: position})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "apigateway:GET"), "could not gather AWS API Gateway authorizers")
		}
		for _, auth := range resp.Items {
			providerArns := []any{}
			for _, p := range auth.ProviderARNs {
				providerArns = append(providerArns, p)
			}
			authId := convert.ToValue(auth.Id)
			mqlAuth, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayAuthorizer,
				map[string]*llx.RawData{
					"arn":                          llx.StringData(fmt.Sprintf(apiAuthorizerArnPattern, region, conn.AccountId(), restApiId, authId)),
					"id":                           llx.StringData(authId),
					"name":                         llx.StringData(convert.ToValue(auth.Name)),
					"type":                         llx.StringData(string(auth.Type)),
					"authType":                     llx.StringData(convert.ToValue(auth.AuthType)),
					"restApiId":                    llx.StringData(restApiId),
					"authorizerCredentials":        llx.StringData(convert.ToValue(auth.AuthorizerCredentials)),
					"authorizerUri":                llx.StringData(convert.ToValue(auth.AuthorizerUri)),
					"authorizerResultTtlInSeconds": llx.IntDataDefault(auth.AuthorizerResultTtlInSeconds, 0),
					"identitySource":               llx.StringData(convert.ToValue(auth.IdentitySource)),
					"identityValidationExpression": llx.StringData(convert.ToValue(auth.IdentityValidationExpression)),
					"providerArns":                 llx.ArrayData(providerArns, mqltypes.String),
					"region":                       llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAuth)
		}
		if resp.Position == nil {
			break
		}
		position = resp.Position
	}
	return res, nil
}

func (a *mqlAwsApigatewayRestapi) deployments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	restApiId := a.Id.Data
	svc := conn.Apigateway(region)
	ctx := context.Background()

	res := []any{}
	var position *string
	for {
		resp, err := svc.GetDeployments(ctx, &apigateway.GetDeploymentsInput{RestApiId: &restApiId, Position: position})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "apigateway:GET"), "could not gather AWS API Gateway deployments")
		}
		for _, d := range resp.Items {
			depId := convert.ToValue(d.Id)
			apiSummary, err := convert.JsonToDict(d.ApiSummary)
			if err != nil {
				return nil, err
			}
			mqlDep, err := CreateResource(a.MqlRuntime, "aws.apigateway.deployment",
				map[string]*llx.RawData{
					"__id":        llx.StringData(restApiId + "/" + depId),
					"id":          llx.StringData(depId),
					"restApiId":   llx.StringData(restApiId),
					"createdDate": llx.TimeDataPtr(d.CreatedDate),
					"description": llx.StringData(convert.ToValue(d.Description)),
					"apiSummary":  llx.DictData(apiSummary),
					"region":      llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDep)
		}
		if resp.Position == nil {
			break
		}
		position = resp.Position
	}
	return res, nil
}

func (a *mqlAwsApigatewayAuthorizer) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApigatewayAuthorizer) iamRole() (*mqlAwsIamRole, error) {
	roleArn := a.AuthorizerCredentials.Data
	if roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// authorizerUri for Lambda integrations is of the form:
//
//	arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{lambdaArn}/invocations
//
// extractLambdaArnFromAuthorizerUri returns the embedded Lambda ARN, or "" if the URI
// is not a Lambda invocation URI (e.g. for COGNITO_USER_POOLS authorizers).
func extractLambdaArnFromAuthorizerUri(uri string) string {
	const marker = "/functions/"
	idx := strings.Index(uri, marker)
	if idx < 0 {
		return ""
	}
	rest := uri[idx+len(marker):]
	end := strings.Index(rest, "/invocations")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func (a *mqlAwsApigatewayAuthorizer) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	lambdaArn := extractLambdaArnFromAuthorizerUri(a.AuthorizerUri.Data)
	if lambdaArn == "" {
		a.LambdaFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(lambdaArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsApigatewayAuthorizer) userPools() ([]any, error) {
	res := []any{}
	for _, poolArn := range a.ProviderArns.Data {
		s, ok := poolArn.(string)
		if !ok || s == "" {
			continue
		}
		pool, err := NewResource(a.MqlRuntime, "aws.cognito.userPool",
			map[string]*llx.RawData{"arn": llx.StringData(s)})
		if err != nil {
			return nil, err
		}
		res = append(res, pool)
	}
	return res, nil
}

// Request validators — fetched per restApi.

func (a *mqlAwsApigatewayRestapi) requestValidators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	restApiId := a.Id.Data
	svc := conn.Apigateway(region)
	ctx := context.Background()

	res := []any{}
	var position *string
	for {
		resp, err := svc.GetRequestValidators(ctx, &apigateway.GetRequestValidatorsInput{RestApiId: &restApiId, Position: position})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "apigateway:GET"), "could not gather AWS API Gateway request validators")
		}
		for _, v := range resp.Items {
			vid := convert.ToValue(v.Id)
			mqlV, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayRequestValidator,
				map[string]*llx.RawData{
					"arn":                       llx.StringData(fmt.Sprintf(apiRequestValidatorArnPattern, region, conn.AccountId(), restApiId, vid)),
					"id":                        llx.StringData(vid),
					"name":                      llx.StringData(convert.ToValue(v.Name)),
					"restApiId":                 llx.StringData(restApiId),
					"validateRequestBody":       llx.BoolData(v.ValidateRequestBody),
					"validateRequestParameters": llx.BoolData(v.ValidateRequestParameters),
					"region":                    llx.StringData(region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlV)
		}
		if resp.Position == nil {
			break
		}
		position = resp.Position
	}
	return res, nil
}

func (a *mqlAwsApigatewayRequestValidator) id() (string, error) {
	return a.Arn.Data, nil
}

// API keys — account-level, fetched across all regions.

func (a *mqlAwsApigateway) apiKeys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getApiKeys(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsApigateway) getApiKeys(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apigateway>getApiKeys>region %s", region)
			svc := conn.Apigateway(region)
			ctx := context.Background()
			res := []any{}
			var position *string
			for {
				resp, err := svc.GetApiKeys(ctx, &apigateway.GetApiKeysInput{Position: position})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing API gateway API keys")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather AWS API Gateway API keys")
				}
				for _, k := range resp.Items {
					kid := convert.ToValue(k.Id)
					stageKeys := []any{}
					for _, sk := range k.StageKeys {
						stageKeys = append(stageKeys, sk)
					}
					if conn.Filters.General.IsFilteredOutByTags(k.Tags) {
						continue
					}
					mqlKey, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayApiKey,
						map[string]*llx.RawData{
							"arn":             llx.StringData(fmt.Sprintf(apiKeyArnPattern, region, conn.AccountId(), kid)),
							"id":              llx.StringData(kid),
							"name":            llx.StringData(convert.ToValue(k.Name)),
							"description":     llx.StringData(convert.ToValue(k.Description)),
							"enabled":         llx.BoolData(k.Enabled),
							"customerId":      llx.StringData(convert.ToValue(k.CustomerId)),
							"stageKeys":       llx.ArrayData(stageKeys, mqltypes.String),
							"createdDate":     llx.TimeDataPtr(k.CreatedDate),
							"lastUpdatedDate": llx.TimeDataPtr(k.LastUpdatedDate),
							"tags":            llx.MapData(toInterfaceMap(k.Tags), mqltypes.String),
							"region":          llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlKey)
				}
				if resp.Position == nil {
					break
				}
				position = resp.Position
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsApigatewayApiKey) id() (string, error) {
	return a.Arn.Data, nil
}

// Usage plans — account-level, fetched across all regions.

func (a *mqlAwsApigateway) usagePlans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getUsagePlans(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsApigateway) getUsagePlans(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apigateway>getUsagePlans>region %s", region)
			svc := conn.Apigateway(region)
			ctx := context.Background()
			res := []any{}
			var position *string
			for {
				resp, err := svc.GetUsagePlans(ctx, &apigateway.GetUsagePlansInput{Position: position})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing API gateway usage plans")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather AWS API Gateway usage plans")
				}
				for _, p := range resp.Items {
					if conn.Filters.General.IsFilteredOutByTags(p.Tags) {
						continue
					}
					pid := convert.ToValue(p.Id)
					apiStages, err := apiStagesToDict(p.ApiStages)
					if err != nil {
						return nil, err
					}
					quotaLimit := int64(-1)
					quotaOffset := int64(-1)
					quotaPeriod := ""
					if p.Quota != nil {
						quotaLimit = int64(p.Quota.Limit)
						quotaOffset = int64(p.Quota.Offset)
						quotaPeriod = string(p.Quota.Period)
					}
					burstLimit := int64(-1)
					rateLimit := -1.0
					if p.Throttle != nil {
						burstLimit = int64(p.Throttle.BurstLimit)
						rateLimit = p.Throttle.RateLimit
					}
					mqlPlan, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayUsagePlan,
						map[string]*llx.RawData{
							"arn":                llx.StringData(fmt.Sprintf(apiUsagePlanArnPattern, region, conn.AccountId(), pid)),
							"id":                 llx.StringData(pid),
							"name":               llx.StringData(convert.ToValue(p.Name)),
							"description":        llx.StringData(convert.ToValue(p.Description)),
							"productCode":        llx.StringData(convert.ToValue(p.ProductCode)),
							"apiStages":          llx.ArrayData(apiStages, mqltypes.Any),
							"quotaLimit":         llx.IntData(quotaLimit),
							"quotaOffset":        llx.IntData(quotaOffset),
							"quotaPeriod":        llx.StringData(quotaPeriod),
							"throttleBurstLimit": llx.IntData(burstLimit),
							"throttleRateLimit":  llx.FloatData(rateLimit),
							"tags":               llx.MapData(toInterfaceMap(p.Tags), mqltypes.String),
							"region":             llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPlan)
				}
				if resp.Position == nil {
					break
				}
				position = resp.Position
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func apiStagesToDict(stages []types.ApiStage) ([]any, error) {
	out := []any{}
	for _, s := range stages {
		throttle := map[string]any{}
		for k, t := range s.Throttle {
			throttle[k] = map[string]any{
				"burstLimit": int64(t.BurstLimit),
				"rateLimit":  t.RateLimit,
			}
		}
		out = append(out, map[string]any{
			"apiId":    convert.ToValue(s.ApiId),
			"stage":    convert.ToValue(s.Stage),
			"throttle": throttle,
		})
	}
	return out, nil
}

func (a *mqlAwsApigatewayUsagePlan) id() (string, error) {
	return a.Arn.Data, nil
}

// VPC links — account-level, fetched across all regions.

func (a *mqlAwsApigateway) vpcLinks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getVpcLinks(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsApigateway) getVpcLinks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apigateway>getVpcLinks>region %s", region)
			svc := conn.Apigateway(region)
			ctx := context.Background()
			res := []any{}
			var position *string
			for {
				resp, err := svc.GetVpcLinks(ctx, &apigateway.GetVpcLinksInput{Position: position})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing API gateway VPC links")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather AWS API Gateway VPC links")
				}
				for _, v := range resp.Items {
					if conn.Filters.General.IsFilteredOutByTags(v.Tags) {
						continue
					}
					vid := convert.ToValue(v.Id)
					targetArns := []any{}
					for _, t := range v.TargetArns {
						targetArns = append(targetArns, t)
					}
					mqlLink, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayVpcLink,
						map[string]*llx.RawData{
							"arn":           llx.StringData(fmt.Sprintf(apiVpcLinkArnPattern, region, conn.AccountId(), vid)),
							"id":            llx.StringData(vid),
							"name":          llx.StringData(convert.ToValue(v.Name)),
							"description":   llx.StringData(convert.ToValue(v.Description)),
							"status":        llx.StringData(string(v.Status)),
							"statusMessage": llx.StringData(convert.ToValue(v.StatusMessage)),
							"targetArns":    llx.ArrayData(targetArns, mqltypes.String),
							"tags":          llx.MapData(toInterfaceMap(v.Tags), mqltypes.String),
							"region":        llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlLink)
				}
				if resp.Position == nil {
					break
				}
				position = resp.Position
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsApigatewayVpcLink) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApigatewayVpcLink) targets() ([]any, error) {
	res := []any{}
	for _, t := range a.TargetArns.Data {
		s, ok := t.(string)
		if !ok || s == "" {
			continue
		}
		lb, err := NewResource(a.MqlRuntime, "aws.elb.loadbalancer",
			map[string]*llx.RawData{"arn": llx.StringData(s)})
		if err != nil {
			return nil, err
		}
		res = append(res, lb)
	}
	return res, nil
}

type mqlAwsApigatewayStageInternal struct {
	cacheWebAclArn string
}
