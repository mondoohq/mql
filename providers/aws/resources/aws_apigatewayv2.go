// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsApigatewayv2) id() (string, error) {
	return "aws.apigatewayv2", nil
}

// ---------- aws.apigatewayv2.api ----------

func (a *mqlAwsApigatewayv2) apis() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getApis(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsApigatewayv2) getApis(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			svc := conn.Apigatewayv2(region)
			ctx := context.Background()
			var nextToken *string
			for {
				out, err := svc.GetApis(ctx, &apigatewayv2.GetApisInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, api := range out.Items {
					mqlApi, err := newMqlAwsApigatewayv2Api(a.MqlRuntime, region, api)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlApi)
				}
				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsApigatewayv2Api(runtime *plugin.Runtime, region string, api apigwv2types.Api) (*mqlAwsApigatewayv2Api, error) {
	corsDict, err := convert.JsonToDict(api.CorsConfiguration)
	if err != nil {
		return nil, err
	}
	arn := apigatewayv2ApiArn(region, api.ApiId)
	res, err := CreateResource(runtime, "aws.apigatewayv2.api", map[string]*llx.RawData{
		"__id":                      llx.StringData(arn),
		"apiId":                     llx.StringDataPtr(api.ApiId),
		"arn":                       llx.StringData(arn),
		"name":                      llx.StringDataPtr(api.Name),
		"protocolType":              llx.StringData(string(api.ProtocolType)),
		"region":                    llx.StringData(region),
		"description":               llx.StringDataPtr(api.Description),
		"apiEndpoint":               llx.StringDataPtr(api.ApiEndpoint),
		"disableExecuteApiEndpoint": llx.BoolDataPtr(api.DisableExecuteApiEndpoint),
		"disableSchemaValidation":   llx.BoolDataPtr(api.DisableSchemaValidation),
		"apiKeySelectionExpression": llx.StringDataPtr(api.ApiKeySelectionExpression),
		"routeSelectionExpression":  llx.StringDataPtr(api.RouteSelectionExpression),
		"corsConfiguration":         llx.DictData(corsDict),
		"ipAddressType":             llx.StringData(string(api.IpAddressType)),
		"apiGatewayManaged":         llx.BoolDataPtr(api.ApiGatewayManaged),
		"version":                   llx.StringDataPtr(api.Version),
		"tags":                      llx.MapData(stringMapToAny(api.Tags), types.String),
		"createdAt":                 llx.TimeDataPtr(api.CreatedDate),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayv2Api), nil
}

func apigatewayv2ApiArn(region string, apiId *string) string {
	if apiId == nil {
		return ""
	}
	return fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s", region, *apiId)
}

func stringMapToAny(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	res := make(map[string]any, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

func stringSliceToAny(s []string) []any {
	res := make([]any, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}

func (a *mqlAwsApigatewayv2Api) id() (string, error) {
	return apigatewayv2ApiArn(a.Region.Data, &a.ApiId.Data), nil
}

// initAwsApigatewayv2Api lets typed back-references like
// aws.apigatewayv2.stage.api() resolve a previously-fetched api by apiId.
// Without this init, NewResource would create an empty resource keyed on a
// stub ARN and return blank fields.
func initAwsApigatewayv2Api(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// Resolve a discovered asset (aws-apigatewayv2-api platform) by its ARN.
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformApigatewayv2Api); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["apiId"] == nil && args["arn"] == nil {
		return args, nil, errors.New("apiId or arn required to fetch aws.apigatewayv2.api")
	}

	obj, err := CreateResource(runtime, "aws.apigatewayv2", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	apis := obj.(*mqlAwsApigatewayv2).GetApis()
	if apis.Error != nil {
		return nil, nil, apis.Error
	}

	var wantApiId, wantArn string
	if args["apiId"] != nil {
		wantApiId = args["apiId"].Value.(string)
	}
	if args["arn"] != nil {
		wantArn = args["arn"].Value.(string)
	}
	for _, r := range apis.Data {
		api := r.(*mqlAwsApigatewayv2Api)
		if (wantApiId != "" && api.ApiId.Data == wantApiId) || (wantArn != "" && api.Arn.Data == wantArn) {
			return args, api, nil
		}
	}
	if wantApiId != "" {
		return nil, nil, fmt.Errorf("aws.apigatewayv2.api with apiId %q not found", wantApiId)
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.apigatewayv2.api with arn %q not found", wantArn)
}

// ---------- aws.apigatewayv2.stage ----------

func (a *mqlAwsApigatewayv2Api) stages() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	apiId := a.ApiId.Data
	svc := conn.Apigatewayv2(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		out, err := svc.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: &apiId, NextToken: nextToken})
		if err != nil {
			return nil, classifyAwsError(err, "apigateway:GET")
		}
		for _, s := range out.Items {
			mqlStage, err := newMqlAwsApigatewayv2Stage(a.MqlRuntime, region, apiId, s)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlStage)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return res, nil
}

func newMqlAwsApigatewayv2Stage(runtime *plugin.Runtime, region, apiId string, s apigwv2types.Stage) (*mqlAwsApigatewayv2Stage, error) {
	defaultRouteSettings, err := convert.JsonToDict(s.DefaultRouteSettings)
	if err != nil {
		return nil, err
	}
	routeSettings, err := convert.JsonToDict(s.RouteSettings)
	if err != nil {
		return nil, err
	}
	accessLog, err := convert.JsonToDict(s.AccessLogSettings)
	if err != nil {
		return nil, err
	}

	stageName := ""
	if s.StageName != nil {
		stageName = *s.StageName
	}

	stageId := apigatewayv2StageId(region, apiId, stageName)
	defaultRoute, err := newMqlApigatewayv2RouteSettings(runtime, stageId, s.DefaultRouteSettings)
	if err != nil {
		return nil, err
	}

	mqlAccessLog := llx.NilData
	if s.AccessLogSettings != nil {
		mqlAccessLog, err = newMqlApigatewayAccessLog(runtime, "aws.apigatewayv2.stage.accessLogConfiguration", stageId,
			convert.ToValue(s.AccessLogSettings.DestinationArn), convert.ToValue(s.AccessLogSettings.Format))
		if err != nil {
			return nil, err
		}
	}

	res, err := CreateResource(runtime, "aws.apigatewayv2.stage", map[string]*llx.RawData{
		"__id":                        llx.StringData(stageId),
		"stageName":                   llx.StringData(stageName),
		"apiId":                       llx.StringData(apiId),
		"region":                      llx.StringData(region),
		"description":                 llx.StringDataPtr(s.Description),
		"autoDeploy":                  llx.BoolDataPtr(s.AutoDeploy),
		"deploymentId":                llx.StringDataPtr(s.DeploymentId),
		"clientCertificateId":         llx.StringDataPtr(s.ClientCertificateId),
		"stageVariables":              llx.MapData(stringMapToAny(s.StageVariables), types.String),
		"defaultRouteSettings":        llx.DictData(defaultRouteSettings),
		"routeSettings":               llx.DictData(routeSettings),
		"accessLogSettings":           llx.DictData(accessLog),
		"defaultRoute":                defaultRoute,
		"accessLog":                   mqlAccessLog,
		"apiGatewayManaged":           llx.BoolDataPtr(s.ApiGatewayManaged),
		"lastDeploymentStatusMessage": llx.StringDataPtr(s.LastDeploymentStatusMessage),
		"tags":                        llx.MapData(stringMapToAny(s.Tags), types.String),
		"createdAt":                   llx.TimeDataPtr(s.CreatedDate),
		"updatedAt":                   llx.TimeDataPtr(s.LastUpdatedDate),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayv2Stage), nil
}

func (a *mqlAwsApigatewayv2StageAccessLogConfiguration) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return resolveAccessLogGroup(a.MqlRuntime, a.DestinationArn.Data, &a.LogGroup.State)
}

// newMqlApigatewayv2RouteSettings builds the stage-wide default route
// settings. Nil settings mean the stage sets no defaults at all, which is
// reported as null rather than as logging off with a zero throttling limit,
// since a zero limit would read as "throttled to nothing".
func newMqlApigatewayv2RouteSettings(runtime *plugin.Runtime, stageId string, rs *apigwv2types.RouteSettings) (*llx.RawData, error) {
	if rs == nil {
		return llx.NilData, nil
	}
	burstLimit := llx.NilData
	if rs.ThrottlingBurstLimit != nil {
		burstLimit = llx.IntData(int64(*rs.ThrottlingBurstLimit))
	}
	rateLimit := llx.NilData
	if rs.ThrottlingRateLimit != nil {
		rateLimit = llx.FloatData(*rs.ThrottlingRateLimit)
	}
	res, err := CreateResource(runtime, "aws.apigatewayv2.routeSettings", map[string]*llx.RawData{
		"__id":                   llx.StringData(stageId + "/defaultRouteSettings"),
		"dataTraceEnabled":       llx.BoolData(convert.ToValue(rs.DataTraceEnabled)),
		"detailedMetricsEnabled": llx.BoolData(convert.ToValue(rs.DetailedMetricsEnabled)),
		"loggingLevel":           llx.StringData(string(rs.LoggingLevel)),
		"throttlingBurstLimit":   burstLimit,
		"throttlingRateLimit":    rateLimit,
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "aws.apigatewayv2.routeSettings"), nil
}

func apigatewayv2StageId(region, apiId, stageName string) string {
	return fmt.Sprintf("%s/apis/%s/stages/%s", region, apiId, stageName)
}

func (a *mqlAwsApigatewayv2Stage) id() (string, error) {
	return apigatewayv2StageId(a.Region.Data, a.ApiId.Data, a.StageName.Data), nil
}

func (a *mqlAwsApigatewayv2Stage) api() (*mqlAwsApigatewayv2Api, error) {
	mqlApi, err := NewResource(a.MqlRuntime, "aws.apigatewayv2.api",
		map[string]*llx.RawData{"apiId": llx.StringData(a.ApiId.Data)})
	if err != nil {
		return nil, err
	}
	return mqlApi.(*mqlAwsApigatewayv2Api), nil
}

// ---------- aws.apigatewayv2.route ----------

func (a *mqlAwsApigatewayv2Api) routes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	apiId := a.ApiId.Data
	svc := conn.Apigatewayv2(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		out, err := svc.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: &apiId, NextToken: nextToken})
		if err != nil {
			return nil, classifyAwsError(err, "apigateway:GET")
		}
		for _, r := range out.Items {
			mqlRoute, err := newMqlAwsApigatewayv2Route(a.MqlRuntime, region, apiId, r)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRoute)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return res, nil
}

func newMqlAwsApigatewayv2Route(runtime *plugin.Runtime, region, apiId string, r apigwv2types.Route) (*mqlAwsApigatewayv2Route, error) {
	routeId := ""
	if r.RouteId != nil {
		routeId = *r.RouteId
	}
	res, err := CreateResource(runtime, "aws.apigatewayv2.route", map[string]*llx.RawData{
		"__id":                llx.StringData(apigatewayv2RouteId(region, apiId, routeId)),
		"routeId":             llx.StringData(routeId),
		"apiId":               llx.StringData(apiId),
		"region":              llx.StringData(region),
		"routeKey":            llx.StringDataPtr(r.RouteKey),
		"target":              llx.StringDataPtr(r.Target),
		"authorizationType":   llx.StringData(string(r.AuthorizationType)),
		"authorizerId":        llx.StringDataPtr(r.AuthorizerId),
		"authorizationScopes": llx.ArrayData(stringSliceToAny(r.AuthorizationScopes), types.String),
		"apiKeyRequired":      llx.BoolDataPtr(r.ApiKeyRequired),
		"operationName":       llx.StringDataPtr(r.OperationName),
		"requestModels":       llx.MapData(stringMapToAny(r.RequestModels), types.String),
		"apiGatewayManaged":   llx.BoolDataPtr(r.ApiGatewayManaged),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayv2Route), nil
}

func apigatewayv2RouteId(region, apiId, routeId string) string {
	return fmt.Sprintf("%s/apis/%s/routes/%s", region, apiId, routeId)
}

func (a *mqlAwsApigatewayv2Route) id() (string, error) {
	return apigatewayv2RouteId(a.Region.Data, a.ApiId.Data, a.RouteId.Data), nil
}

func (a *mqlAwsApigatewayv2Route) api() (*mqlAwsApigatewayv2Api, error) {
	mqlApi, err := NewResource(a.MqlRuntime, "aws.apigatewayv2.api",
		map[string]*llx.RawData{"apiId": llx.StringData(a.ApiId.Data)})
	if err != nil {
		return nil, err
	}
	return mqlApi.(*mqlAwsApigatewayv2Api), nil
}

// ---------- aws.apigatewayv2.authorizer ----------

func (a *mqlAwsApigatewayv2Api) authorizers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	apiId := a.ApiId.Data
	svc := conn.Apigatewayv2(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		out, err := svc.GetAuthorizers(ctx, &apigatewayv2.GetAuthorizersInput{ApiId: &apiId, NextToken: nextToken})
		if err != nil {
			return nil, classifyAwsError(err, "apigateway:GET")
		}
		for _, az := range out.Items {
			mqlAuth, err := newMqlAwsApigatewayv2Authorizer(a.MqlRuntime, region, apiId, az)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAuth)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return res, nil
}

func newMqlAwsApigatewayv2Authorizer(runtime *plugin.Runtime, region, apiId string, az apigwv2types.Authorizer) (*mqlAwsApigatewayv2Authorizer, error) {
	jwtConfig, err := convert.JsonToDict(az.JwtConfiguration)
	if err != nil {
		return nil, err
	}
	authorizerId := ""
	if az.AuthorizerId != nil {
		authorizerId = *az.AuthorizerId
	}
	ttl := int64(0)
	if az.AuthorizerResultTtlInSeconds != nil {
		ttl = int64(*az.AuthorizerResultTtlInSeconds)
	}
	res, err := CreateResource(runtime, "aws.apigatewayv2.authorizer", map[string]*llx.RawData{
		"__id":                           llx.StringData(apigatewayv2AuthorizerId(region, apiId, authorizerId)),
		"authorizerId":                   llx.StringData(authorizerId),
		"apiId":                          llx.StringData(apiId),
		"region":                         llx.StringData(region),
		"name":                           llx.StringDataPtr(az.Name),
		"authorizerType":                 llx.StringData(string(az.AuthorizerType)),
		"authorizerCredentialsArn":       llx.StringDataPtr(az.AuthorizerCredentialsArn),
		"authorizerUri":                  llx.StringDataPtr(az.AuthorizerUri),
		"authorizerPayloadFormatVersion": llx.StringDataPtr(az.AuthorizerPayloadFormatVersion),
		"authorizerResultTtlInSeconds":   llx.IntData(ttl),
		"enableSimpleResponses":          llx.BoolDataPtr(az.EnableSimpleResponses),
		"identitySource":                 llx.ArrayData(stringSliceToAny(az.IdentitySource), types.String),
		"identityValidationExpression":   llx.StringDataPtr(az.IdentityValidationExpression),
		"jwtConfiguration":               llx.DictData(jwtConfig),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayv2Authorizer), nil
}

func apigatewayv2AuthorizerId(region, apiId, authorizerId string) string {
	return fmt.Sprintf("%s/apis/%s/authorizers/%s", region, apiId, authorizerId)
}

func (a *mqlAwsApigatewayv2Authorizer) id() (string, error) {
	return apigatewayv2AuthorizerId(a.Region.Data, a.ApiId.Data, a.AuthorizerId.Data), nil
}

func (a *mqlAwsApigatewayv2Authorizer) api() (*mqlAwsApigatewayv2Api, error) {
	mqlApi, err := NewResource(a.MqlRuntime, "aws.apigatewayv2.api",
		map[string]*llx.RawData{"apiId": llx.StringData(a.ApiId.Data)})
	if err != nil {
		return nil, err
	}
	return mqlApi.(*mqlAwsApigatewayv2Api), nil
}

// ---------- aws.apigatewayv2.domainName ----------

func (a *mqlAwsApigatewayv2) domainNames() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getDomainNames(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsApigatewayv2) getDomainNames(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			svc := conn.Apigatewayv2(region)
			ctx := context.Background()
			var nextToken *string
			for {
				out, err := svc.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied for apigatewayv2 GetDomainNames")
						return res, nil
					}
					return nil, err
				}
				for _, dn := range out.Items {
					mqlDn, err := newMqlAwsApigatewayv2DomainName(a.MqlRuntime, region, dn)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDn)
				}
				if out.NextToken == nil {
					break
				}
				nextToken = out.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsApigatewayv2DomainName(runtime *plugin.Runtime, region string, dn apigwv2types.DomainName) (*mqlAwsApigatewayv2DomainName, error) {
	configs, err := convert.JsonToDictSlice(dn.DomainNameConfigurations)
	if err != nil {
		return nil, err
	}
	mtls, err := convert.JsonToDict(dn.MutualTlsAuthentication)
	if err != nil {
		return nil, err
	}
	domain := ""
	if dn.DomainName != nil {
		domain = *dn.DomainName
	}
	arn := ""
	if dn.DomainNameArn != nil {
		arn = *dn.DomainNameArn
	}
	if arn == "" {
		arn = fmt.Sprintf("%s/domainNames/%s", region, domain)
	}
	res, err := CreateResource(runtime, "aws.apigatewayv2.domainName", map[string]*llx.RawData{
		"__id":                          llx.StringData(arn),
		"domainName":                    llx.StringData(domain),
		"arn":                           llx.StringData(arn),
		"region":                        llx.StringData(region),
		"routingMode":                   llx.StringData(string(dn.RoutingMode)),
		"apiMappingSelectionExpression": llx.StringDataPtr(dn.ApiMappingSelectionExpression),
		"domainNameConfigurations":      llx.ArrayData(configs, types.Dict),
		"mutualTlsAuthentication":       llx.DictData(mtls),
		"tags":                          llx.MapData(stringMapToAny(dn.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayv2DomainName), nil
}

func (a *mqlAwsApigatewayv2DomainName) id() (string, error) {
	return a.Arn.Data, nil
}

// isPublic reports whether the route can be invoked without authentication —
// its authorization type is NONE (or unset), meaning no IAM signature, JWT, or
// custom authorizer is required.
func (a *mqlAwsApigatewayv2Route) isPublic() (bool, error) {
	authType := a.GetAuthorizationType()
	if authType.Error != nil {
		return false, authType.Error
	}
	return routeAuthIsPublic(authType.Data), nil
}

// routeAuthIsPublic reports whether an API Gateway v2 route authorization type
// leaves the route open. NONE (the default when no authorizer is attached) means
// unauthenticated public access; AWS_IAM, JWT, and CUSTOM all require a caller
// identity.
func routeAuthIsPublic(authorizationType string) bool {
	return authorizationType == "" || strings.EqualFold(authorizationType, "NONE")
}
