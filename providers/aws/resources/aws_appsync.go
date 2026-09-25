// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsAppsync) id() (string, error) {
	return "aws.appsync", nil
}

// ---------- aws.appsync.graphqlApi ----------

// mqlAwsAppsyncGraphqlApiInternal caches values needed to resolve typed
// references and the lazily-fetched response cache.
type mqlAwsAppsyncGraphqlApiInternal struct {
	wafWebAclArn      string
	logCloudWatchRole string
	cacheLock         sync.Mutex
	cacheFetched      bool
	cacheData         *appsynctypes.ApiCache
}

func (a *mqlAwsAppsync) apis() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getApis(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result == nil {
			continue
		}
		res = append(res, pool.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsAppsync) getApis(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			svc := conn.Appsync(region)
			ctx := context.Background()
			var nextToken *string
			for {
				out, err := svc.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied for appsync ListGraphqlApis")
						return res, nil
					}
					return nil, err
				}
				for _, api := range out.GraphqlApis {
					mqlApi, err := newMqlAwsAppsyncGraphqlApi(a.MqlRuntime, region, api)
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

func newMqlAwsAppsyncGraphqlApi(runtime *plugin.Runtime, region string, api appsynctypes.GraphqlApi) (*mqlAwsAppsyncGraphqlApi, error) {
	additionalAuth, err := convert.JsonToDictSlice(api.AdditionalAuthenticationProviders)
	if err != nil {
		return nil, err
	}

	logFieldLogLevel := ""
	logExcludeVerboseContent := false
	logCloudWatchRole := ""
	if api.LogConfig != nil {
		logFieldLogLevel = string(api.LogConfig.FieldLogLevel)
		logExcludeVerboseContent = api.LogConfig.ExcludeVerboseContent
		if api.LogConfig.CloudWatchLogsRoleArn != nil {
			logCloudWatchRole = *api.LogConfig.CloudWatchLogsRoleArn
		}
	}

	arn := convert.ToValue(api.Arn)
	res, err := CreateResource(runtime, "aws.appsync.graphqlApi", map[string]*llx.RawData{
		"__id":                              llx.StringData(arn),
		"apiId":                             llx.StringDataPtr(api.ApiId),
		"arn":                               llx.StringData(arn),
		"name":                              llx.StringDataPtr(api.Name),
		"region":                            llx.StringData(region),
		"authenticationType":                llx.StringData(string(api.AuthenticationType)),
		"additionalAuthenticationProviders": llx.ArrayData(additionalAuth, types.Dict),
		"logFieldLogLevel":                  llx.StringData(logFieldLogLevel),
		"logExcludeVerboseContent":          llx.BoolData(logExcludeVerboseContent),
		"xrayEnabled":                       llx.BoolData(api.XrayEnabled),
		"visibility":                        llx.StringData(string(api.Visibility)),
		"apiType":                           llx.StringData(string(api.ApiType)),
		"introspectionConfig":               llx.StringData(string(api.IntrospectionConfig)),
		"queryDepthLimit":                   llx.IntData(int64(api.QueryDepthLimit)),
		"resolverCountLimit":                llx.IntData(int64(api.ResolverCountLimit)),
		"uris":                              llx.MapData(stringMapToAny(api.Uris), types.String),
		"ownerContact":                      llx.StringDataPtr(api.OwnerContact),
		"tags":                              llx.MapData(stringMapToAny(api.Tags), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlApi := res.(*mqlAwsAppsyncGraphqlApi)
	mqlApi.wafWebAclArn = convert.ToValue(api.WafWebAclArn)
	mqlApi.logCloudWatchRole = logCloudWatchRole
	return mqlApi, nil
}

func (a *mqlAwsAppsyncGraphqlApi) id() (string, error) {
	return a.Arn.Data, nil
}

// initAwsAppsyncGraphqlApi lets `aws.appsync.graphqlApi(apiId: "...")`
// resolve a previously-fetched API by its apiId.
func initAwsAppsyncGraphqlApi(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["apiId"] == nil {
		return args, nil, errors.New("apiId required to fetch aws.appsync.graphqlApi")
	}

	obj, err := CreateResource(runtime, "aws.appsync", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	apis := obj.(*mqlAwsAppsync).GetApis()
	if apis.Error != nil {
		return nil, nil, apis.Error
	}

	want := args["apiId"].Value.(string)
	for _, r := range apis.Data {
		api := r.(*mqlAwsAppsyncGraphqlApi)
		if api.ApiId.Data == want {
			return args, api, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.appsync.graphqlApi with apiId %q not found", want)
}

func (a *mqlAwsAppsyncGraphqlApi) logCloudWatchLogsRole() (*mqlAwsIamRole, error) {
	if a.logCloudWatchRole == "" {
		a.LogCloudWatchLogsRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.logCloudWatchRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsAppsyncGraphqlApi) webAcl() (*mqlAwsWafAcl, error) {
	if a.wafWebAclArn == "" {
		a.WebAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.waf.acl",
		map[string]*llx.RawData{"arn": llx.StringData(a.wafWebAclArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAcl), nil
}

// fetchCache lazily retrieves the API's response cache. AppSync returns a
// NotFoundException when no cache is provisioned, in which case it returns
// (nil, nil) so callers can mark their fields null.
func (a *mqlAwsAppsyncGraphqlApi) fetchCache() (*appsynctypes.ApiCache, error) {
	if a.cacheFetched {
		return a.cacheData, nil
	}
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	if a.cacheFetched {
		return a.cacheData, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Appsync(a.Region.Data)
	apiId := a.ApiId.Data
	out, err := svc.GetApiCache(context.Background(), &appsync.GetApiCacheInput{ApiId: &apiId})
	if err != nil {
		var notFound *appsynctypes.NotFoundException
		if errors.As(err, &notFound) {
			a.cacheFetched = true
			return nil, nil
		}
		return nil, classifyAwsError(err, "appsync:GetApiCache")
	}
	a.cacheFetched = true
	a.cacheData = out.ApiCache
	return a.cacheData, nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheBehavior() (string, error) {
	c, err := a.fetchCache()
	if err != nil {
		return "", err
	}
	if c == nil {
		a.CacheBehavior.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(c.ApiCachingBehavior), nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheType() (string, error) {
	c, err := a.fetchCache()
	if err != nil {
		return "", err
	}
	if c == nil {
		a.CacheType.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(c.Type), nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheStatus() (string, error) {
	c, err := a.fetchCache()
	if err != nil {
		return "", err
	}
	if c == nil {
		a.CacheStatus.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(c.Status), nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheTtl() (int64, error) {
	c, err := a.fetchCache()
	if err != nil {
		return 0, err
	}
	if c == nil {
		a.CacheTtl.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return c.Ttl, nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheAtRestEncryptionEnabled() (bool, error) {
	c, err := a.fetchCache()
	if err != nil {
		return false, err
	}
	if c == nil {
		a.CacheAtRestEncryptionEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return c.AtRestEncryptionEnabled, nil
}

func (a *mqlAwsAppsyncGraphqlApi) cacheTransitEncryptionEnabled() (bool, error) {
	c, err := a.fetchCache()
	if err != nil {
		return false, err
	}
	if c == nil {
		a.CacheTransitEncryptionEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return c.TransitEncryptionEnabled, nil
}

// ---------- aws.appsync.apiKey ----------

func (a *mqlAwsAppsyncGraphqlApi) apiKeys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Appsync(a.Region.Data)
	ctx := context.Background()
	apiId := a.ApiId.Data

	res := []any{}
	var nextToken *string
	for {
		out, err := svc.ListApiKeys(ctx, &appsync.ListApiKeysInput{ApiId: &apiId, NextToken: nextToken})
		if err != nil {
			return nil, classifyAwsError(err, "appsync:ListApiKeys")
		}
		for _, key := range out.ApiKeys {
			keyId := convert.ToValue(key.Id)
			mqlKey, err := CreateResource(a.MqlRuntime, "aws.appsync.apiKey", map[string]*llx.RawData{
				"__id":        llx.StringData(fmt.Sprintf("%s/apikeys/%s", apiId, keyId)),
				"id":          llx.StringData(keyId),
				"apiId":       llx.StringData(apiId),
				"description": llx.StringDataPtr(key.Description),
				"expires":     llx.TimeDataPtr(appsyncEpochTime(key.Expires)),
				"deletes":     llx.TimeDataPtr(appsyncEpochTime(key.Deletes)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlKey)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return res, nil
}

func (a *mqlAwsAppsyncApiKey) id() (string, error) {
	return fmt.Sprintf("%s/apikeys/%s", a.ApiId.Data, a.Id.Data), nil
}

// appsyncEpochTime converts an AppSync epoch-seconds timestamp to a
// *time.Time, returning nil when the value is unset (0).
func appsyncEpochTime(sec int64) *time.Time {
	if sec == 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}
