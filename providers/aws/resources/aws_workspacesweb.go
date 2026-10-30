// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/workspacesweb"
	workspaceswebtypes "github.com/aws/aws-sdk-go-v2/service/workspacesweb/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isWorkspacesWebRegionError checks if the error indicates the WorkSpaces Web
// service is not available or reachable in the given region.
func isWorkspacesWebRegionError(err error) bool {
	return Is400AccessDeniedError(err) ||
		IsServiceNotAvailableInRegionError(err) ||
		errors.Is(err, context.DeadlineExceeded)
}

func (a *mqlAwsWorkspacesweb) id() (string, error) {
	return "aws.workspacesweb", nil
}

// Portals

func (a *mqlAwsWorkspacesweb) portals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPortals(conn), 5)
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

func (a *mqlAwsWorkspacesweb) getPortals(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspacesweb>getPortals>calling aws with region %s", region)
			svc := conn.WorkspacesWeb(region)
			res := []any{}

			var nextToken *string
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := svc.ListPortals(ctx, &workspacesweb.ListPortalsInput{
					NextToken: nextToken,
				})
				cancel()
				if err != nil {
					if isWorkspacesWebRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces Web portal API")
						return res, nil
					}
					return nil, err
				}
				for _, portal := range resp.Portals {
					mqlPortal, err := newMqlAwsWorkspaceswebPortal(a.MqlRuntime, region, portal)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPortal)
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

func newMqlAwsWorkspaceswebPortal(runtime *plugin.Runtime, region string, portal workspaceswebtypes.PortalSummary) (*mqlAwsWorkspaceswebPortal, error) {
	res, err := CreateResource(runtime, "aws.workspacesweb.portal",
		map[string]*llx.RawData{
			"__id":                      llx.StringDataPtr(portal.PortalArn),
			"portalArn":                 llx.StringDataPtr(portal.PortalArn),
			"displayName":               llx.StringDataPtr(portal.DisplayName),
			"portalEndpoint":            llx.StringDataPtr(portal.PortalEndpoint),
			"portalStatus":              llx.StringData(string(portal.PortalStatus)),
			"authenticationType":        llx.StringData(string(portal.AuthenticationType)),
			"browserType":               llx.StringData(string(portal.BrowserType)),
			"instanceType":              llx.StringData(string(portal.InstanceType)),
			"rendererType":              llx.StringData(string(portal.RendererType)),
			"browserSettingsArn":        llx.StringDataPtr(portal.BrowserSettingsArn),
			"networkSettingsArn":        llx.StringDataPtr(portal.NetworkSettingsArn),
			"dataProtectionSettingsArn": llx.StringDataPtr(portal.DataProtectionSettingsArn),
			"maxConcurrentSessions":     llx.IntDataDefault(portal.MaxConcurrentSessions, 0),
			"creationDate":              llx.TimeDataPtr(portal.CreationDate),
			"region":                    llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsWorkspaceswebPortal).cacheUserSettingsArn = convert.ToValue(portal.UserSettingsArn)
	res.(*mqlAwsWorkspaceswebPortal).cacheTrustStoreArn = convert.ToValue(portal.TrustStoreArn)
	res.(*mqlAwsWorkspaceswebPortal).cacheIpAccessSettingsArn = convert.ToValue(portal.IpAccessSettingsArn)
	res.(*mqlAwsWorkspaceswebPortal).cacheUserAccessLoggingSettingsArn = convert.ToValue(portal.UserAccessLoggingSettingsArn)
	return res.(*mqlAwsWorkspaceswebPortal), nil
}

func (a *mqlAwsWorkspaceswebPortal) id() (string, error) {
	return a.PortalArn.Data, nil
}

type mqlAwsWorkspaceswebPortalInternal struct {
	cacheUserSettingsArn              string
	cacheTrustStoreArn                string
	cacheIpAccessSettingsArn          string
	cacheUserAccessLoggingSettingsArn string
	detailFetched                     bool
	detailLock                        sync.Mutex
	cacheCustomerManagedKey           string
	cachePortalCustomDomain           string
	cacheStatusReason                 string
	cacheSessionLoggerArn             string
}

// fetchDetail calls GetPortal once to populate fields that ListPortals doesn't
// return (currently: customerManagedKey). Errors that look like "service
// unavailable in this region" are swallowed so the portal still renders.
func (a *mqlAwsWorkspaceswebPortal) fetchDetail() error {
	if a.detailFetched {
		return nil
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.WorkspacesWeb(a.Region.Data)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	arn := a.PortalArn.Data
	resp, err := svc.GetPortal(ctx, &workspacesweb.GetPortalInput{PortalArn: &arn})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.detailFetched = true
			return nil
		}
		return err
	}
	if resp.Portal != nil {
		a.cacheCustomerManagedKey = convert.ToValue(resp.Portal.CustomerManagedKey)
		a.cachePortalCustomDomain = convert.ToValue(resp.Portal.PortalCustomDomain)
		a.cacheStatusReason = convert.ToValue(resp.Portal.StatusReason)
		a.cacheSessionLoggerArn = convert.ToValue(resp.Portal.SessionLoggerArn)
	}
	a.detailFetched = true
	return nil
}

func (a *mqlAwsWorkspaceswebPortal) customerManagedKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return workspaceswebKmsKeyFromArn(a.MqlRuntime, a.cacheCustomerManagedKey, &a.CustomerManagedKey)
}

func (a *mqlAwsWorkspaceswebPortal) portalCustomDomain() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.cachePortalCustomDomain, nil
}

func (a *mqlAwsWorkspaceswebPortal) statusReason() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.cacheStatusReason, nil
}

func (a *mqlAwsWorkspaceswebPortal) sessionLoggerArn() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.cacheSessionLoggerArn, nil
}

func (a *mqlAwsWorkspaceswebPortal) userAccessLoggingSetting() (*mqlAwsWorkspaceswebUserAccessLoggingSetting, error) {
	arnVal := a.cacheUserAccessLoggingSettingsArn
	if arnVal == "" {
		a.UserAccessLoggingSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.workspacesweb.userAccessLoggingSetting",
		map[string]*llx.RawData{"userAccessLoggingSettingsArn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWorkspaceswebUserAccessLoggingSetting), nil
}

// User Access Logging Settings

func (a *mqlAwsWorkspacesweb) userAccessLoggingSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUserAccessLoggingSettings(conn), 5)
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

func (a *mqlAwsWorkspacesweb) getUserAccessLoggingSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspacesweb>getUserAccessLoggingSettings>calling aws with region %s", region)
			svc := conn.WorkspacesWeb(region)
			res := []any{}

			var nextToken *string
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := svc.ListUserAccessLoggingSettings(ctx, &workspacesweb.ListUserAccessLoggingSettingsInput{
					NextToken: nextToken,
				})
				cancel()
				if err != nil {
					if isWorkspacesWebRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces Web user access logging settings API")
						return res, nil
					}
					return nil, err
				}
				for _, setting := range resp.UserAccessLoggingSettings {
					mqlSetting, err := newMqlAwsWorkspaceswebUserAccessLoggingSetting(a.MqlRuntime, region, setting)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSetting)
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

func newMqlAwsWorkspaceswebUserAccessLoggingSetting(runtime *plugin.Runtime, region string, setting workspaceswebtypes.UserAccessLoggingSettingsSummary) (*mqlAwsWorkspaceswebUserAccessLoggingSetting, error) {
	res, err := CreateResource(runtime, "aws.workspacesweb.userAccessLoggingSetting",
		map[string]*llx.RawData{
			"__id":                         llx.StringDataPtr(setting.UserAccessLoggingSettingsArn),
			"userAccessLoggingSettingsArn": llx.StringDataPtr(setting.UserAccessLoggingSettingsArn),
			"region":                       llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsWorkspaceswebUserAccessLoggingSetting).cacheKinesisStreamArn = convert.ToValue(setting.KinesisStreamArn)
	return res.(*mqlAwsWorkspaceswebUserAccessLoggingSetting), nil
}

func (a *mqlAwsWorkspaceswebUserAccessLoggingSetting) id() (string, error) {
	return a.UserAccessLoggingSettingsArn.Data, nil
}

func (a *mqlAwsWorkspaceswebUserAccessLoggingSetting) kinesisStream() (*mqlAwsKinesisStream, error) {
	arnVal := a.cacheKinesisStreamArn
	if arnVal == "" {
		a.KinesisStream.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kinesis.stream",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKinesisStream), nil
}

// IP Access Settings

func (a *mqlAwsWorkspacesweb) ipAccessSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getIpAccessSettings(conn), 5)
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

func (a *mqlAwsWorkspacesweb) getIpAccessSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspacesweb>getIpAccessSettings>calling aws with region %s", region)
			svc := conn.WorkspacesWeb(region)
			res := []any{}

			var nextToken *string
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := svc.ListIpAccessSettings(ctx, &workspacesweb.ListIpAccessSettingsInput{
					NextToken: nextToken,
				})
				cancel()
				if err != nil {
					if isWorkspacesWebRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces Web IP access settings API")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range resp.IpAccessSettings {
					mql, err := newMqlAwsWorkspaceswebIpAccessSettingsFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mql)
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

type mqlAwsWorkspaceswebIpAccessSettingInternal struct {
	detailFetched           bool
	detailLock              sync.Mutex
	associatedArns          []string
	cacheCustomerManagedKey string
	cacheIpRules            []any
}

// fetchDetail calls GetIpAccessSettings once and caches everything that
// IpAccessSettingsSummary doesn't include (associatedPortalArns,
// customerManagedKey). Both associatedPortals() and customerManagedKey()
// route through here so a single API call serves both.
func (a *mqlAwsWorkspaceswebIpAccessSetting) fetchDetail() error {
	if a.detailFetched {
		return nil
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.WorkspacesWeb(a.Region.Data)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	arn := a.IpAccessSettingsArn.Data
	resp, err := svc.GetIpAccessSettings(ctx, &workspacesweb.GetIpAccessSettingsInput{IpAccessSettingsArn: &arn})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.detailFetched = true
			return nil
		}
		return err
	}
	if resp.IpAccessSettings != nil {
		a.associatedArns = append([]string(nil), resp.IpAccessSettings.AssociatedPortalArns...)
		a.cacheCustomerManagedKey = convert.ToValue(resp.IpAccessSettings.CustomerManagedKey)
		a.cacheIpRules = ipRulesToDicts(resp.IpAccessSettings.IpRules)
	}
	a.detailFetched = true
	return nil
}

func ipRulesToDicts(rules []workspaceswebtypes.IpRule) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, map[string]any{
			"ipRange":     awsString(r.IpRange),
			"description": awsString(r.Description),
		})
	}
	return out
}

func (a *mqlAwsWorkspaceswebIpAccessSetting) ipRules() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.cacheIpRules, nil
}

func newMqlAwsWorkspaceswebIpAccessSettingsFromSummary(runtime *plugin.Runtime, region string, summary workspaceswebtypes.IpAccessSettingsSummary) (*mqlAwsWorkspaceswebIpAccessSetting, error) {
	res, err := CreateResource(runtime, "aws.workspacesweb.ipAccessSetting",
		map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(summary.IpAccessSettingsArn),
			"ipAccessSettingsArn": llx.StringDataPtr(summary.IpAccessSettingsArn),
			"displayName":         llx.StringDataPtr(summary.DisplayName),
			"description":         llx.StringDataPtr(summary.Description),
			"creationDate":        llx.TimeDataPtr(summary.CreationDate),
			"region":              llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWorkspaceswebIpAccessSetting), nil
}

func newMqlAwsWorkspaceswebIpAccessSettingsFromDetail(runtime *plugin.Runtime, region string, ipas *workspaceswebtypes.IpAccessSettings) (*mqlAwsWorkspaceswebIpAccessSetting, error) {
	if ipas == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "aws.workspacesweb.ipAccessSetting",
		map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(ipas.IpAccessSettingsArn),
			"ipAccessSettingsArn": llx.StringDataPtr(ipas.IpAccessSettingsArn),
			"displayName":         llx.StringDataPtr(ipas.DisplayName),
			"description":         llx.StringDataPtr(ipas.Description),
			"creationDate":        llx.TimeDataPtr(ipas.CreationDate),
			"region":              llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mql := res.(*mqlAwsWorkspaceswebIpAccessSetting)
	mql.associatedArns = append([]string(nil), ipas.AssociatedPortalArns...)
	mql.cacheCustomerManagedKey = convert.ToValue(ipas.CustomerManagedKey)
	mql.cacheIpRules = ipRulesToDicts(ipas.IpRules)
	mql.detailFetched = true
	return mql, nil
}

func (a *mqlAwsWorkspaceswebIpAccessSetting) associatedPortals() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return associatedPortalsFromArns(a.MqlRuntime, a.associatedArns)
}

func (a *mqlAwsWorkspaceswebIpAccessSetting) id() (string, error) {
	return a.IpAccessSettingsArn.Data, nil
}

func (a *mqlAwsWorkspaceswebIpAccessSetting) customerManagedKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return workspaceswebKmsKeyFromArn(a.MqlRuntime, a.cacheCustomerManagedKey, &a.CustomerManagedKey)
}

// Trust Stores

func (a *mqlAwsWorkspacesweb) trustStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrustStores(conn), 5)
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

func (a *mqlAwsWorkspacesweb) getTrustStores(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspacesweb>getTrustStores>calling aws with region %s", region)
			svc := conn.WorkspacesWeb(region)
			res := []any{}

			var nextToken *string
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := svc.ListTrustStores(ctx, &workspacesweb.ListTrustStoresInput{
					NextToken: nextToken,
				})
				cancel()
				if err != nil {
					if isWorkspacesWebRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces Web trust store API")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range resp.TrustStores {
					mql, err := newMqlAwsWorkspaceswebTrustStoreFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mql)
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

type mqlAwsWorkspaceswebTrustStoreInternal struct {
	associatedFetched bool
	associatedLock    sync.Mutex
	associatedArns    []string
}

func newMqlAwsWorkspaceswebTrustStoreFromSummary(runtime *plugin.Runtime, region string, summary workspaceswebtypes.TrustStoreSummary) (*mqlAwsWorkspaceswebTrustStore, error) {
	res, err := CreateResource(runtime, "aws.workspacesweb.trustStore",
		map[string]*llx.RawData{
			"__id":          llx.StringDataPtr(summary.TrustStoreArn),
			"trustStoreArn": llx.StringDataPtr(summary.TrustStoreArn),
			"region":        llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWorkspaceswebTrustStore), nil
}

func newMqlAwsWorkspaceswebTrustStoreFromDetail(runtime *plugin.Runtime, region string, ts *workspaceswebtypes.TrustStore) (*mqlAwsWorkspaceswebTrustStore, error) {
	if ts == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "aws.workspacesweb.trustStore",
		map[string]*llx.RawData{
			"__id":          llx.StringDataPtr(ts.TrustStoreArn),
			"trustStoreArn": llx.StringDataPtr(ts.TrustStoreArn),
			"region":        llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mql := res.(*mqlAwsWorkspaceswebTrustStore)
	mql.associatedArns = append([]string(nil), ts.AssociatedPortalArns...)
	mql.associatedFetched = true
	return mql, nil
}

func (a *mqlAwsWorkspaceswebTrustStore) associatedPortals() ([]any, error) {
	if !a.associatedFetched {
		a.associatedLock.Lock()
		defer a.associatedLock.Unlock()
		if !a.associatedFetched {
			conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
			svc := conn.WorkspacesWeb(a.Region.Data)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			arn := a.TrustStoreArn.Data
			resp, err := svc.GetTrustStore(ctx, &workspacesweb.GetTrustStoreInput{TrustStoreArn: &arn})
			if err != nil {
				if isWorkspacesWebRegionError(err) {
					a.associatedFetched = true
					return []any{}, nil
				}
				return nil, err
			}
			if resp.TrustStore != nil {
				a.associatedArns = append([]string(nil), resp.TrustStore.AssociatedPortalArns...)
			}
			a.associatedFetched = true
		}
	}
	return associatedPortalsFromArns(a.MqlRuntime, a.associatedArns)
}

func (a *mqlAwsWorkspaceswebTrustStore) id() (string, error) {
	return a.TrustStoreArn.Data, nil
}

// User Settings

func (a *mqlAwsWorkspacesweb) userSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getUserSettings(conn), 5)
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

func (a *mqlAwsWorkspacesweb) getUserSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("workspacesweb>getUserSettings>calling aws with region %s", region)
			svc := conn.WorkspacesWeb(region)
			res := []any{}

			var nextToken *string
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				resp, err := svc.ListUserSettings(ctx, &workspacesweb.ListUserSettingsInput{
					NextToken: nextToken,
				})
				cancel()
				if err != nil {
					if isWorkspacesWebRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS WorkSpaces Web user settings API")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range resp.UserSettings {
					mql, err := newMqlAwsWorkspaceswebUserSettingsFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mql)
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

type mqlAwsWorkspaceswebUserSettingInternal struct {
	detailFetched           bool
	detailLock              sync.Mutex
	associatedArns          []string
	cacheCustomerManagedKey string
	cacheWebAuthnAllowed    string
}

// fetchDetail calls GetUserSettings once and caches everything that
// UserSettingsSummary doesn't include (associatedPortalArns, customerManagedKey).
// Both associatedPortals() and customerManagedKey() route through here.
func (a *mqlAwsWorkspaceswebUserSetting) fetchDetail() error {
	if a.detailFetched {
		return nil
	}
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.WorkspacesWeb(a.Region.Data)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	arn := a.UserSettingsArn.Data
	resp, err := svc.GetUserSettings(ctx, &workspacesweb.GetUserSettingsInput{UserSettingsArn: &arn})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.detailFetched = true
			return nil
		}
		return err
	}
	if resp.UserSettings != nil {
		a.associatedArns = append([]string(nil), resp.UserSettings.AssociatedPortalArns...)
		a.cacheCustomerManagedKey = convert.ToValue(resp.UserSettings.CustomerManagedKey)
		a.cacheWebAuthnAllowed = string(resp.UserSettings.WebAuthnAllowed)
	}
	a.detailFetched = true
	return nil
}

func (a *mqlAwsWorkspaceswebUserSetting) webAuthnAllowed() (string, error) {
	if err := a.fetchDetail(); err != nil {
		return "", err
	}
	return a.cacheWebAuthnAllowed, nil
}

func newMqlAwsWorkspaceswebUserSettingsFromSummary(runtime *plugin.Runtime, region string, summary workspaceswebtypes.UserSettingsSummary) (*mqlAwsWorkspaceswebUserSetting, error) {
	res, err := CreateResource(runtime, "aws.workspacesweb.userSetting",
		map[string]*llx.RawData{
			"__id":                           llx.StringDataPtr(summary.UserSettingsArn),
			"userSettingsArn":                llx.StringDataPtr(summary.UserSettingsArn),
			"copyAllowed":                    llx.StringData(string(summary.CopyAllowed)),
			"pasteAllowed":                   llx.StringData(string(summary.PasteAllowed)),
			"downloadAllowed":                llx.StringData(string(summary.DownloadAllowed)),
			"uploadAllowed":                  llx.StringData(string(summary.UploadAllowed)),
			"printAllowed":                   llx.StringData(string(summary.PrintAllowed)),
			"deepLinkAllowed":                llx.StringData(string(summary.DeepLinkAllowed)),
			"disconnectTimeoutInMinutes":     llx.IntDataDefault(summary.DisconnectTimeoutInMinutes, 0),
			"idleDisconnectTimeoutInMinutes": llx.IntDataDefault(summary.IdleDisconnectTimeoutInMinutes, 0),
			"region":                         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWorkspaceswebUserSetting), nil
}

func newMqlAwsWorkspaceswebUserSettingsFromDetail(runtime *plugin.Runtime, region string, us *workspaceswebtypes.UserSettings) (*mqlAwsWorkspaceswebUserSetting, error) {
	if us == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "aws.workspacesweb.userSetting",
		map[string]*llx.RawData{
			"__id":                           llx.StringDataPtr(us.UserSettingsArn),
			"userSettingsArn":                llx.StringDataPtr(us.UserSettingsArn),
			"copyAllowed":                    llx.StringData(string(us.CopyAllowed)),
			"pasteAllowed":                   llx.StringData(string(us.PasteAllowed)),
			"downloadAllowed":                llx.StringData(string(us.DownloadAllowed)),
			"uploadAllowed":                  llx.StringData(string(us.UploadAllowed)),
			"printAllowed":                   llx.StringData(string(us.PrintAllowed)),
			"deepLinkAllowed":                llx.StringData(string(us.DeepLinkAllowed)),
			"disconnectTimeoutInMinutes":     llx.IntDataDefault(us.DisconnectTimeoutInMinutes, 0),
			"idleDisconnectTimeoutInMinutes": llx.IntDataDefault(us.IdleDisconnectTimeoutInMinutes, 0),
			"region":                         llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mql := res.(*mqlAwsWorkspaceswebUserSetting)
	mql.associatedArns = append([]string(nil), us.AssociatedPortalArns...)
	mql.cacheCustomerManagedKey = convert.ToValue(us.CustomerManagedKey)
	mql.cacheWebAuthnAllowed = string(us.WebAuthnAllowed)
	mql.detailFetched = true
	return mql, nil
}

func (a *mqlAwsWorkspaceswebUserSetting) id() (string, error) {
	return a.UserSettingsArn.Data, nil
}

func (a *mqlAwsWorkspaceswebUserSetting) customerManagedKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return workspaceswebKmsKeyFromArn(a.MqlRuntime, a.cacheCustomerManagedKey, &a.CustomerManagedKey)
}

func (a *mqlAwsWorkspaceswebUserSetting) associatedPortals() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return associatedPortalsFromArns(a.MqlRuntime, a.associatedArns)
}

// Portal typed references — call Get* for the linked sub-resource so the
// returned object reflects current state instead of an init-stub. (List* on
// these resources doesn't surface portal associations.)

func (a *mqlAwsWorkspaceswebPortal) ipAccessSettings() (*mqlAwsWorkspaceswebIpAccessSetting, error) {
	arnVal := a.cacheIpAccessSettingsArn
	if arnVal == "" {
		a.IpAccessSettings.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.WorkspacesWeb(region)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := svc.GetIpAccessSettings(ctx, &workspacesweb.GetIpAccessSettingsInput{IpAccessSettingsArn: &arnVal})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.IpAccessSettings.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	return newMqlAwsWorkspaceswebIpAccessSettingsFromDetail(a.MqlRuntime, region, resp.IpAccessSettings)
}

func (a *mqlAwsWorkspaceswebPortal) trustStore() (*mqlAwsWorkspaceswebTrustStore, error) {
	arnVal := a.cacheTrustStoreArn
	if arnVal == "" {
		a.TrustStore.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.WorkspacesWeb(region)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := svc.GetTrustStore(ctx, &workspacesweb.GetTrustStoreInput{TrustStoreArn: &arnVal})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.TrustStore.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	return newMqlAwsWorkspaceswebTrustStoreFromDetail(a.MqlRuntime, region, resp.TrustStore)
}

func (a *mqlAwsWorkspaceswebPortal) userSettings() (*mqlAwsWorkspaceswebUserSetting, error) {
	arnVal := a.cacheUserSettingsArn
	if arnVal == "" {
		a.UserSettings.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.WorkspacesWeb(region)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := svc.GetUserSettings(ctx, &workspacesweb.GetUserSettingsInput{UserSettingsArn: &arnVal})
	if err != nil {
		if isWorkspacesWebRegionError(err) {
			a.UserSettings.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	return newMqlAwsWorkspaceswebUserSettingsFromDetail(a.MqlRuntime, region, resp.UserSettings)
}

func awsString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// workspaceswebKmsKeyFromArn returns a typed aws.kms.key for a customer-managed
// key ARN, or null when the ARN is empty (i.e. the resource uses an AWS-managed
// key). Resources that don't pre-cache the ARN call this with "" and get null.
func workspaceswebKmsKeyFromArn(runtime *plugin.Runtime, arn string, state *plugin.TValue[*mqlAwsKmsKey]) (*mqlAwsKmsKey, error) {
	if arn == "" {
		state.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.kms.key", map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

// initAwsWorkspaceswebUserAccessLoggingSetting resolves a setting looked up by
// ARN. The lister yields these per region, so we list once and find the match.
// Falls back to a bare resource if the setting can't be listed.
func initAwsWorkspaceswebUserAccessLoggingSetting(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnArg, ok := args["userAccessLoggingSettingsArn"]
	if !ok || arnArg == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "aws.workspacesweb", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	wsweb := obj.(*mqlAwsWorkspacesweb)
	rawSettings := wsweb.GetUserAccessLoggingSettings()
	if rawSettings.Error != nil {
		return nil, nil, rawSettings.Error
	}
	for _, s := range rawSettings.Data {
		setting := s.(*mqlAwsWorkspaceswebUserAccessLoggingSetting)
		if setting.UserAccessLoggingSettingsArn.Data == arnVal {
			return nil, setting, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.workspacesweb.userAccessLoggingSetting with arn %q not found", arnVal)
}

// associatedPortalsFromArns returns typed aws.workspacesweb.portal references
// for each ARN. The resulting resources may be bare (just portalArn) until a
// caller traverses an attribute that triggers initAwsWorkspaceswebPortal.
func associatedPortalsFromArns(runtime *plugin.Runtime, arns []string) ([]any, error) {
	res := make([]any, 0, len(arns))
	for _, arn := range arns {
		if arn == "" {
			continue
		}
		portal, err := NewResource(runtime, "aws.workspacesweb.portal",
			map[string]*llx.RawData{"portalArn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, portal)
	}
	return res, nil
}

// initAwsWorkspaceswebPortal resolves a portal looked up by ARN — typically
// from associatedPortals() on ipAccessSettings/trustStore/userSettings. When
// the portal hasn't been listed yet, fall back to ListPortals across all
// regions to find the matching ARN. If found, returns the populated portal;
// if not, returns the bare {portalArn} so callers can still render the ARN.
func initAwsWorkspaceswebPortal(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// already resolved
	if len(args) > 2 {
		return args, nil, nil
	}
	arnArg, ok := args["portalArn"]
	if !ok || arnArg == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "aws.workspacesweb", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	wsweb := obj.(*mqlAwsWorkspacesweb)
	rawPortals := wsweb.GetPortals()
	if rawPortals.Error != nil {
		return nil, nil, rawPortals.Error
	}
	for _, p := range rawPortals.Data {
		portal := p.(*mqlAwsWorkspaceswebPortal)
		if portal.PortalArn.Data == arnVal {
			return nil, portal, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.workspacesweb.portal with arn %q not found", arnVal)
}

type mqlAwsWorkspaceswebUserAccessLoggingSettingInternal struct {
	cacheKinesisStreamArn string
}
