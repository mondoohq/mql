// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/fms"
	fmstypes "github.com/aws/aws-sdk-go-v2/service/fms/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// mqlAwsFmsInternal caches the GetAdminAccount response so the two computed
// methods that draw from it (defaultAdminAccount, defaultAdminRoleStatus)
// share a single API call. Double-checked locked so concurrent field reads
// don't fire the same API twice.
type mqlAwsFmsInternal struct {
	adminFetched bool
	adminAccount string
	adminStatus  string
	adminLock    sync.Mutex
}

// FMS administration is anchored in us-east-1 — the Firewall Manager admin
// account must operate from that region regardless of where individual
// policies live.
const fmsRegion = "us-east-1"

func (a *mqlAwsFms) id() (string, error) {
	return "aws.fms", nil
}

func (a *mqlAwsFms) defaultAdminAccount() (string, error) {
	account, _, err := a.fetchAdminAccount()
	return account, err
}

func (a *mqlAwsFms) defaultAdminRoleStatus() (string, error) {
	_, status, err := a.fetchAdminAccount()
	return status, err
}

// fetchAdminAccount calls GetAdminAccount at most once per mqlAwsFms
// instance and caches the (account, status) tuple under adminLock so the
// two computed methods above share the result.
func (a *mqlAwsFms) fetchAdminAccount() (string, string, error) {
	if a.adminFetched {
		return a.adminAccount, a.adminStatus, nil
	}
	a.adminLock.Lock()
	defer a.adminLock.Unlock()
	if a.adminFetched {
		return a.adminAccount, a.adminStatus, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	resp, err := svc.GetAdminAccount(context.Background(), &fms.GetAdminAccountInput{})
	if err != nil {
		if isFmsNotAdminError(err) {
			a.adminFetched = true
			a.adminStatus = "UNKNOWN"
			return "", "UNKNOWN", nil
		}
		return "", "", classifyAwsError(err, "fms:GetAdminAccount")
	}
	account := ""
	if resp.AdminAccount != nil {
		account = *resp.AdminAccount
	}
	a.adminAccount = account
	a.adminStatus = string(resp.RoleStatus)
	a.adminFetched = true
	return a.adminAccount, a.adminStatus, nil
}

func isFmsNotAdminError(err error) bool {
	var notFound *fmstypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return true
	}
	var invalidOp *fmstypes.InvalidOperationException
	return errors.As(err, &invalidOp)
}

func (a *mqlAwsFms) adminAccounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	paginator := fms.NewListAdminAccountsForOrganizationPaginator(svc, &fms.ListAdminAccountsForOrganizationInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isFmsNotAdminError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListAdminAccountsForOrganization")
		}
		for _, admin := range page.AdminAccounts {
			mqlAdmin, err := CreateResource(a.MqlRuntime, "aws.fms.adminAccount",
				map[string]*llx.RawData{
					"accountId":    llx.StringDataPtr(admin.AdminAccount),
					"defaultAdmin": llx.BoolData(admin.DefaultAdmin),
					"status":       llx.StringData(string(admin.Status)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAdmin)
		}
	}
	return res, nil
}

func (a *mqlAwsFmsAdminAccount) id() (string, error) {
	return "aws.fms.adminAccount/" + a.AccountId.Data, a.AccountId.Error
}

func (a *mqlAwsFms) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	paginator := fms.NewListPoliciesPaginator(svc, &fms.ListPoliciesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isFmsNotAdminError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListPolicies")
		}
		for _, summary := range page.PolicyList {
			detail, err := svc.GetPolicy(ctx, &fms.GetPolicyInput{PolicyId: summary.PolicyId})
			if err != nil {
				if Is400AccessDeniedError(err) {
					continue
				}
				var notFound *fmstypes.ResourceNotFoundException
				if errors.As(err, &notFound) {
					continue
				}
				return nil, err
			}
			mqlPolicy, err := createFmsPolicy(a.MqlRuntime, summary, detail)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func createFmsPolicy(runtime *plugin.Runtime, summary fmstypes.PolicySummary, detail *fms.GetPolicyOutput) (plugin.Resource, error) {
	arn := summary.PolicyArn
	if arn == nil {
		arn = detail.PolicyArn
	}

	var policy fmstypes.Policy
	if detail.Policy != nil {
		policy = *detail.Policy
	}

	resourceType := ""
	if policy.ResourceType != nil {
		resourceType = *policy.ResourceType
	} else if summary.ResourceType != nil {
		resourceType = *summary.ResourceType
	}

	resourceTypeList := policy.ResourceTypeList

	resourceTags := map[string]any{}
	for _, tag := range policy.ResourceTags {
		if tag.Key == nil {
			continue
		}
		val := ""
		if tag.Value != nil {
			val = *tag.Value
		}
		resourceTags[*tag.Key] = val
	}

	securityServiceType := string(summary.SecurityServiceType)
	var managedServiceData any
	if policy.SecurityServicePolicyData != nil {
		if t := policy.SecurityServicePolicyData.Type; t != "" {
			securityServiceType = string(t)
		}
		if raw := policy.SecurityServicePolicyData.ManagedServiceData; raw != nil && *raw != "" {
			var parsed any
			if err := json.Unmarshal([]byte(*raw), &parsed); err != nil {
				log.Warn().Err(err).Str("policyId", deref(summary.PolicyId)).Msg("failed to parse FMS managed service data")
			} else {
				managedServiceData = parsed
			}
		}
	}

	includeMap := stringSliceMapToAny(policy.IncludeMap)
	excludeMap := stringSliceMapToAny(policy.ExcludeMap)

	return CreateResource(runtime, "aws.fms.policy",
		map[string]*llx.RawData{
			"arn":                               llx.StringDataPtr(arn),
			"id":                                llx.StringDataPtr(summary.PolicyId),
			"name":                              llx.StringDataPtr(summary.PolicyName),
			"description":                       llx.StringDataPtr(policy.PolicyDescription),
			"status":                            llx.StringData(string(summary.PolicyStatus)),
			"remediationEnabled":                llx.BoolData(summary.RemediationEnabled),
			"deleteUnusedFMManagedResources":    llx.BoolData(summary.DeleteUnusedFMManagedResources),
			"resourceType":                      llx.StringData(resourceType),
			"resourceTypeList":                  llx.ArrayData(llx.TArr2Raw(resourceTypeList), types.String),
			"resourceTags":                      llx.MapData(resourceTags, types.String),
			"excludeResourceTags":               llx.BoolData(policy.ExcludeResourceTags),
			"resourceTagLogicalOperator":        llx.StringData(string(policy.ResourceTagLogicalOperator)),
			"securityServiceType":               llx.StringData(securityServiceType),
			"securityServiceManagedServiceData": llx.DictData(managedServiceData),
			"includeMap":                        llx.MapData(includeMap, types.Array(types.String)),
			"excludeMap":                        llx.MapData(excludeMap, types.Array(types.String)),
			"resourceSetIds":                    llx.ArrayData(llx.TArr2Raw(policy.ResourceSetIds), types.String),
		})
}

func stringSliceMapToAny(m map[string][]string) map[string]any {
	if m == nil {
		return nil
	}
	res := make(map[string]any, len(m))
	for k, v := range m {
		arr := make([]any, len(v))
		for i, s := range v {
			arr[i] = s
		}
		res[k] = arr
	}
	return res
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (a *mqlAwsFmsPolicy) id() (string, error) {
	if a.Arn.Error != nil {
		return "", a.Arn.Error
	}
	if a.Arn.Data != "" {
		return a.Arn.Data, nil
	}
	return "aws.fms.policy/" + a.Id.Data, a.Id.Error
}

func (a *mqlAwsFmsPolicy) complianceStatuses() ([]any, error) {
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	policyId := a.Id.Data
	if policyId == "" {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	paginator := fms.NewListComplianceStatusPaginator(svc, &fms.ListComplianceStatusInput{PolicyId: &policyId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			var notFound *fmstypes.ResourceNotFoundException
			if errors.As(err, &notFound) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListComplianceStatus")
		}
		for _, s := range page.PolicyComplianceStatusList {
			entry := map[string]any{
				"memberAccount": deref(s.MemberAccount),
			}
			if s.LastUpdated != nil {
				entry["lastUpdated"] = s.LastUpdated.Format("2006-01-02T15:04:05Z07:00")
			}
			status := ""
			var violatorCount int64
			limitExceeded := false
			for _, ev := range s.EvaluationResults {
				if ev.ComplianceStatus == fmstypes.PolicyComplianceStatusTypeNonCompliant {
					status = string(fmstypes.PolicyComplianceStatusTypeNonCompliant)
				} else if status == "" {
					status = string(ev.ComplianceStatus)
				}
				violatorCount += ev.ViolatorCount
				if ev.EvaluationLimitExceeded {
					limitExceeded = true
				}
			}
			entry["status"] = status
			entry["violatorCount"] = violatorCount
			entry["evaluationLimitExceeded"] = limitExceeded
			if s.IssueInfoMap != nil {
				issues := map[string]any{}
				for k, v := range s.IssueInfoMap {
					issues[k] = v
				}
				entry["issueInfoMap"] = issues
			}
			res = append(res, entry)
		}
	}
	return res, nil
}

func (a *mqlAwsFms) notificationChannel() (*mqlAwsFmsNotificationChannel, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	resp, err := svc.GetNotificationChannel(context.Background(), &fms.GetNotificationChannelInput{})
	if err != nil {
		if isFmsNotAdminError(err) {
			a.NotificationChannel.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, classifyAwsError(err, "fms:GetNotificationChannel")
	}
	if resp.SnsTopicArn == nil && resp.SnsRoleName == nil {
		a.NotificationChannel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlChannel, err := CreateResource(a.MqlRuntime, "aws.fms.notificationChannel",
		map[string]*llx.RawData{
			"snsTopicArn": llx.StringDataPtr(resp.SnsTopicArn),
			"snsRoleName": llx.StringDataPtr(resp.SnsRoleName),
		})
	if err != nil {
		return nil, err
	}
	return mqlChannel.(*mqlAwsFmsNotificationChannel), nil
}

func (a *mqlAwsFmsNotificationChannel) id() (string, error) {
	return "aws.fms.notificationChannel/" + a.SnsTopicArn.Data, a.SnsTopicArn.Error
}

func (a *mqlAwsFmsNotificationChannel) snsTopic() (*mqlAwsSnsTopic, error) {
	if a.SnsTopicArn.Error != nil {
		return nil, a.SnsTopicArn.Error
	}
	if a.SnsTopicArn.Data == "" {
		a.SnsTopic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(a.SnsTopicArn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsFms) appsLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	paginator := fms.NewListAppsListsPaginator(svc, &fms.ListAppsListsInput{
		DefaultLists: false,
		MaxResults:   intPtr32(100),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isFmsNotAdminError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListAppsLists")
		}
		for _, list := range page.AppsLists {
			apps := make([]any, 0, len(list.AppsList))
			for _, app := range list.AppsList {
				appDict := map[string]any{
					"appName":  deref(app.AppName),
					"protocol": deref(app.Protocol),
				}
				if app.Port != nil {
					appDict["port"] = *app.Port
				}
				apps = append(apps, appDict)
			}
			mqlList, err := CreateResource(a.MqlRuntime, "aws.fms.appsList",
				map[string]*llx.RawData{
					"arn":  llx.StringDataPtr(list.ListArn),
					"id":   llx.StringDataPtr(list.ListId),
					"name": llx.StringDataPtr(list.ListName),
					"apps": llx.ArrayData(apps, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlList)
		}
	}
	return res, nil
}

func (a *mqlAwsFmsAppsList) id() (string, error) {
	if a.Arn.Error != nil {
		return "", a.Arn.Error
	}
	if a.Arn.Data != "" {
		return a.Arn.Data, nil
	}
	return "aws.fms.appsList/" + a.Id.Data, a.Id.Error
}

func (a *mqlAwsFms) protocolsLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	paginator := fms.NewListProtocolsListsPaginator(svc, &fms.ListProtocolsListsInput{
		DefaultLists: false,
		MaxResults:   intPtr32(100),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isFmsNotAdminError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListProtocolsLists")
		}
		for _, list := range page.ProtocolsLists {
			mqlList, err := CreateResource(a.MqlRuntime, "aws.fms.protocolsList",
				map[string]*llx.RawData{
					"arn":       llx.StringDataPtr(list.ListArn),
					"id":        llx.StringDataPtr(list.ListId),
					"name":      llx.StringDataPtr(list.ListName),
					"protocols": llx.ArrayData(llx.TArr2Raw(list.ProtocolsList), types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlList)
		}
	}
	return res, nil
}

func (a *mqlAwsFmsProtocolsList) id() (string, error) {
	if a.Arn.Error != nil {
		return "", a.Arn.Error
	}
	if a.Arn.Data != "" {
		return a.Arn.Data, nil
	}
	return "aws.fms.protocolsList/" + a.Id.Data, a.Id.Error
}

func (a *mqlAwsFms) resourceSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		page, err := svc.ListResourceSets(ctx, &fms.ListResourceSetsInput{NextToken: nextToken})
		if err != nil {
			if isFmsNotAdminError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, "fms:ListResourceSets")
		}
		for _, summary := range page.ResourceSets {
			detail, err := svc.GetResourceSet(ctx, &fms.GetResourceSetInput{Identifier: summary.Id})
			if err != nil {
				if Is400AccessDeniedError(err) {
					continue
				}
				var notFound *fmstypes.ResourceNotFoundException
				if errors.As(err, &notFound) {
					continue
				}
				return nil, err
			}
			var typeList []string
			var arn *string
			if detail.ResourceSet != nil {
				typeList = detail.ResourceSet.ResourceTypeList
			}
			arn = detail.ResourceSetArn
			mqlSet, err := CreateResource(a.MqlRuntime, "aws.fms.resourceSet",
				map[string]*llx.RawData{
					"arn":              llx.StringDataPtr(arn),
					"id":               llx.StringDataPtr(summary.Id),
					"name":             llx.StringDataPtr(summary.Name),
					"description":      llx.StringDataPtr(summary.Description),
					"resourceTypeList": llx.ArrayData(llx.TArr2Raw(typeList), types.String),
					"status":           llx.StringData(string(summary.ResourceSetStatus)),
					"lastUpdateTime":   llx.TimeDataPtr(summary.LastUpdateTime),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSet)
		}
		if page.NextToken == nil {
			break
		}
		nextToken = page.NextToken
	}
	return res, nil
}

func (a *mqlAwsFmsResourceSet) id() (string, error) {
	// __id is keyed by the resource-set id (not arn) so cache lookups from
	// both `aws.fms.resourceSets()` and `aws.fms.policy.resourceSets()` land
	// on the same entry.
	return "aws.fms.resourceSet/" + a.Id.Data, a.Id.Error
}

// initAwsFmsResourceSet fetches a single resource set by id. Used when a
// caller materializes a resource set by id (e.g. through a policy's
// resourceSets() accessor) without having listed `aws.fms.resourceSets()`
// first. When the list has already populated the cache, NewResource hits
// the cache and skips this fetch.
func initAwsFmsResourceSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	idArg, ok := args["id"]
	if !ok || idArg == nil {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Fms(fmsRegion)
	resp, err := svc.GetResourceSet(context.Background(), &fms.GetResourceSetInput{Identifier: &id})
	if err != nil {
		if isFmsNotAdminError(err) {
			return args, nil, nil
		}
		var notFound *fmstypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return args, nil, nil
		}
		return nil, nil, classifyAwsError(fmt.Errorf("fetching aws.fms.resourceSet with id %q: %w", id, err), "fms:GetResourceSet")
	}
	var (
		name             *string
		description      *string
		resourceTypeList []string
		status           string
		lastUpdateTime   *time.Time
	)
	if resp.ResourceSet != nil {
		name = resp.ResourceSet.Name
		description = resp.ResourceSet.Description
		resourceTypeList = resp.ResourceSet.ResourceTypeList
		status = string(resp.ResourceSet.ResourceSetStatus)
		lastUpdateTime = resp.ResourceSet.LastUpdateTime
	}
	res, err := CreateResource(runtime, "aws.fms.resourceSet",
		map[string]*llx.RawData{
			"arn":              llx.StringDataPtr(resp.ResourceSetArn),
			"id":               llx.StringData(id),
			"name":             llx.StringDataPtr(name),
			"description":      llx.StringDataPtr(description),
			"resourceTypeList": llx.ArrayData(llx.TArr2Raw(resourceTypeList), types.String),
			"status":           llx.StringData(status),
			"lastUpdateTime":   llx.TimeDataPtr(lastUpdateTime),
		})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// resourceSets resolves the policy's ResourceSetIds into typed
// aws.fms.resourceSet records. When `aws.fms.resourceSets()` has already
// been called, this hits the runtime cache and avoids any extra API
// traffic; otherwise it falls through to initAwsFmsResourceSet which
// fetches the set on demand.
func (a *mqlAwsFmsPolicy) resourceSets() ([]any, error) {
	if a.ResourceSetIds.Error != nil {
		return nil, a.ResourceSetIds.Error
	}
	ids := a.ResourceSetIds.Data
	out := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(a.MqlRuntime, "aws.fms.resourceSet",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func intPtr32(v int32) *int32 {
	return &v
}
