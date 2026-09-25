// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsIdentitycenter) id() (string, error) {
	return "aws.identitycenter", nil
}

func (a *mqlAwsIdentitycenter) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
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

func (a *mqlAwsIdentitycenter) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	f := func() (jobpool.JobResult, error) {
		// Identity Center is a global service accessed through a regional endpoint.
		// Pass empty string to use the default region.
		svc := conn.SsoAdmin("")
		ctx := context.Background()
		res := []any{}

		paginator := ssoadmin.NewListInstancesPaginator(svc, &ssoadmin.ListInstancesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, classifyAwsError(err, "sso:ListInstances")
			}

			for _, instance := range page.Instances {
				regions := make([]any, 0, len(instance.Regions))
				for _, r := range instance.Regions {
					regions = append(regions, map[string]any{
						"regionName":      convert.ToValue(r.RegionName),
						"status":          string(r.Status),
						"isPrimaryRegion": r.IsPrimaryRegion,
					})
				}

				mqlInstance, err := CreateResource(a.MqlRuntime, "aws.identitycenter.instance",
					map[string]*llx.RawData{
						"__id":            llx.StringDataPtr(instance.InstanceArn),
						"arn":             llx.StringDataPtr(instance.InstanceArn),
						"name":            llx.StringDataPtr(instance.Name),
						"identityStoreId": llx.StringDataPtr(instance.IdentityStoreId),
						"status":          llx.StringData(string(instance.Status)),
						"statusReason":    llx.StringDataPtr(instance.StatusReason),
						"createdAt":       llx.TimeDataPtr(instance.CreatedDate),
						"ownerAccountId":  llx.StringDataPtr(instance.OwnerAccountId),
						"primaryRegion":   llx.StringDataPtr(instance.PrimaryRegion),
						"regions":         llx.ArrayData(regions, types.Dict),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}
		}
		return jobpool.JobResult(res), nil
	}
	tasks = append(tasks, jobpool.NewJob(f))
	return tasks
}

func (a *mqlAwsIdentitycenterInstance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIdentitycenterInstance) permissionSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.Arn.Data
	res := []any{}

	paginator := ssoadmin.NewListPermissionSetsPaginator(svc, &ssoadmin.ListPermissionSetsInput{
		InstanceArn: &instanceArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, psArn := range page.PermissionSets {
			mqlPs, err := CreateResource(a.MqlRuntime, "aws.identitycenter.permissionSet",
				map[string]*llx.RawData{
					"__id": llx.StringData(psArn),
					"arn":  llx.StringData(psArn),
				})
			if err != nil {
				return nil, err
			}
			mqlPsRes := mqlPs.(*mqlAwsIdentitycenterPermissionSet)
			mqlPsRes.cacheInstanceArn = instanceArn
			res = append(res, mqlPs)
		}
	}
	return res, nil
}

type mqlAwsIdentitycenterPermissionSetInternal struct {
	cacheInstanceArn string
	fetched          atomic.Bool
	lock             sync.Mutex
	descResp         *ssoadmin.DescribePermissionSetOutput

	managedPoliciesOnce sync.Once
	managedPoliciesList []ssotypes.AttachedManagedPolicy
	managedPoliciesErr  error
}

func (a *mqlAwsIdentitycenterPermissionSet) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) fetchDetail() (*ssoadmin.DescribePermissionSetOutput, error) {
	if a.fetched.Load() {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched.Load() {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.cacheInstanceArn
	psArn := a.Arn.Data
	resp, err := svc.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      &instanceArn,
		PermissionSetArn: &psArn,
	})
	if err != nil {
		return nil, err
	}
	// Publish the value before the flag: a reader on the lock-free fast path
	// that observes fetched==true must never see a nil descResp, or the
	// accessors below nil-deref and kill the scan.
	a.descResp = resp
	a.fetched.Store(true)
	return resp, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) name() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.PermissionSet == nil {
		return "", nil
	}
	return convert.ToValue(resp.PermissionSet.Name), nil
}

func (a *mqlAwsIdentitycenterPermissionSet) description() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.PermissionSet == nil {
		return "", nil
	}
	return convert.ToValue(resp.PermissionSet.Description), nil
}

func (a *mqlAwsIdentitycenterPermissionSet) sessionDuration() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.PermissionSet == nil {
		return "", nil
	}
	return convert.ToValue(resp.PermissionSet.SessionDuration), nil
}

func (a *mqlAwsIdentitycenterPermissionSet) relayState() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.PermissionSet == nil {
		return "", nil
	}
	return convert.ToValue(resp.PermissionSet.RelayState), nil
}

func (a *mqlAwsIdentitycenterPermissionSet) createdAt() (*time.Time, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.PermissionSet == nil {
		return nil, nil
	}
	return resp.PermissionSet.CreatedDate, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) inlinePolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.cacheInstanceArn
	psArn := a.Arn.Data
	resp, err := svc.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{
		InstanceArn:      &instanceArn,
		PermissionSetArn: &psArn,
	})
	if err != nil {
		return "", err
	}
	if resp.InlinePolicy == nil {
		return "", nil
	}
	return *resp.InlinePolicy, nil
}

// listManagedPolicies walks the AWS managed policies attached to the permission
// set once and hands the same list to both the deprecated dict field and the
// policy references, rather than paginating the same API twice.
func (a *mqlAwsIdentitycenterPermissionSet) listManagedPolicies() ([]ssotypes.AttachedManagedPolicy, error) {
	a.managedPoliciesOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.SsoAdmin("")
		ctx := context.Background()

		instanceArn := a.cacheInstanceArn
		psArn := a.Arn.Data

		paginator := ssoadmin.NewListManagedPoliciesInPermissionSetPaginator(svc, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn:      &instanceArn,
			PermissionSetArn: &psArn,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				a.managedPoliciesErr = err
				return
			}
			a.managedPoliciesList = append(a.managedPoliciesList, page.AttachedManagedPolicies...)
		}
	})
	return a.managedPoliciesList, a.managedPoliciesErr
}

func (a *mqlAwsIdentitycenterPermissionSet) managedPolicies() ([]any, error) {
	policies, err := a.listManagedPolicies()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, mp := range policies {
		res = append(res, map[string]any{
			"arn":  convert.ToValue(mp.Arn),
			"name": convert.ToValue(mp.Name),
		})
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) awsManagedPolicies() ([]any, error) {
	policies, err := a.listManagedPolicies()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, mp := range policies {
		arnVal := convert.ToValue(mp.Arn)
		if arnVal == "" {
			continue
		}
		mqlPolicy, err := NewResource(a.MqlRuntime, "aws.iam.policy", map[string]*llx.RawData{
			"arn": llx.StringData(arnVal),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.cacheInstanceArn
	psArn := a.Arn.Data
	tags := make(map[string]any)
	paginator := ssoadmin.NewListTagsForResourcePaginator(svc, &ssoadmin.ListTagsForResourceInput{
		InstanceArn: &instanceArn,
		ResourceArn: &psArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for k, v := range ssoTagsToMap(page.Tags) {
			tags[k] = v
		}
	}
	return tags, nil
}

func (a *mqlAwsIdentitycenterInstance) accountAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	log.Debug().Msg("fetching account assignments requires iterating permission sets, accounts, and assignments (triple-nested pagination) — this may be slow for organizations with many permission sets")

	instanceArn := a.Arn.Data
	res := []any{}

	// Get all permission sets first
	psSets := []string{}
	psPaginator := ssoadmin.NewListPermissionSetsPaginator(svc, &ssoadmin.ListPermissionSetsInput{
		InstanceArn: &instanceArn,
	})
	for psPaginator.HasMorePages() {
		page, err := psPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		psSets = append(psSets, page.PermissionSets...)
	}

	// For each permission set, list accounts that have assignments
	for _, psArn := range psSets {
		accPaginator := ssoadmin.NewListAccountsForProvisionedPermissionSetPaginator(svc,
			&ssoadmin.ListAccountsForProvisionedPermissionSetInput{
				InstanceArn:      &instanceArn,
				PermissionSetArn: &psArn,
			})
		for accPaginator.HasMorePages() {
			accPage, err := accPaginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, accountId := range accPage.AccountIds {
				assignPaginator := ssoadmin.NewListAccountAssignmentsPaginator(svc,
					&ssoadmin.ListAccountAssignmentsInput{
						InstanceArn:      &instanceArn,
						AccountId:        &accountId,
						PermissionSetArn: &psArn,
					})
				for assignPaginator.HasMorePages() {
					assignPage, err := assignPaginator.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					for _, assignment := range assignPage.AccountAssignments {
						assignId := fmt.Sprintf("%s/%s/%s/%s",
							convert.ToValue(assignment.AccountId),
							convert.ToValue(assignment.PermissionSetArn),
							string(assignment.PrincipalType),
							convert.ToValue(assignment.PrincipalId))

						mqlAssignment, err := CreateResource(a.MqlRuntime, "aws.identitycenter.accountAssignment",
							map[string]*llx.RawData{
								"__id":          llx.StringData(assignId),
								"id":            llx.StringData(assignId),
								"accountId":     llx.StringDataPtr(assignment.AccountId),
								"principalType": llx.StringData(string(assignment.PrincipalType)),
								"principalId":   llx.StringDataPtr(assignment.PrincipalId),
							})
						if err != nil {
							return nil, err
						}
						cast := mqlAssignment.(*mqlAwsIdentitycenterAccountAssignment)
						cast.cacheInstanceArn = instanceArn
						cast.cachePermissionSetArn = convert.ToValue(assignment.PermissionSetArn)
						res = append(res, mqlAssignment)
					}
				}
			}
		}
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterAccountAssignment) id() (string, error) {
	return a.Id.Data, nil
}

func ssoTagsToMap(tags []ssotypes.Tag) map[string]any {
	return tagsToMap(tags, func(t ssotypes.Tag) *string { return t.Key }, func(t ssotypes.Tag) *string { return t.Value })
}

// Permission set customer managed policies
func (a *mqlAwsIdentitycenterPermissionSet) customerManagedPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.cacheInstanceArn
	psArn := a.Arn.Data
	res := []any{}

	paginator := ssoadmin.NewListCustomerManagedPolicyReferencesInPermissionSetPaginator(svc,
		&ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{
			InstanceArn:      &instanceArn,
			PermissionSetArn: &psArn,
		})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cmp := range page.CustomerManagedPolicyReferences {
			res = append(res, map[string]any{
				"name": convert.ToValue(cmp.Name),
				"path": convert.ToValue(cmp.Path),
			})
		}
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterPermissionSet) permissionsBoundary() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.cacheInstanceArn
	psArn := a.Arn.Data

	resp, err := svc.GetPermissionsBoundaryForPermissionSet(ctx, &ssoadmin.GetPermissionsBoundaryForPermissionSetInput{
		InstanceArn:      &instanceArn,
		PermissionSetArn: &psArn,
	})
	if err != nil {
		// No permissions boundary attached returns a ResourceNotFoundException
		var notFoundErr *ssotypes.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			return nil, nil
		}
		return nil, classifyAwsError(err, "sso:GetPermissionsBoundaryForPermissionSet")
	}
	if resp.PermissionsBoundary == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.PermissionsBoundary)
}

// Account assignment typed permissionSet reference
type mqlAwsIdentitycenterAccountAssignmentInternal struct {
	cacheInstanceArn      string
	cachePermissionSetArn string
}

func (a *mqlAwsIdentitycenterAccountAssignment) permissionSet() (*mqlAwsIdentitycenterPermissionSet, error) {
	if a.cachePermissionSetArn == "" {
		a.PermissionSet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlPs, err := NewResource(a.MqlRuntime, "aws.identitycenter.permissionSet",
		map[string]*llx.RawData{"arn": llx.StringData(a.cachePermissionSetArn)})
	if err != nil {
		return nil, err
	}
	cast := mqlPs.(*mqlAwsIdentitycenterPermissionSet)
	if cast.cacheInstanceArn == "" {
		cast.cacheInstanceArn = a.cacheInstanceArn
	}
	return cast, nil
}

// Identity Center groups
func (a *mqlAwsIdentitycenterInstance) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	idStoreId := a.IdentityStoreId.Data
	if idStoreId == "" {
		return nil, nil
	}

	svc := conn.IdentityStore("")
	ctx := context.Background()
	res := []any{}

	paginator := identitystore.NewListGroupsPaginator(svc, &identitystore.ListGroupsInput{
		IdentityStoreId: &idStoreId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "identitystore:ListGroups")
		}
		for _, group := range page.Groups {
			mqlGroup, err := CreateResource(a.MqlRuntime, "aws.identitycenter.group",
				map[string]*llx.RawData{
					"__id":        llx.StringData("identitycenter/group/" + convert.ToValue(group.GroupId)),
					"groupId":     llx.StringDataPtr(group.GroupId),
					"displayName": llx.StringDataPtr(group.DisplayName),
					"createdAt":   llx.TimeDataPtr(group.CreatedAt),
				})
			if err != nil {
				return nil, err
			}
			cast := mqlGroup.(*mqlAwsIdentitycenterGroup)
			// Eagerly set description from list response
			cast.Description = plugin.TValue[string]{Data: convert.ToValue(group.Description), State: plugin.StateIsSet}

			externalIds := []any{}
			for _, eid := range group.ExternalIds {
				externalIds = append(externalIds, map[string]any{
					"issuer": convert.ToValue(eid.Issuer),
					"id":     convert.ToValue(eid.Id),
				})
			}
			cast.ExternalIds = plugin.TValue[[]any]{Data: externalIds, State: plugin.StateIsSet}

			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterGroup) id() (string, error) {
	return a.__id, nil
}

// description and externalIds are eagerly populated
func (a *mqlAwsIdentitycenterGroup) description() (string, error) { return "", nil }
func (a *mqlAwsIdentitycenterGroup) externalIds() ([]any, error)  { return nil, nil }

// Identity Center users
func (a *mqlAwsIdentitycenterInstance) users() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	idStoreId := a.IdentityStoreId.Data
	if idStoreId == "" {
		return nil, nil
	}

	svc := conn.IdentityStore("")
	ctx := context.Background()
	res := []any{}

	paginator := identitystore.NewListUsersPaginator(svc, &identitystore.ListUsersInput{
		IdentityStoreId: &idStoreId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "identitystore:ListUsers")
		}
		for _, user := range page.Users {
			mqlUser, err := CreateResource(a.MqlRuntime, "aws.identitycenter.user",
				map[string]*llx.RawData{
					"__id":        llx.StringData("identitycenter/user/" + convert.ToValue(user.UserId)),
					"userId":      llx.StringDataPtr(user.UserId),
					"userName":    llx.StringDataPtr(user.UserName),
					"displayName": llx.StringDataPtr(user.DisplayName),
					"createdAt":   llx.TimeDataPtr(user.CreatedAt),
				})
			if err != nil {
				return nil, err
			}
			cast := mqlUser.(*mqlAwsIdentitycenterUser)

			emails := []any{}
			for _, email := range user.Emails {
				emails = append(emails, map[string]any{
					"value":   convert.ToValue(email.Value),
					"type":    convert.ToValue(email.Type),
					"primary": email.Primary,
				})
			}
			cast.Emails = plugin.TValue[[]any]{Data: emails, State: plugin.StateIsSet}

			externalIds := []any{}
			for _, eid := range user.ExternalIds {
				externalIds = append(externalIds, map[string]any{
					"issuer": convert.ToValue(eid.Issuer),
					"id":     convert.ToValue(eid.Id),
				})
			}
			cast.ExternalIds = plugin.TValue[[]any]{Data: externalIds, State: plugin.StateIsSet}

			res = append(res, mqlUser)
		}
	}
	return res, nil
}

func (a *mqlAwsIdentitycenterUser) id() (string, error) {
	return a.__id, nil
}

// emails and externalIds are eagerly populated
func (a *mqlAwsIdentitycenterUser) emails() ([]any, error)      { return nil, nil }
func (a *mqlAwsIdentitycenterUser) externalIds() ([]any, error) { return nil, nil }

// Identity Center applications (Identity Center–managed and customer-managed)
func (a *mqlAwsIdentitycenterInstance) applications() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.SsoAdmin("")
	ctx := context.Background()

	instanceArn := a.Arn.Data
	res := []any{}

	paginator := ssoadmin.NewListApplicationsPaginator(svc, &ssoadmin.ListApplicationsInput{
		InstanceArn: &instanceArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "sso:ListApplications")
		}
		for _, app := range page.Applications {
			portalVisibility := ""
			signInOrigin := ""
			applicationUrl := ""
			if app.PortalOptions != nil {
				portalVisibility = string(app.PortalOptions.Visibility)
				if app.PortalOptions.SignInOptions != nil {
					signInOrigin = string(app.PortalOptions.SignInOptions.Origin)
					applicationUrl = convert.ToValue(app.PortalOptions.SignInOptions.ApplicationUrl)
				}
			}

			mqlApp, err := CreateResource(a.MqlRuntime, "aws.identitycenter.application",
				map[string]*llx.RawData{
					"__id":                   llx.StringDataPtr(app.ApplicationArn),
					"arn":                    llx.StringDataPtr(app.ApplicationArn),
					"name":                   llx.StringDataPtr(app.Name),
					"description":            llx.StringDataPtr(app.Description),
					"status":                 llx.StringData(string(app.Status)),
					"identityStoreArn":       llx.StringDataPtr(app.IdentityStoreArn),
					"applicationProviderArn": llx.StringDataPtr(app.ApplicationProviderArn),
					"applicationAccount":     llx.StringDataPtr(app.ApplicationAccount),
					"createdFrom":            llx.StringDataPtr(app.CreatedFrom),
					"createdDate":            llx.TimeDataPtr(app.CreatedDate),
					"portalVisibility":       llx.StringData(portalVisibility),
					"signInOrigin":           llx.StringData(signInOrigin),
					"applicationUrl":         llx.StringData(applicationUrl),
				})
			if err != nil {
				return nil, err
			}
			cast := mqlApp.(*mqlAwsIdentitycenterApplication)
			cast.cacheInstance = a
			res = append(res, mqlApp)
		}
	}
	return res, nil
}

type mqlAwsIdentitycenterApplicationInternal struct {
	cacheInstance *mqlAwsIdentitycenterInstance
}

func (a *mqlAwsIdentitycenterApplication) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIdentitycenterApplication) instance() (*mqlAwsIdentitycenterInstance, error) {
	if a.cacheInstance != nil {
		return a.cacheInstance, nil
	}
	a.Instance.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}
