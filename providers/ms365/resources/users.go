// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-beta-sdk-go/auditlogs"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

var userSelectFields = []string{
	"id", "accountEnabled", "city", "companyName", "country", "createdDateTime",
	"department", "displayName", "employeeId", "givenName", "jobTitle", "mail",
	"mobilePhone", "otherMails", "officeLocation", "postalCode", "state", "identities",
	"streetAddress", "surname", "userPrincipalName", "userType", "creationType",
	"assignedLicenses", "employeeType", "employeeHireDate",
	"lastPasswordChangeDateTime", "onPremisesSyncEnabled", "onPremisesLastSyncDateTime",
	"onPremisesDomainName", "onPremisesSamAccountName", "preferredLanguage",
	"usageLocation", "externalUserState", "passwordPolicies",
	// also fetched in bulk so job()/contact() resolve from the list response
	// instead of an N+1 per-user Get
	"businessPhones", "faxNumber", "mailNickname",
}

func (a *mqlMicrosoft) users() (*mqlMicrosoftUsers, error) {
	resource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft.users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftUsers), nil
}

func initMicrosoftUsers(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args["__id"] = newListResourceIdFromArguments("microsoft.users", args)
	resource, err := runtime.CreateResource(runtime, "microsoft.users", args)
	if err != nil {
		return args, nil, err
	}

	return args, resource.(*mqlMicrosoftUsers), nil
}

// list fetches users from Entra ID and allows the user provide a filter to retrieve
// a subset of users
//
// Permissions: User.Read.All, Directory.Read.All
// see https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
func (a *mqlMicrosoftUsers) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	// Index of users are stored inside the top level resource `microsoft`, just like
	// MFA response. Here we create or get the resource to access those internals
	mainResource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	microsoft := mainResource.(*mqlMicrosoft)

	// fetch user data
	ctx := context.Background()
	top := int32(999)
	opts := &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: userSelectFields,
			Top:    &top,
		},
	}

	if a.Search.State == plugin.StateIsSet || a.Filter.State == plugin.StateIsSet {
		// search and filter requires this header
		headers := abstractions.NewRequestHeaders()
		headers.Add("ConsistencyLevel", "eventual")
		opts.Headers = headers

		if a.Search.State == plugin.StateIsSet {
			log.Debug().
				Str("search", a.Search.Data).
				Msg("microsoft.users.list.search set")
			search, err := parseSearch(a.Search.Data)
			if err != nil {
				return nil, err
			}
			opts.QueryParameters.Search = &search
		}
		if a.Filter.State == plugin.StateIsSet {
			log.Debug().
				Str("filter", a.Filter.Data).
				Msg("microsoft.users.list.filter set")
			opts.QueryParameters.Filter = &a.Filter.Data
			count := true
			opts.QueryParameters.Count = &count
		}
	}

	resp, err := graphClient.Users().Get(ctx, opts)
	if err != nil {
		return nil, transformError(err)
	}
	users, err := iterate[*models.User](ctx,
		resp,
		graphClient.GetAdapter(),
		users.CreateDeltaGetResponseFromDiscriminatorValue,
	)
	if err != nil {
		return nil, transformError(err)
	}

	// construct the result
	res := []any{}
	for _, u := range users {
		graphUser, err := newMqlMicrosoftUser(a.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		// index users by id and principal name
		microsoft.indexUser(graphUser)
		res = append(res, graphUser)
	}

	return res, nil
}

// count returns the total number of users in the tenant via the Graph
// $count endpoint, avoiding a full user-list fetch (which is prohibitively
// slow on large tenants).
func (a *mqlMicrosoftUsers) count() (int64, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return 0, err
	}

	opts := &users.CountRequestBuilderGetRequestConfiguration{Headers: abstractions.NewRequestHeaders()}
	opts.Headers.Add("ConsistencyLevel", "eventual")
	count, err := graphClient.Users().Count().Get(context.Background(), opts)
	if err != nil {
		return 0, transformError(err)
	}
	if count == nil {
		// This should never happen, but we better check
		return 0, errors.New("unable to count users, counter parameter API returned nil")
	}

	return int64(*count), nil
}

func initMicrosoftUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the user if we have been supplied by id, displayName or userPrincipalName
	if len(args) > 1 {
		return args, nil, nil
	}

	rawId, okId := args["id"]
	rawDisplayName, okDisplayName := args["displayName"]
	rawPrincipalName, okPrincipalName := args["userPrincipalName"]

	if !okId && !okDisplayName && !okPrincipalName {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	// Fast path: look up directly by id. Skips the redundant filter+get
	// round-trip we'd otherwise pay for every microsoft.user(id: "...")
	// reference (most callers — owners, members, etc.).
	if okId {
		user, err := graphClient.Users().ByUserId(rawId.Value.(string)).Get(ctx, &users.UserItemRequestBuilderGetRequestConfiguration{
			QueryParameters: &users.UserItemRequestBuilderGetQueryParameters{
				Select: userSelectFields,
			},
		})
		if err != nil {
			return nil, nil, transformError(err)
		}
		mqlMsApp, err := newMqlMicrosoftUser(runtime, user)
		if err != nil {
			return nil, nil, err
		}
		return nil, mqlMsApp, nil
	}

	var filter string
	if okPrincipalName {
		filter = odataEqFilter("userPrincipalName", rawPrincipalName.Value.(string))
	} else if okDisplayName {
		filter = odataEqFilter("displayName", rawDisplayName.Value.(string))
	}

	resp, err := graphClient.Users().Get(ctx, &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Filter: &filter,
			Select: userSelectFields,
		},
	})
	if err != nil {
		return nil, nil, transformError(err)
	}

	val := resp.GetValue()
	if len(val) == 0 {
		return nil, nil, errors.New("user not found")
	}
	// displayName is not unique. Taking the first match would report one
	// user's data for a query that named another.
	if len(val) > 1 {
		return nil, nil, fmt.Errorf("%d users match %s, look the user up by id or userPrincipalName instead", len(val), filter)
	}

	// Reuse the filter response directly — it already carries every
	// userSelectFields field, so a second Get by id would return the
	// same data.
	mqlMsApp, err := newMqlMicrosoftUser(runtime, val[0])
	if err != nil {
		return nil, nil, err
	}

	// index the user so per-user batched fields can resolve it
	if microsoft, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{}); err == nil {
		microsoft.(*mqlMicrosoft).indexUser(mqlMsApp)
	}

	return nil, mqlMsApp, nil
}

// microsoftParent returns the singleton microsoft resource, which owns the
// shared user index and the per-user batched-field caches.
func (a *mqlMicrosoftUser) microsoftParent() (*mqlMicrosoft, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoft), nil
}

// odataEqFilter builds an OData `field eq 'value'` filter. A single quote
// inside an OData string literal is escaped by doubling it, so a value like
// O'Brien neither breaks the request nor changes the filter.
func odataEqFilter(field, value string) string {
	return fmt.Sprintf("%s eq '%s'", field, strings.ReplaceAll(value, "'", "''"))
}

// userAssignedLicenseID is the cache key for a microsoft.user.assignedLicense.
//
// The SKU id alone does not identify the assignment. A license assignment only
// exists in the context of one user, and disabledPlans varies per user for the
// same SKU, so keying on the SKU makes every user holding it share one cache
// entry. CreateResource is first-wins, so the first user's disabledPlans would
// then be reported for everyone else on that SKU. The key carries both.
func userAssignedLicenseID(userID, skuID string) string {
	return userID + "/" + skuID
}

func newMqlMicrosoftUser(runtime *plugin.Runtime, u models.Userable) (*mqlMicrosoftUser, error) {
	identities := []any{}
	uid := convert.ToValue(u.GetId())
	for idx, userId := range u.GetIdentities() {
		id := fmt.Sprintf("%s-%d", uid, idx)
		identity, err := CreateResource(runtime, "microsoft.user.identity", map[string]*llx.RawData{
			"signInType":       llx.StringDataPtr(userId.GetSignInType()),
			"issuer":           llx.StringDataPtr(userId.GetIssuer()),
			"issuerAssignedId": llx.StringDataPtr(userId.GetIssuerAssignedId()),
			"__id":             llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}

	mqlAssignedLicensesList := []any{}

	if u.GetAssignedLicenses() != nil {
		for _, license := range u.GetAssignedLicenses() {
			if license == nil || license.GetSkuId() == nil {
				continue
			}
			skuId := license.GetSkuId().String()

			var disabledPlanStrings []string
			if license.GetDisabledPlans() != nil {
				for _, planUUID := range license.GetDisabledPlans() {
					disabledPlanStrings = append(disabledPlanStrings, planUUID.String())
				}
			}

			mqlAssignedLicenses, err := CreateResource(runtime, "microsoft.user.assignedLicense",
				map[string]*llx.RawData{
					"__id":          llx.StringData(userAssignedLicenseID(uid, skuId)),
					"disabledPlans": llx.ArrayData(convert.SliceAnyToInterface(disabledPlanStrings), types.String),
					"skuId":         llx.StringData(skuId),
				})
			if err != nil {
				return nil, err
			}
			mqlAssignedLicensesList = append(mqlAssignedLicensesList, mqlAssignedLicenses)
		}
	}

	// Build job/contact from the already-fetched user so the computed
	// job()/contact() accessors resolve from the bulk list response instead of
	// firing an N+1 per-user Get.
	jobDict, contactDict := buildUserJobContact(u)

	graphUser, err := CreateResource(runtime, "microsoft.user",
		map[string]*llx.RawData{
			"__id":                       llx.StringDataPtr(u.GetId()),
			"id":                         llx.StringDataPtr(u.GetId()),
			"accountEnabled":             llx.BoolDataPtr(u.GetAccountEnabled()),
			"city":                       llx.StringDataPtr(u.GetCity()), // deprecated
			"createdDateTime":            llx.TimeDataPtr(u.GetCreatedDateTime()),
			"displayName":                llx.StringDataPtr(u.GetDisplayName()),
			"givenName":                  llx.StringDataPtr(u.GetGivenName()),
			"surname":                    llx.StringDataPtr(u.GetSurname()),
			"userPrincipalName":          llx.StringDataPtr(u.GetUserPrincipalName()),
			"userType":                   llx.StringDataPtr(u.GetUserType()),
			"creationType":               llx.StringDataPtr(u.GetCreationType()),
			"identities":                 llx.ArrayData(identities, types.ResourceLike),
			"assignedLicenses":           llx.ArrayData(mqlAssignedLicensesList, types.ResourceLike),
			"employeeType":               llx.StringDataPtr(u.GetEmployeeType()),
			"employeeHireDate":           llx.TimeDataPtr(u.GetEmployeeHireDate()),
			"job":                        llx.DictData(jobDict),
			"contact":                    llx.DictData(contactDict),
			"lastPasswordChangeDateTime": llx.TimeDataPtr(u.GetLastPasswordChangeDateTime()),
			"onPremisesSyncEnabled":      llx.BoolDataPtr(u.GetOnPremisesSyncEnabled()),
			"onPremisesLastSyncDateTime": llx.TimeDataPtr(u.GetOnPremisesLastSyncDateTime()),
			"onPremisesDomainName":       llx.StringDataPtr(u.GetOnPremisesDomainName()),
			"onPremisesSamAccountName":   llx.StringDataPtr(u.GetOnPremisesSamAccountName()),
			"preferredLanguage":          llx.StringDataPtr(u.GetPreferredLanguage()),
			"usageLocation":              llx.StringDataPtr(u.GetUsageLocation()),
			"externalUserState":          llx.StringDataPtr(u.GetExternalUserState()),
			"passwordPolicies":           llx.StringDataPtr(u.GetPasswordPolicies()),
		})
	if err != nil {
		return nil, err
	}
	return graphUser.(*mqlMicrosoftUser), nil
}

// https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
var userJobContactFields = []string{
	"jobTitle", "companyName", "department", "employeeId", "employeeType", "employeeHireDate",
	"officeLocation", "streetAddress", "city", "state", "postalCode", "country", "businessPhones", "mobilePhone", "mail", "otherMails", "faxNumber", "mailNickname",
}

func (a *mqlMicrosoftUser) mfaEnabled() (bool, error) {
	mql, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return false, err
	}

	resp := mql.(*mqlMicrosoft).loadMfaResp()
	if resp.err != nil {
		a.MfaEnabled.Error = resp.err
		a.MfaEnabled.State = plugin.StateIsSet
		return false, resp.err
	}

	a.MfaEnabled.Data = resp.mfaMap[a.Id.Data]
	a.MfaEnabled.State = plugin.StateIsSet
	return a.MfaEnabled.Data, nil
}

// buildUserJobContact builds the job and contact dicts from an already-fetched
// user. Used during bulk list construction so job()/contact() resolve from the
// list response, and by the populateJobContactData fallback for the by-id path.
func buildUserJobContact(u models.Userable) (any, any) {
	jobDesc, _ := convert.JsonToDict(userJob{
		JobTitle:    u.GetJobTitle(),
		CompanyName: u.GetCompanyName(),
		Department:  u.GetDepartment(),
		EmployeeId:  u.GetEmployeeId(),
		// EmployeeType:     u.GetEmployeeType(),
		// EmployeeHireDate: u.GetEmployeeHireDate(),
		OfficeLocation: u.GetOfficeLocation(),
	})
	contactDesc, _ := convert.JsonToDict(userContact{
		StreetAddress:  u.GetStreetAddress(),
		City:           u.GetCity(),
		State:          u.GetState(),
		PostalCode:     u.GetPostalCode(),
		Country:        u.GetCountry(),
		BusinessPhones: u.GetBusinessPhones(),
		MobilePhone:    u.GetMobilePhone(),
		Email:          u.GetMail(),
		OtherMails:     u.GetOtherMails(),
		FaxNumber:      u.GetFaxNumber(),
		MailNickname:   u.GetMailNickname(),
	})
	return jobDesc, contactDesc
}

func (a *mqlMicrosoftUser) populateJobContactData() error {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return err
	}

	userID := a.Id.Data
	ctx := context.Background()
	userData, err := graphClient.Users().ByUserId(userID).Get(ctx, &users.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UserItemRequestBuilderGetQueryParameters{
			Select: userJobContactFields,
		},
	})
	if err != nil {
		return transformError(err)
	}

	jobDesc, contactDesc := buildUserJobContact(userData)
	a.Job = plugin.TValue[any]{Data: jobDesc, State: plugin.StateIsSet}
	a.Contact = plugin.TValue[any]{Data: contactDesc, State: plugin.StateIsSet}

	return nil
}

func (a *mqlMicrosoftUser) auditlog() (*mqlMicrosoftUserAuditlog, error) {
	res, err := CreateResource(a.MqlRuntime, "microsoft.user.auditlog", map[string]*llx.RawData{
		"__id":   llx.StringData(a.Id.Data),
		"userId": llx.StringData(a.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUserAuditlog), nil
}

func (a *mqlMicrosoftUserAuditlog) signins() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.auditlogBatches.signins.resolve(a.UserId.Data, ms.indexedUserIDs(), ms.loadUserSignins)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return []any{}, nil
	}
	return v.([]any), nil
}

// microsoftParent returns the singleton microsoft resource, which owns the
// per-user audit-log batched-field caches.
func (a *mqlMicrosoftUserAuditlog) microsoftParent() (*mqlMicrosoft, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoft), nil
}

// batchUserSignins fetches sign-ins for the given users in one batched Graph
// (beta) request. filterFor builds the per-user $filter and top caps the page
// size. The result maps a user id to its []any of sign-in resources.
func (m *mqlMicrosoft) batchUserSignins(ids []string, top int32, filterFor func(userID string) string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	orderBy := "createdDateTime desc"
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		filter := filterFor(id)
		config := &auditlogs.SignInsRequestBuilderGetRequestConfiguration{
			QueryParameters: &auditlogs.SignInsRequestBuilderGetQueryParameters{
				Top:     &top,
				Filter:  &filter,
				Orderby: []string{orderBy},
			},
		}
		reqInfo, err := betaClient.AuditLogs().SignIns().ToGetRequestInformation(ctx, config)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*betamodels.SignInCollectionResponse](ctx, betaClient.GetAdapter(), reqs, betamodels.CreateSignInCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, coll := range res.results {
		signins := []any{}
		var itemErr error
		for _, s := range coll.GetValue() {
			signIn, err := newMqlMicrosoftSignIn(m.MqlRuntime, s)
			if err != nil {
				itemErr = err
				break
			}
			signins = append(signins, signIn)
		}
		if itemErr != nil {
			res.errs[id] = itemErr
			continue
		}
		data[id] = signins
	}
	return data, res.errs, nil
}

// loadUserSignins fetches the recent interactive sign-ins of the given users.
func (m *mqlMicrosoft) loadUserSignins(ids []string) (map[string]any, map[string]error, error) {
	now := time.Now()
	dayAgo := now.AddDate(0, 0, -1)
	return m.batchUserSignins(ids, int32(50), func(userID string) string {
		return fmt.Sprintf(
			"createdDateTime ge %s and createdDateTime lt %s and (userId eq '%s' or contains(tolower(userDisplayName), '%s'))",
			dayAgo.Format(time.RFC3339), now.Format(time.RFC3339), userID, userID)
	})
}

func (a *mqlMicrosoftUserAuditlog) lastInteractiveSignIn() (*mqlMicrosoftUserSignin, error) {
	signIns := a.GetSignins()
	if signIns.Error != nil {
		return nil, signIns.Error
	}
	if len(signIns.Data) == 0 {
		a.LastInteractiveSignIn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	latest := signIns.Data[0].(*mqlMicrosoftUserSignin)
	return latest, nil
}

// Note: the audit log API by default excludes the non-interactive sign-ins. This is a workaround to fetch the last non-interactive sign-in.
// We could also grab those as part of the `sign-ins` query but then the amount of data would be much larger as non-interactive logins are much more frequent.
func (a *mqlMicrosoftUserAuditlog) lastNonInteractiveSignIn() (*mqlMicrosoftUserSignin, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.auditlogBatches.lastNonInteractiveSignIn.resolve(a.UserId.Data, ms.indexedUserIDs(), ms.loadUserLastNonInteractiveSignin)
	if err != nil {
		return nil, err
	}
	if v == nil {
		a.LastNonInteractiveSignIn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v.(*mqlMicrosoftUserSignin), nil
}

// loadUserLastNonInteractiveSignin fetches the most recent non-interactive
// sign-in of the given users. Users with no such sign-in are omitted so the
// accessor reports a null field.
func (m *mqlMicrosoft) loadUserLastNonInteractiveSignin(ids []string) (map[string]any, map[string]error, error) {
	now := time.Now()
	dayAgo := now.AddDate(0, 0, -1)
	data, errs, err := m.batchUserSignins(ids, int32(1), func(userID string) string {
		return fmt.Sprintf(
			"signInEventTypes/any(t: t ne 'interactiveUser') and createdDateTime ge %s and createdDateTime lt %s and (userId eq '%s' or contains(tolower(userDisplayName), '%s'))",
			dayAgo.Format(time.RFC3339), now.Format(time.RFC3339), userID, userID)
	})
	if err != nil {
		return nil, nil, err
	}
	out := make(map[string]any, len(data))
	for id, v := range data {
		signins := v.([]any)
		if len(signins) == 0 {
			continue
		}
		out[id] = signins[0]
	}
	return out, errs, nil
}

func newMqlMicrosoftSignIn(runtime *plugin.Runtime, signIn betamodels.SignInable) (*mqlMicrosoftUserSignin, error) {
	var conditionalAccessStatus *string
	if signIn.GetConditionalAccessStatus() != nil {
		s := signIn.GetConditionalAccessStatus().String()
		conditionalAccessStatus = &s
	}
	var signInRiskDetail *string
	if signIn.GetRiskDetail() != nil {
		s := signIn.GetRiskDetail().String()
		signInRiskDetail = &s
	}
	var signInRiskState *string
	if signIn.GetRiskState() != nil {
		s := signIn.GetRiskState().String()
		signInRiskState = &s
	}
	var riskLevelAggregated *string
	if signIn.GetRiskLevelAggregated() != nil {
		s := signIn.GetRiskLevelAggregated().String()
		riskLevelAggregated = &s
	}
	var riskLevelDuringSignIn *string
	if signIn.GetRiskLevelDuringSignIn() != nil {
		s := signIn.GetRiskLevelDuringSignIn().String()
		riskLevelDuringSignIn = &s
	}
	riskEventTypes := []any{}
	for _, t := range signIn.GetRiskEventTypesV2() {
		riskEventTypes = append(riskEventTypes, t)
	}

	var statusErrorCode *int32
	var statusFailureReason *string
	if status := signIn.GetStatus(); status != nil {
		statusErrorCode = status.GetErrorCode()
		statusFailureReason = status.GetFailureReason()
	}

	var city, state, countryOrRegion *string
	if loc := signIn.GetLocation(); loc != nil {
		city = loc.GetCity()
		state = loc.GetState()
		countryOrRegion = loc.GetCountryOrRegion()
	}

	mqlSignIn, err := CreateResource(runtime, "microsoft.user.signin",
		map[string]*llx.RawData{
			"__id":                    llx.StringDataPtr(signIn.GetId()),
			"id":                      llx.StringDataPtr(signIn.GetId()),
			"createdDateTime":         llx.TimeDataPtr(signIn.GetCreatedDateTime()),
			"userId":                  llx.StringDataPtr(signIn.GetUserId()),
			"clientAppUsed":           llx.StringDataPtr(signIn.GetClientAppUsed()),
			"resourceDisplayName":     llx.StringDataPtr(signIn.GetResourceDisplayName()),
			"userDisplayName":         llx.StringDataPtr(signIn.GetUserDisplayName()),
			"appDisplayName":          llx.StringDataPtr(signIn.GetAppDisplayName()),
			"interactive":             llx.BoolDataPtr(signIn.GetIsInteractive()),
			"appId":                   llx.StringDataPtr(signIn.GetAppId()),
			"resourceId":              llx.StringDataPtr(signIn.GetResourceId()),
			"ipAddress":               llx.StringDataPtr(signIn.GetIpAddress()),
			"correlationId":           llx.StringDataPtr(signIn.GetCorrelationId()),
			"userAgent":               llx.StringDataPtr(signIn.GetUserAgent()),
			"conditionalAccessStatus": llx.StringDataPtr(conditionalAccessStatus),
			"riskDetail":              llx.StringDataPtr(signInRiskDetail),
			"riskState":               llx.StringDataPtr(signInRiskState),
			"riskLevelAggregated":     llx.StringDataPtr(riskLevelAggregated),
			"riskLevelDuringSignIn":   llx.StringDataPtr(riskLevelDuringSignIn),
			"riskEventTypes":          llx.ArrayData(riskEventTypes, types.String),
			"statusErrorCode":         llx.IntDataPtr(statusErrorCode),
			"statusFailureReason":     llx.StringDataPtr(statusFailureReason),
			"city":                    llx.StringDataPtr(city),
			"state":                   llx.StringDataPtr(state),
			"countryOrRegion":         llx.StringDataPtr(countryOrRegion),
		})
	if err != nil {
		return nil, err
	}

	return mqlSignIn.(*mqlMicrosoftUserSignin), nil
}

type userJob struct {
	CompanyName      *string    `json:"companyName"`
	JobTitle         *string    `json:"jobTitle"`
	Department       *string    `json:"department"`
	EmployeeId       *string    `json:"employeeId"`
	EmployeeType     *string    `json:"employeeType"`
	EmployeeHireDate *time.Time `json:"employeeHireDate"`
	OfficeLocation   *string    `json:"officeLocation"`
}

type userContact struct {
	StreetAddress  *string  `json:"streetAddress"`
	City           *string  `json:"city"`
	State          *string  `json:"state"`
	PostalCode     *string  `json:"postalCode"`
	Country        *string  `json:"country"`
	BusinessPhones []string `json:"BusinessPhones"`
	MobilePhone    *string  `json:"mobilePhone"`
	Email          *string  `json:"email"`
	OtherMails     []string `json:"otherMails"`
	FaxNumber      *string  `json:"faxNumber"`
	MailNickname   *string  `json:"mailNickname"`
}

func (a *mqlMicrosoftUser) job() (any, error) {
	return nil, a.populateJobContactData()
}

func (a *mqlMicrosoftUser) contact() (any, error) {
	return nil, a.populateJobContactData()
}

func (a *mqlMicrosoftUser) settings() (any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.userBatches.settings.resolve(a.Id.Data, ms.indexedUserIDs(), ms.loadUserSettings)
}

// loadUserSettings fetches the settings of the given users in one batched
// Graph request.
func (m *mqlMicrosoft) loadUserSettings(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		reqInfo, err := graphClient.Users().ByUserId(id).Settings().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*models.UserSettings](ctx, graphClient.GetAdapter(), reqs, models.CreateUserSettingsFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, s := range res.results {
		dict, err := convert.JsonToDict(newUserSettings(s))
		if err != nil {
			res.errs[id] = err
			continue
		}
		data[id] = dict
	}
	return data, res.errs, nil
}

// signInActivity returns the user's last interactive and non-interactive sign-in
// timestamps. The signInActivity property requires the AuditLog.Read.All permission,
// so it is fetched on demand rather than included in the bulk user select.
func (a *mqlMicrosoftUser) signInActivity() (any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	return ms.userBatches.signInActivity.resolve(a.Id.Data, ms.indexedUserIDs(), ms.loadUserSignInActivity)
}

// loadUserSignInActivity fetches the signInActivity of the given users in one
// batched Graph request.
func (m *mqlMicrosoft) loadUserSignInActivity(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	config := &users.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UserItemRequestBuilderGetQueryParameters{
			Select: []string{"signInActivity"},
		},
	}
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		reqInfo, err := graphClient.Users().ByUserId(id).ToGetRequestInformation(ctx, config)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*models.User](ctx, graphClient.GetAdapter(), reqs, models.CreateUserFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, u := range res.results {
		dict, err := convert.JsonToDict(newSignInActivity(u.GetSignInActivity()))
		if err != nil {
			res.errs[id] = err
			continue
		}
		data[id] = dict
	}
	return data, res.errs, nil
}

type authMethod struct {
	Id string `json:"id"`
}

type phoneMethod struct {
	authMethod
	Type           string  `json:"type"`
	PhoneNumber    *string `json:"phoneNumber"`
	SsmSignInState string  `json:"ssmSignInState"`
}

type fido2Method struct {
	authMethod
	Name                    *string  `json:"name"`
	AttestationLevel        string   `json:"attestationLevel"`
	Model                   *string  `json:"model"`
	AttestationCertificates []string `json:"attestationCertificates"`
}

type emailMethod struct {
	authMethod
	EmailAddress *string `json:"emailAddress"`
}

type windowsHelloMethod struct {
	authMethod
	Name        *string `json:"name"`
	DeviceId    *string `json:"deviceId"`
	KeyStrength string  `json:"keyStrength"`
}

type softwareMethod struct {
	authMethod
}

type passwordMethod struct {
	authMethod
}

type microsoftAuthenticatorMethod struct {
	authMethod
	Name            *string `json:"name"`
	PhoneAppVersion *string `json:"phoneAppVersion"`
	DeviceTag       *string `json:"deviceTag"`
}

type temporaryAccessPassMethod struct {
	authMethod
	IsUsable          *bool  `json:"isUsable"`
	IsUsableOnce      *bool  `json:"isUsableOnce"`
	LifetimeInMinutes *int32 `json:"lifetimeInMinutes"`
}

type userAuthentication struct {
	userID                     string
	methodCount                int
	PhoneMethods               []phoneMethod                  `json:"phoneMethods"`
	Fido2Methods               []fido2Method                  `json:"fido2Methods"`
	SoftwareMethods            []softwareMethod               `json:"softwareMethods"`
	MicrosoftAuthenticator     []microsoftAuthenticatorMethod `json:"microsoftAuthenticator"`
	PasswordMethods            []passwordMethod               `json:"passwordMethods"`
	TemporaryAccessPassMethods []temporaryAccessPassMethod    `json:"temporaryAccessPassMethods"`
	WindowsHelloMethods        []windowsHelloMethod           `json:"windowsHelloMethods"`
	EmailMethods               []emailMethod                  `json:"emailMethods"`
}

// authMethods needs the permission UserAuthenticationMethod.Read.All
func (a *mqlMicrosoftUser) authMethods() (*mqlMicrosoftUserAuthenticationMethods, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.userBatches.authMethods.resolve(a.Id.Data, ms.indexedUserIDs(), ms.loadUserAuthMethods)
	if err != nil {
		return nil, err
	}
	if v == nil {
		a.AuthMethods.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v.(*mqlMicrosoftUserAuthenticationMethods), nil
}

// loadUserAuthMethods fetches the authentication methods of the given users in
// one batched Graph request. A 403 on a user's call surfaces the missing
// UserAuthenticationMethod.Read.All permission for that user only.
func (m *mqlMicrosoft) loadUserAuthMethods(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		reqInfo, err := graphClient.Users().ByUserId(id).Authentication().Methods().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*models.AuthenticationMethodCollectionResponse](ctx, graphClient.GetAdapter(), reqs, models.CreateAuthenticationMethodCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, coll := range res.results {
		mqlAuth, err := newMqlMicrosoftUserAuthentication(m.MqlRuntime, buildUserAuthentication(id, coll.GetValue()))
		if err != nil {
			res.errs[id] = err
			continue
		}
		data[id] = mqlAuth
	}
	for id, code := range res.statuses {
		if code == 403 {
			res.errs[id] = errors.New("UserAuthenticationMethod.Read.All permission is required")
			// the error wins over any partially-deserialized result; keep the
			// data and errs maps disjoint so lookups stay consistent
			delete(data, id)
		}
	}
	return data, res.errs, nil
}

// buildUserAuthentication groups a user's authentication methods by type.
func buildUserAuthentication(userID string, methods []models.AuthenticationMethodable) userAuthentication {
	ua := userAuthentication{
		userID:      userID,
		methodCount: len(methods),
	}
	for i := range methods {
		entry := methods[i]
		switch x := entry.(type) {
		case *models.PhoneAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}

			m := phoneMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				PhoneNumber: x.GetPhoneNumber(),
			}

			if x.GetPhoneType() != nil {
				m.Type = x.GetPhoneType().String()
			}

			if x.GetSmsSignInState() != nil {
				m.SsmSignInState = x.GetSmsSignInState().String()
			}

			ua.PhoneMethods = append(ua.PhoneMethods, m)
		case *models.Fido2AuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := fido2Method{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				Name:                    x.GetDisplayName(),
				Model:                   x.GetModel(),
				AttestationCertificates: x.GetAttestationCertificates(),
			}
			if x.GetAttestationLevel() != nil {
				m.AttestationLevel = x.GetAttestationLevel().String()
			}
			ua.Fido2Methods = append(ua.Fido2Methods, m)
		case *models.SoftwareOathAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := softwareMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
			}

			ua.SoftwareMethods = append(ua.SoftwareMethods, m)
		case *models.MicrosoftAuthenticatorAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := microsoftAuthenticatorMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				Name:            x.GetDisplayName(),
				PhoneAppVersion: x.GetPhoneAppVersion(),
				DeviceTag:       x.GetDeviceTag(),
			}

			ua.MicrosoftAuthenticator = append(ua.MicrosoftAuthenticator, m)
		case *models.PasswordAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := passwordMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
			}

			ua.PasswordMethods = append(ua.PasswordMethods, m)
		case *models.TemporaryAccessPassAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := temporaryAccessPassMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				IsUsable:          x.GetIsUsable(),
				IsUsableOnce:      x.GetIsUsableOnce(),
				LifetimeInMinutes: x.GetLifetimeInMinutes(),
			}
			ua.TemporaryAccessPassMethods = append(ua.TemporaryAccessPassMethods, m)
		case *models.WindowsHelloForBusinessAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}
			m := windowsHelloMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				Name: x.GetDisplayName(),
			}
			if x.GetDevice() != nil {
				m.DeviceId = x.GetDevice().GetDeviceId()
			}

			if x.GetKeyStrength() != nil {
				m.KeyStrength = x.GetKeyStrength().String()
			}

			ua.WindowsHelloMethods = append(ua.WindowsHelloMethods, m)
		case *models.EmailAuthenticationMethod:
			if x.GetId() == nil {
				continue
			}

			m := emailMethod{
				authMethod: authMethod{
					Id: *x.GetId(),
				},
				EmailAddress: x.GetEmailAddress(),
			}
			ua.EmailMethods = append(ua.EmailMethods, m)
		default:

		}
	}

	return ua
}

func newMqlMicrosoftUserAuthentication(runtime *plugin.Runtime, u userAuthentication) (*mqlMicrosoftUserAuthenticationMethods, error) {
	if u.userID == "" {
		return nil, errors.New("user id is required")
	}
	phoneMethods, _ := convert.JsonToDictSlice(u.PhoneMethods)
	emailMethods, _ := convert.JsonToDictSlice(u.EmailMethods)
	fido2Methods, _ := convert.JsonToDictSlice(u.Fido2Methods)
	softwareMethods, _ := convert.JsonToDictSlice(u.SoftwareMethods)
	microsoftAuthenticator, _ := convert.JsonToDictSlice(u.MicrosoftAuthenticator)
	passwordMethods, _ := convert.JsonToDictSlice(u.PasswordMethods)
	temporaryAccessPassMethods, _ := convert.JsonToDictSlice(u.TemporaryAccessPassMethods)
	windowsHelloMethods, _ := convert.JsonToDictSlice(u.WindowsHelloMethods)

	graphUser, err := CreateResource(runtime, "microsoft.user.authenticationMethods",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(u.userID),
			"count":                      llx.IntData(u.methodCount),
			"phoneMethods":               llx.DictData(phoneMethods),
			"emailMethods":               llx.DictData(emailMethods),
			"fido2Methods":               llx.DictData(fido2Methods),
			"softwareMethods":            llx.DictData(softwareMethods),
			"microsoftAuthenticator":     llx.DictData(microsoftAuthenticator),
			"passwordMethods":            llx.DictData(passwordMethods),
			"temporaryAccessPassMethods": llx.DictData(temporaryAccessPassMethods),
			"windowsHelloMethods":        llx.DictData(windowsHelloMethods),
		})
	if err != nil {
		return nil, err
	}
	return graphUser.(*mqlMicrosoftUserAuthenticationMethods), nil
}

func (a *mqlMicrosoftUser) authenticationRequirements() (*mqlMicrosoftUserAuthenticationRequirements, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.userBatches.authRequires.resolve(a.Id.Data, ms.indexedUserIDs(), ms.loadUserAuthRequirements)
	if err != nil {
		return nil, err
	}
	if v == nil {
		a.AuthenticationRequirements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v.(*mqlMicrosoftUserAuthenticationRequirements), nil
}

// loadUserAuthRequirements fetches the per-user MFA state of the given users in
// one batched Graph (beta) request.
func (m *mqlMicrosoft) loadUserAuthRequirements(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	betaClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		reqInfo, err := betaClient.Users().ByUserId(id).Authentication().Requirements().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*betamodels.StrongAuthenticationRequirements](ctx, betaClient.GetAdapter(), reqs, betamodels.CreateStrongAuthenticationRequirementsFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, r := range res.results {
		var perUserMfaState string
		if r.GetPerUserMfaState() != nil {
			perUserMfaState = r.GetPerUserMfaState().String()
		}
		mqlAuthRequirements, err := CreateResource(m.MqlRuntime, ResourceMicrosoftUserAuthenticationRequirements,
			map[string]*llx.RawData{
				"__id":            llx.StringData(id),
				"perUserMfaState": llx.StringData(perUserMfaState),
			})
		if err != nil {
			res.errs[id] = err
			continue
		}
		data[id] = mqlAuthRequirements
	}
	return data, res.errs, nil
}

// Needs the permission AuditLog.Read.All
func (a *mqlMicrosoftUserAuthenticationMethods) registrationDetails() (*mqlMicrosoftUserAuthenticationMethodsUserRegistrationDetails, error) {
	userID := a.__id
	if userID == "" {
		return nil, errors.New("cannot fetch user registration details without a user ID")
	}

	// From the tenant-wide report, read once and indexed, rather than a Get per
	// user: this record used to cost 50 calls on a tenant whose whole
	// authMethods parent cost 4 batched ones.
	ms, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	byUser, err := ms.(*mqlMicrosoft).loadRegistrationDetails()
	if err != nil {
		return nil, err
	}

	details, ok := byUser[userID]
	if !ok {
		// A user with no registration record is a legitimate state -- the report
		// omits users who have never registered a method -- so report null
		// rather than the 404 the per-user Get returned.
		a.RegistrationDetails.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	return newMqlUserRegistrationDetails(a.MqlRuntime, details)
}

func newMqlUserRegistrationDetails(runtime *plugin.Runtime, details models.UserRegistrationDetailsable) (*mqlMicrosoftUserAuthenticationMethodsUserRegistrationDetails, error) {
	if details.GetId() == nil {
		return nil, errors.New("user registration details response is missing an ID")
	}

	var userPrefMethodStr, userTypeStr string
	if details.GetUserPreferredMethodForSecondaryAuthentication() != nil {
		userPrefMethodStr = details.GetUserPreferredMethodForSecondaryAuthentication().String()
	}
	if details.GetUserType() != nil {
		userTypeStr = details.GetUserType().String()
	}

	data := map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(details.GetId()),
		"id":                    llx.StringDataPtr(details.GetId()),
		"isAdmin":               llx.BoolDataPtr(details.GetIsAdmin()),
		"isMfaCapable":          llx.BoolDataPtr(details.GetIsMfaCapable()),
		"isMfaRegistered":       llx.BoolDataPtr(details.GetIsMfaRegistered()),
		"isPasswordlessCapable": llx.BoolDataPtr(details.GetIsPasswordlessCapable()),
		"isSsprCapable":         llx.BoolDataPtr(details.GetIsSsprCapable()),
		"isSsprEnabled":         llx.BoolDataPtr(details.GetIsSsprEnabled()),
		"isSsprRegistered":      llx.BoolDataPtr(details.GetIsSsprRegistered()),
		"isSystemPreferredAuthenticationMethodEnabled":  llx.BoolDataPtr(details.GetIsSystemPreferredAuthenticationMethodEnabled()),
		"lastUpdatedDateTime":                           llx.TimeDataPtr(details.GetLastUpdatedDateTime()),
		"methodsRegistered":                             llx.ArrayData(convert.SliceAnyToInterface(details.GetMethodsRegistered()), types.String),
		"systemPreferredAuthenticationMethods":          llx.ArrayData(convert.SliceAnyToInterface(details.GetSystemPreferredAuthenticationMethods()), types.String),
		"userDisplayName":                               llx.StringDataPtr(details.GetUserDisplayName()),
		"userPreferredMethodForSecondaryAuthentication": llx.StringData(userPrefMethodStr),
		"userPrincipalName":                             llx.StringDataPtr(details.GetUserPrincipalName()),
		"userType":                                      llx.StringData(userTypeStr),
	}

	resource, err := CreateResource(runtime, "microsoft.user.authenticationMethods.userRegistrationDetails", data)
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftUserAuthenticationMethodsUserRegistrationDetails), nil
}

func (a *mqlMicrosoftUser) licenseDetails() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.userBatches.licenseDetails.resolve(a.Id.Data, ms.indexedUserIDs(), ms.loadUserLicenseDetails)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return []any{}, nil
	}
	return v.([]any), nil
}

// loadUserLicenseDetails fetches the license details of the given users in one
// batched Graph request.
//
// Permissions: User.Read.All, Directory.Read.All
func (m *mqlMicrosoft) loadUserLicenseDetails(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		reqInfo, err := graphClient.Users().ByUserId(id).LicenseDetails().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: reqInfo})
	}
	res, err := batchGet[*models.LicenseDetailsCollectionResponse](ctx, graphClient.GetAdapter(), reqs, models.CreateLicenseDetailsCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(res.results))
	for id, coll := range res.results {
		details := []any{}
		var itemErr error
		for _, d := range coll.GetValue() {
			mqlDetail, err := newMqlMicrosoftUserLicenseDetail(m.MqlRuntime, id, d)
			if err != nil {
				itemErr = err
				break
			}
			details = append(details, mqlDetail)
		}
		if itemErr != nil {
			res.errs[id] = itemErr
			continue
		}
		data[id] = details
	}
	return data, res.errs, nil
}

// userLicenseDetailID is the cache key for a microsoft.user.licenseDetail.
//
// The Graph licenseDetail id is not unique per user: it is derived from the
// tenant and the SKU, so every user holding the same SKU gets the same id.
// CreateResource is first-wins, so keying on that id alone would report the
// first user's servicePlans for everyone else on that SKU. The key carries the
// user id as well, like userAssignedLicenseID.
func userLicenseDetailID(userID, licenseDetailID string) string {
	return userID + "/" + licenseDetailID
}

func newMqlMicrosoftUserLicenseDetail(runtime *plugin.Runtime, userID string, d models.LicenseDetailsable) (*mqlMicrosoftUserLicenseDetail, error) {
	if d.GetId() == nil {
		return nil, errors.New("license detail response is missing an ID")
	}
	detailKey := userLicenseDetailID(userID, *d.GetId())

	var skuId, skuPartNumber string
	if d.GetSkuId() != nil {
		skuId = d.GetSkuId().String()
	}
	if d.GetSkuPartNumber() != nil {
		skuPartNumber = *d.GetSkuPartNumber()
	}

	servicePlans := []any{}
	for i, sp := range d.GetServicePlans() {
		planId := fmt.Sprintf("%s-service-plans-%d", detailKey, i)

		servicePlan, err := CreateResource(runtime, "microsoft.user.licenseDetail.servicePlanInfo",
			map[string]*llx.RawData{
				"__id":               llx.StringData(planId),
				"appliesTo":          llx.StringDataPtr(sp.GetAppliesTo()),
				"provisioningStatus": llx.StringDataPtr(sp.GetProvisioningStatus()),
				"servicePlanId":      llx.StringDataPtr(newUuidString(sp.GetServicePlanId())),
				"servicePlanName":    llx.StringDataPtr(sp.GetServicePlanName()),
			})
		if err != nil {
			return nil, err
		}
		servicePlans = append(servicePlans, servicePlan)
	}

	data := map[string]*llx.RawData{
		"__id":          llx.StringData(detailKey),
		"id":            llx.StringDataPtr(d.GetId()),
		"skuId":         llx.StringData(skuId),
		"skuPartNumber": llx.StringData(skuPartNumber),
		"servicePlans":  llx.ArrayData(servicePlans, types.ResourceLike),
	}

	resource, err := CreateResource(runtime, "microsoft.user.licenseDetail", data)
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftUserLicenseDetail), nil
}
