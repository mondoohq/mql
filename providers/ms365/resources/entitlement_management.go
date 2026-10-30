// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	graphidentitygovernance "github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// entitlementManagementReadPermission is the Microsoft Graph application
// permission every entitlement management read in this file needs.
const entitlementManagementReadPermission = "EntitlementManagement.Read.All"

const entitlementManagementSettingsID = "microsoft.identityAndAccess/entitlementManagement/settings"

// entitlementManagementData memoizes the entitlement management listings for
// a scan. Catalogs, access packages and assignment policies reference each
// other, and resolving those references from the memoized lists keeps every
// accessor at the one list call per collection that the listing itself costs.
type entitlementManagementData struct {
	catalogsOnce sync.Once
	catalogs     []any
	catalogsByID map[string]*mqlMicrosoftIdentityAndAccessAccessPackageCatalog
	catalogsErr  error

	packagesOnce sync.Once
	packages     []any
	packagesByID map[string]*mqlMicrosoftIdentityAndAccessAccessPackage
	packagesErr  error

	policiesOnce sync.Once
	policies     []any
	policiesErr  error
}

type mqlMicrosoftIdentityAndAccessInternal struct {
	entitlementManagement entitlementManagementData
}

type mqlMicrosoftIdentityAndAccessAccessPackageInternal struct {
	cacheCatalogID string
}

type mqlMicrosoftIdentityAndAccessAccessPackageAssignmentPolicyInternal struct {
	cacheAccessPackageID string
}

// identityAndAccessSingleton returns the scan's microsoft.identityAndAccess
// resource, which holds the memoized entitlement management listings.
func identityAndAccessSingleton(runtime *plugin.Runtime) (*mqlMicrosoftIdentityAndAccess, error) {
	res, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccess, nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftIdentityAndAccess), nil
}

func (a *mqlMicrosoftIdentityAndAccess) entitlementManagementSettings() (*mqlMicrosoftIdentityAndAccessEntitlementManagementSettings, error) {
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessEntitlementManagementSettings, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftIdentityAndAccessEntitlementManagementSettings), nil
}

// initMicrosoftIdentityAndAccessEntitlementManagementSettings fetches the
// settings singleton, so the resource answers the same whether it is reached
// through microsoft.identityAndAccess or named on its own.
func initMicrosoftIdentityAndAccessEntitlementManagementSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	settings, err := graphClient.
		IdentityGovernance().
		EntitlementManagement().
		Settings().
		Get(context.Background(), nil)
	if err != nil {
		return nil, nil, classifyGraphError(err, entitlementManagementReadPermission)
	}
	return entitlementManagementSettingsArgs(settings), nil, nil
}

// entitlementManagementSettingsArgs maps the settings payload. A payload
// that leaves a value out reads as null rather than as the Kiota enum's zero
// value, which is "none" and would claim external users are never removed.
func entitlementManagementSettingsArgs(settings models.EntitlementManagementSettingsable) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                        llx.StringData(entitlementManagementSettingsID),
		"externalUserLifecycleAction": llx.NilData,
		"durationUntilExternalUserDeletedAfterBlocked": llx.NilData,
	}
	if settings == nil {
		return args
	}
	if action := settings.GetExternalUserLifecycleAction(); action != nil {
		args["externalUserLifecycleAction"] = llx.StringData(action.String())
	}
	args["durationUntilExternalUserDeletedAfterBlocked"] = llx.StringDataPtr(isoDurationPtr(settings.GetDurationUntilExternalUserDeletedAfterBlocked()))
	return args
}

// isoDurationPtr renders an ISO 8601 duration, keeping an absent one nil.
//
// Kiota's own String() is not used: it folds whole weeks out of the days, so
// the P14D Microsoft Graph returned reads back as P2W, it renders a zero
// duration as a bare "P", and it panics on a value it cannot normalize. This
// renders weeks as days, so a duration always reads in the days form the
// Entra admin center and Microsoft Graph use, and zero as PT0S.
func isoDurationPtr(d *serialization.ISODuration) *string {
	if d == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("P")
	if y := d.GetYears(); y != 0 {
		fmt.Fprintf(&b, "%dY", y)
	}
	if mo := isoDurationMonths(d); mo != 0 {
		fmt.Fprintf(&b, "%dM", mo)
	}
	if days := d.GetWeeks()*7 + d.GetDays(); days != 0 {
		fmt.Fprintf(&b, "%dD", days)
	}
	h, m, s, ms := d.GetHours(), d.GetMinutes(), d.GetSeconds(), d.GetMilliSeconds()
	if h != 0 || m != 0 || s != 0 || ms != 0 {
		b.WriteString("T")
		if h != 0 {
			fmt.Fprintf(&b, "%dH", h)
		}
		if m != 0 {
			fmt.Fprintf(&b, "%dM", m)
		}
		switch {
		case ms != 0:
			fmt.Fprintf(&b, "%d.%03dS", s, ms)
		case s != 0:
			fmt.Fprintf(&b, "%dS", s)
		}
	}
	out := b.String()
	if out == "P" {
		out = "PT0S"
	}
	return &out
}

// isoDurationMonthsPattern reads the years and months of Kiota's rendering of
// a duration.
var isoDurationMonthsPattern = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?`)

// isoDurationMonths returns the months component of a duration. Kiota keeps
// the months it parsed but has no getter for them, so they are read back from
// its own rendering, which carries 12 months or more over into years. The
// difference from GetYears restores those months. ToDuration refuses exactly
// the durations that carry months, so any other duration skips the rendering
// (and the panic Kiota raises on a value it cannot normalize).
func isoDurationMonths(d *serialization.ISODuration) (months int) {
	if _, err := d.ToDuration(); err == nil {
		return 0
	}
	defer func() {
		if recover() != nil {
			months = 0
		}
	}()
	m := isoDurationMonthsPattern.FindStringSubmatch(d.String())
	if m == nil {
		return 0
	}
	years, _ := strconv.Atoi(m[1])
	months, _ = strconv.Atoi(m[2])
	return (years-d.GetYears())*12 + months
}

func (a *mqlMicrosoftIdentityAndAccess) accessPackageCatalogs() ([]any, error) {
	em := &a.entitlementManagement
	em.catalogsOnce.Do(func() {
		em.catalogs, em.catalogsByID, em.catalogsErr = fetchAccessPackageCatalogs(a.MqlRuntime)
	})
	return em.catalogs, em.catalogsErr
}

func (a *mqlMicrosoftIdentityAndAccess) accessPackages() ([]any, error) {
	em := &a.entitlementManagement
	em.packagesOnce.Do(func() {
		em.packages, em.packagesByID, em.packagesErr = fetchAccessPackages(a.MqlRuntime)
	})
	return em.packages, em.packagesErr
}

func (a *mqlMicrosoftIdentityAndAccess) accessPackageAssignmentPolicies() ([]any, error) {
	em := &a.entitlementManagement
	em.policiesOnce.Do(func() {
		em.policies, em.policiesErr = fetchAccessPackageAssignmentPolicies(a.MqlRuntime)
	})
	return em.policies, em.policiesErr
}

func fetchAccessPackageCatalogs(runtime *plugin.Runtime) ([]any, map[string]*mqlMicrosoftIdentityAndAccessAccessPackageCatalog, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().EntitlementManagement().Catalogs().Get(ctx, nil)
	if err != nil {
		return nil, nil, classifyGraphError(err, entitlementManagementReadPermission)
	}
	byID := map[string]*mqlMicrosoftIdentityAndAccessAccessPackageCatalog{}
	if resp == nil {
		return []any{}, byID, nil
	}
	catalogs, err := iterate[models.AccessPackageCatalogable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessPackageCatalogCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, classifyGraphError(err, entitlementManagementReadPermission)
	}

	res := []any{}
	for _, catalog := range catalogs {
		if catalog == nil || catalog.GetId() == nil {
			continue
		}
		r, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessAccessPackageCatalog, accessPackageCatalogArgs(catalog))
		if err != nil {
			return nil, nil, err
		}
		mqlCatalog := r.(*mqlMicrosoftIdentityAndAccessAccessPackageCatalog)
		byID[*catalog.GetId()] = mqlCatalog
		res = append(res, mqlCatalog)
	}
	return res, byID, nil
}

func accessPackageCatalogArgs(catalog models.AccessPackageCatalogable) map[string]*llx.RawData {
	catalogType := llx.NilData
	if t := catalog.GetCatalogType(); t != nil {
		catalogType = llx.StringData(t.String())
	}
	state := llx.NilData
	if s := catalog.GetState(); s != nil {
		state = llx.StringData(s.String())
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData("microsoft.identityAndAccess.accessPackageCatalog/" + convert.ToValue(catalog.GetId())),
		"id":                  llx.StringDataPtr(catalog.GetId()),
		"displayName":         llx.StringDataPtr(catalog.GetDisplayName()),
		"description":         llx.StringDataPtr(catalog.GetDescription()),
		"catalogType":         catalogType,
		"state":               state,
		"isExternallyVisible": llx.BoolDataPtr(catalog.GetIsExternallyVisible()),
		"createdDateTime":     graphTimeData(catalog.GetCreatedDateTime()),
		"modifiedDateTime":    graphTimeData(catalog.GetModifiedDateTime()),
	}
}

func fetchAccessPackages(runtime *plugin.Runtime) ([]any, map[string]*mqlMicrosoftIdentityAndAccessAccessPackage, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().EntitlementManagement().AccessPackages().Get(ctx,
		&graphidentitygovernance.EntitlementManagementAccessPackagesRequestBuilderGetRequestConfiguration{
			QueryParameters: &graphidentitygovernance.EntitlementManagementAccessPackagesRequestBuilderGetQueryParameters{
				Expand: []string{"catalog($select=id)"},
			},
		})
	if err != nil {
		return nil, nil, classifyGraphError(err, entitlementManagementReadPermission)
	}
	byID := map[string]*mqlMicrosoftIdentityAndAccessAccessPackage{}
	if resp == nil {
		return []any{}, byID, nil
	}
	packages, err := iterate[models.AccessPackageable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessPackageCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, classifyGraphError(err, entitlementManagementReadPermission)
	}

	res := []any{}
	for _, pkg := range packages {
		if pkg == nil || pkg.GetId() == nil {
			continue
		}
		r, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessAccessPackage, accessPackageArgs(pkg))
		if err != nil {
			return nil, nil, err
		}
		mqlPkg := r.(*mqlMicrosoftIdentityAndAccessAccessPackage)
		if catalog := pkg.GetCatalog(); catalog != nil {
			mqlPkg.cacheCatalogID = convert.ToValue(catalog.GetId())
		}
		byID[*pkg.GetId()] = mqlPkg
		res = append(res, mqlPkg)
	}
	return res, byID, nil
}

func accessPackageArgs(pkg models.AccessPackageable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("microsoft.identityAndAccess.accessPackage/" + convert.ToValue(pkg.GetId())),
		"id":               llx.StringDataPtr(pkg.GetId()),
		"displayName":      llx.StringDataPtr(pkg.GetDisplayName()),
		"description":      llx.StringDataPtr(pkg.GetDescription()),
		"isHidden":         llx.BoolDataPtr(pkg.GetIsHidden()),
		"createdDateTime":  graphTimeData(pkg.GetCreatedDateTime()),
		"modifiedDateTime": graphTimeData(pkg.GetModifiedDateTime()),
	}
}

func fetchAccessPackageAssignmentPolicies(runtime *plugin.Runtime) ([]any, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().EntitlementManagement().AssignmentPolicies().Get(ctx,
		&graphidentitygovernance.EntitlementManagementAssignmentPoliciesRequestBuilderGetRequestConfiguration{
			QueryParameters: &graphidentitygovernance.EntitlementManagementAssignmentPoliciesRequestBuilderGetQueryParameters{
				Expand: []string{"accessPackage($select=id)"},
			},
		})
	if err != nil {
		return nil, classifyGraphError(err, entitlementManagementReadPermission)
	}
	if resp == nil {
		return []any{}, nil
	}
	policies, err := iterate[models.AccessPackageAssignmentPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateAccessPackageAssignmentPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, entitlementManagementReadPermission)
	}

	res := []any{}
	for _, policy := range policies {
		if policy == nil || policy.GetId() == nil {
			continue
		}
		args, err := accessPackageAssignmentPolicyArgs(policy)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessAccessPackageAssignmentPolicy, args)
		if err != nil {
			return nil, err
		}
		mqlPolicy := r.(*mqlMicrosoftIdentityAndAccessAccessPackageAssignmentPolicy)
		if pkg := policy.GetAccessPackage(); pkg != nil {
			mqlPolicy.cacheAccessPackageID = convert.ToValue(pkg.GetId())
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// allowsExternalRequestors reports whether an allowed target scope lets users
// who are not yet in the directory request access: users of one or all
// connected organizations, or any external user.
func allowsExternalRequestors(scope *models.AllowedTargetScope) bool {
	if scope == nil {
		return false
	}
	switch *scope {
	case models.SPECIFICCONNECTEDORGANIZATIONUSERS_ALLOWEDTARGETSCOPE,
		models.ALLCONFIGUREDCONNECTEDORGANIZATIONUSERS_ALLOWEDTARGETSCOPE,
		models.ALLEXTERNALUSERS_ALLOWEDTARGETSCOPE:
		return true
	}
	return false
}

// kiotaListToDicts serializes each element of a Graph model collection into
// a dict, skipping nil elements.
func kiotaListToDicts[T serialization.Parsable](items []T) ([]any, error) {
	res := []any{}
	for _, item := range items {
		d, err := kiotaToDict(item)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue
		}
		res = append(res, d)
	}
	return res, nil
}

// kiotaDictData serializes a Graph model into dict data, keeping an absent
// model null.
func kiotaDictData(p serialization.Parsable) (*llx.RawData, error) {
	d, err := kiotaToDict(p)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return llx.NilData, nil
	}
	return llx.DictData(d), nil
}

func accessPackageAssignmentPolicyArgs(policy models.AccessPackageAssignmentPolicyable) (map[string]*llx.RawData, error) {
	allowedTargetScope := llx.NilData
	if scope := policy.GetAllowedTargetScope(); scope != nil {
		allowedTargetScope = llx.StringData(scope.String())
	}

	specificAllowedTargets, err := kiotaListToDicts(policy.GetSpecificAllowedTargets())
	if err != nil {
		return nil, err
	}

	expirationType, expirationDuration, expirationEnd := llx.NilData, llx.NilData, llx.NilData
	if exp := policy.GetExpiration(); exp != nil {
		if t := exp.GetTypeEscaped(); t != nil {
			expirationType = llx.StringData(t.String())
		}
		expirationDuration = llx.StringDataPtr(isoDurationPtr(exp.GetDuration()))
		expirationEnd = graphTimeData(exp.GetEndDateTime())
	}

	requestorSettings, err := kiotaDictData(policy.GetRequestorSettings())
	if err != nil {
		return nil, err
	}

	approvalRequiredForAdd, approvalRequiredForUpdate, justificationRequired := llx.NilData, llx.NilData, llx.NilData
	approvalStages := []any{}
	if approval := policy.GetRequestApprovalSettings(); approval != nil {
		approvalRequiredForAdd = llx.BoolDataPtr(approval.GetIsApprovalRequiredForAdd())
		approvalRequiredForUpdate = llx.BoolDataPtr(approval.GetIsApprovalRequiredForUpdate())
		justificationRequired = llx.BoolDataPtr(approval.GetIsRequestorJustificationRequired())
		approvalStages, err = kiotaListToDicts(approval.GetStages())
		if err != nil {
			return nil, err
		}
	}

	reviewEnabled := llx.NilData
	reviewSettings := llx.NilData
	if review := policy.GetReviewSettings(); review != nil {
		reviewEnabled = llx.BoolDataPtr(review.GetIsEnabled())
		reviewSettings, err = kiotaDictData(review)
		if err != nil {
			return nil, err
		}
	}

	automaticRequestSettings, err := kiotaDictData(policy.GetAutomaticRequestSettings())
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"__id":                             llx.StringData("microsoft.identityAndAccess.accessPackageAssignmentPolicy/" + convert.ToValue(policy.GetId())),
		"id":                               llx.StringDataPtr(policy.GetId()),
		"displayName":                      llx.StringDataPtr(policy.GetDisplayName()),
		"description":                      llx.StringDataPtr(policy.GetDescription()),
		"allowedTargetScope":               allowedTargetScope,
		"allowsExternalRequestors":         llx.BoolData(allowsExternalRequestors(policy.GetAllowedTargetScope())),
		"specificAllowedTargets":           llx.ArrayData(specificAllowedTargets, types.Dict),
		"expirationType":                   expirationType,
		"expirationDuration":               expirationDuration,
		"expirationEndDateTime":            expirationEnd,
		"requestorSettings":                requestorSettings,
		"isApprovalRequiredForAdd":         approvalRequiredForAdd,
		"isApprovalRequiredForUpdate":      approvalRequiredForUpdate,
		"isRequestorJustificationRequired": justificationRequired,
		"approvalStages":                   llx.ArrayData(approvalStages, types.Dict),
		"isAccessReviewEnabled":            reviewEnabled,
		"reviewSettings":                   reviewSettings,
		"automaticRequestSettings":         automaticRequestSettings,
		"createdDateTime":                  graphTimeData(policy.GetCreatedDateTime()),
		"modifiedDateTime":                 graphTimeData(policy.GetModifiedDateTime()),
	}, nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessPackageCatalog) accessPackages() ([]any, error) {
	ia, err := identityAndAccessSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	packages, err := ia.accessPackages()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, p := range packages {
		pkg := p.(*mqlMicrosoftIdentityAndAccessAccessPackage)
		if pkg.cacheCatalogID != "" && pkg.cacheCatalogID == a.Id.Data {
			res = append(res, pkg)
		}
	}
	return res, nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessPackage) catalog() (*mqlMicrosoftIdentityAndAccessAccessPackageCatalog, error) {
	if a.cacheCatalogID == "" {
		a.Catalog.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ia, err := identityAndAccessSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if _, err := ia.accessPackageCatalogs(); err != nil {
		return nil, err
	}
	catalog, ok := ia.entitlementManagement.catalogsByID[a.cacheCatalogID]
	if !ok {
		a.Catalog.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return catalog, nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessPackage) assignmentPolicies() ([]any, error) {
	ia, err := identityAndAccessSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policies, err := ia.accessPackageAssignmentPolicies()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, p := range policies {
		policy := p.(*mqlMicrosoftIdentityAndAccessAccessPackageAssignmentPolicy)
		if policy.cacheAccessPackageID != "" && policy.cacheAccessPackageID == a.Id.Data {
			res = append(res, policy)
		}
	}
	return res, nil
}

func (a *mqlMicrosoftIdentityAndAccessAccessPackageAssignmentPolicy) accessPackage() (*mqlMicrosoftIdentityAndAccessAccessPackage, error) {
	if a.cacheAccessPackageID == "" {
		a.AccessPackage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ia, err := identityAndAccessSingleton(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if _, err := ia.accessPackages(); err != nil {
		return nil, err
	}
	pkg, ok := ia.entitlementManagement.packagesByID[a.cacheAccessPackageID]
	if !ok {
		a.AccessPackage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pkg, nil
}
