// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/directory"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/organization"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

type mqlMicrosoftTenantInternal struct {
	lock              sync.Mutex
	realmDataFetched  bool
	subscriptionsOnce sync.Once
	subscriptionsData []companySubscription
	subscriptionsErr  error
}

type userRealmResponse struct {
	Login               string               `json:"Login"`
	DomainName          string               `json:"DomainName"`
	FederationBrandName string               `json:"FederationBrandName"`
	NameSpaceType       string               `json:"NameSpaceType,omitempty"`
	TenantBrandingInfo  []tenantBrandingInfo `json:"TenantBrandingInfo"`
}

type tenantBrandingInfo struct {
	KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
	BannerLogo             string `json:"BannerLogo,omitempty"`
	BackgroundColor        string `json:"BackgroundColor,omitempty"`
	UseTransparentLightbox bool   `json:"UseTransparentLightbox,omitempty"`
}

func (m *mqlMicrosoftTenant) id() (string, error) {
	return m.Id.Data, nil
}

// Deprecated: use `microsoft.tenant` instead
func (a *mqlMicrosoft) organizations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Organization().Get(ctx, &organization.OrganizationRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	orgs, err := iterate[models.Organizationable](ctx, resp, graphClient.GetAdapter(), models.CreateOrganizationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range orgs {
		org := orgs[i]
		mqlResource, err := newMicrosoftTenant(a.MqlRuntime, org)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

var tenantFields = []string{
	"id",
	"assignedPlans",
	"createdDateTime",
	"displayName",
	"verifiedDomains",
	"onPremisesSyncEnabled",
	"tenantType",
	"provisionedPlans",
	"privacyProfile",
	"technicalNotificationMails",
	"preferredLanguage",
	"countryLetterCode",
	"securityComplianceNotificationMails",
	"securityComplianceNotificationPhones",
}

func initMicrosoftTenant(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Organization().ByOrganizationId(conn.TenantId()).Get(ctx, &organization.OrganizationItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &organization.OrganizationItemRequestBuilderGetQueryParameters{
			Select: tenantFields,
		},
	})
	if err != nil {
		return nil, nil, transformError(err)
	}

	tenant, err := newMicrosoftTenant(runtime, resp)
	if err != nil {
		return nil, nil, err
	}
	return nil, tenant, nil
}

func newMicrosoftTenant(runtime *plugin.Runtime, org models.Organizationable) (*mqlMicrosoftTenant, error) {
	assignedPlans, err := convert.JsonToDictSlice(newAssignedPlans(org.GetAssignedPlans()))
	if err != nil {
		return nil, err
	}
	verifiedDomains, err := convert.JsonToDictSlice(newVerifiedDomains(org.GetVerifiedDomains()))
	if err != nil {
		return nil, err
	}

	provisionedPlans, err := convert.JsonToDictSlice(newProvisionedPlans(org.GetProvisionedPlans()))
	if err != nil {
		return nil, err
	}

	privacyProfileDict := map[string]any{}
	if org.GetPrivacyProfile() != nil {
		privacyProfileDict, err = convert.JsonToDict(newPrivacyProfile(org.GetPrivacyProfile()))
		if err != nil {
			return nil, err
		}
	}

	mqlResource, err := CreateResource(runtime, "microsoft.tenant",
		map[string]*llx.RawData{
			"id":                                   llx.StringDataPtr(org.GetId()),
			"assignedPlans":                        llx.DictData(assignedPlans),
			"name":                                 llx.StringDataPtr(org.GetDisplayName()),
			"verifiedDomains":                      llx.DictData(verifiedDomains),
			"onPremisesSyncEnabled":                llx.BoolDataPtr(org.GetOnPremisesSyncEnabled()),
			"createdAt":                            llx.TimeDataPtr(org.GetCreatedDateTime()),
			"type":                                 llx.StringDataPtr(org.GetTenantType()),
			"provisionedPlans":                     llx.DictData(provisionedPlans),
			"technicalNotificationMails":           llx.ArrayData(convert.SliceAnyToInterface(org.GetTechnicalNotificationMails()), types.String),
			"preferredLanguage":                    llx.StringDataPtr(org.GetPreferredLanguage()),
			"privacyProfile":                       llx.DictData(privacyProfileDict),
			"countryLetterCode":                    llx.StringDataPtr(org.GetCountryLetterCode()),
			"securityComplianceNotificationMails":  llx.ArrayData(convert.SliceAnyToInterface(org.GetSecurityComplianceNotificationMails()), types.String),
			"securityComplianceNotificationPhones": llx.ArrayData(convert.SliceAnyToInterface(org.GetSecurityComplianceNotificationPhones()), types.String),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftTenant), nil
}

// enabledServicePlanServices returns the distinct, alphabetically sorted set of
// service families from a tenant's assignedPlans whose capabilityStatus is
// "Enabled". The input is the assignedPlans dict slice as stored on the
// resource (each element a map with "service" and "capabilityStatus" keys);
// entries that are not maps, lack an enabled status, or carry an empty service
// name are skipped. It is the pure core of the enabledServicePlans() accessor.
func enabledServicePlanServices(assignedPlans []any) []string {
	seen := map[string]struct{}{}
	for _, p := range assignedPlans {
		plan, ok := p.(map[string]any)
		if !ok {
			continue
		}
		status, _ := plan["capabilityStatus"].(string)
		if !strings.EqualFold(status, "Enabled") {
			continue
		}
		service, _ := plan["service"].(string)
		if service == "" {
			continue
		}
		seen[service] = struct{}{}
	}

	services := make([]string, 0, len(seen))
	for service := range seen {
		services = append(services, service)
	}
	sort.Strings(services)
	return services
}

// enabledServicePlans surfaces the tenant's enabled service families so checks
// can gate on licensing without parsing the assignedPlans dicts by hand.
func (a *mqlMicrosoftTenant) enabledServicePlans() ([]any, error) {
	assignedPlans := a.GetAssignedPlans()
	if assignedPlans.Error != nil {
		return nil, assignedPlans.Error
	}
	return convert.SliceAnyToInterface(enabledServicePlanServices(assignedPlans.Data)), nil
}

// https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
// getCompanySubscriptions fetches the tenant's commercial subscriptions once
// and caches the result so subscriptions() and paidLicenses() share one call.
func (a *mqlMicrosoftTenant) getCompanySubscriptions() ([]companySubscription, error) {
	a.subscriptionsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			a.subscriptionsErr = err
			return
		}
		ctx := context.Background()
		resp, err := graphClient.Directory().Subscriptions().Get(ctx, &directory.SubscriptionsRequestBuilderGetRequestConfiguration{})
		if err != nil {
			a.subscriptionsErr = transformError(err)
			return
		}
		subs, err := iterate[models.CompanySubscriptionable](ctx, resp, graphClient.GetAdapter(), models.CreateCompanySubscriptionCollectionResponseFromDiscriminatorValue)
		if err != nil {
			a.subscriptionsErr = err
			return
		}

		res := make([]companySubscription, 0, len(subs))
		for _, sub := range subs {
			res = append(res, newCompanySubscription(sub))
		}
		a.subscriptionsData = res
	})
	return a.subscriptionsData, a.subscriptionsErr
}

func (a *mqlMicrosoftTenant) subscriptions() ([]any, error) {
	subs, err := a.getCompanySubscriptions()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(subs))
	for _, sub := range subs {
		res = append(res, sub)
	}

	return convert.JsonToDictSlice(res)
}

func (a *mqlMicrosoftTenant) paidLicenses() (int64, error) {
	subs, err := a.getCompanySubscriptions()
	if err != nil {
		return 0, err
	}
	return sumPaidLicenses(subs), nil
}

// sumPaidLicenses totals the seats a tenant actually pays for, excluding
// trials, subscriptions past their billing grace period, and free/self-service
// plans.
func sumPaidLicenses(subs []companySubscription) int64 {
	var total int64
	for _, sub := range subs {
		if sub.IsTrial != nil && *sub.IsTrial {
			continue
		}
		// Only active subscriptions are still billed. "Warning" is the
		// post-expiry grace period (still live); Suspended/LockedOut/Deleted
		// are past grace with the service off.
		if sub.Status != nil && *sub.Status != "Enabled" && *sub.Status != "Warning" {
			continue
		}
		// Free and self-service plans are not paid seats and report sentinel
		// license counts (e.g. RIGHTSMANAGEMENT_ADHOC reports 1,000,000).
		if sub.SkuPartNumber != nil {
			if _, free := selfServiceSkuPartNumbers[*sub.SkuPartNumber]; free {
				continue
			}
		}
		if sub.TotalLicenses != nil {
			total += int64(*sub.TotalLicenses)
		}
	}
	return total
}

// selfServiceSkuPartNumbers are free/self-service/viral Microsoft plans that a
// tenant does not pay per-seat for. They surface in the subscription list with
// status Enabled and isTrial false, and report sentinel license counts (10,000
// or 1,000,000), so they must be excluded from paidLicenses. This list is
// best-effort; Microsoft adds freemium products over time, so it may need
// extending as new ones surface.
var selfServiceSkuPartNumbers = map[string]struct{}{
	"RIGHTSMANAGEMENT_ADHOC":         {}, // Rights Management Adhoc
	"WINDOWS_STORE":                  {}, // Windows Store for Business
	"FLOW_FREE":                      {}, // Power Automate Free
	"POWERAPPS_VIRAL":                {}, // Power Apps Plan 2 Trial (viral)
	"POWER_BI_STANDARD":              {}, // Power BI (free)
	"CCIBOTS_PRIVPREV_VIRAL":         {}, // Power Virtual Agents Viral Trial
	"TEAMS_EXPLORATORY":              {}, // Microsoft Teams Exploratory
	"STREAM":                         {}, // Microsoft Stream Trial
	"SPZA_IW":                        {}, // App Connect IW
	"PROJECT_MADEIRA_PREVIEW_IW_SKU": {}, // Dynamics 365 Business Central preview
}

func (a *mqlMicrosoft) tenantDomainName() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	resp, err := graphClient.Organization().Get(ctx, &organization.OrganizationRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return "", transformError(err)
	}
	orgs, err := iterate[models.Organizationable](ctx, resp, graphClient.GetAdapter(), models.CreateOrganizationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return "", err
	}
	tenantDomainName := ""

	for _, org := range orgs {
		for _, d := range org.GetVerifiedDomains() {
			if d.GetIsInitial() != nil && *d.GetIsInitial() && d.GetName() != nil {
				tenantDomainName = *d.GetName()
			}
		}
	}

	return tenantDomainName, nil
}

func (a *mqlMicrosoftTenant) settings() (*mqlMicrosoftTenantSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	appsAndServicesConfig, err := graphClient.Admin().AppsAndServices().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}
	return a.settingsFrom(appsAndServicesConfig)
}

// settingsFrom builds the tenant settings from the admin appsAndServices
// answer. An answer without settings reads null rather than as both switches
// off: nothing was read, so nothing can be claimed about either.
func (a *mqlMicrosoftTenant) settingsFrom(appsAndServicesConfig betamodels.AdminAppsAndServicesable) (*mqlMicrosoftTenantSettings, error) {
	if appsAndServicesConfig == nil || appsAndServicesConfig.GetSettings() == nil {
		a.Settings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	settingsId := fmt.Sprintf("%s-settings", a.Id.Data)
	mqlSettings, err := CreateResource(a.MqlRuntime, "microsoft.tenantSettings",
		map[string]*llx.RawData{
			"__id":                         llx.StringData(settingsId),
			"isAppAndServicesTrialEnabled": llx.BoolDataPtr(appsAndServicesConfig.GetSettings().GetIsAppAndServicesTrialEnabled()),
			"isOfficeStoreEnabled":         llx.BoolDataPtr(appsAndServicesConfig.GetSettings().GetIsOfficeStoreEnabled()),
		})
	if err != nil {
		return nil, err
	}

	return mqlSettings.(*mqlMicrosoftTenantSettings), nil
}

// Least privileged permissions: OrgSettings-Forms.Read.All
func (a *mqlMicrosoftTenant) formsSettings() (*mqlMicrosoftTenantFormsSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	beatGraphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	formsSetting, err := beatGraphClient.Admin().Forms().Get(context.Background(), nil)
	if err != nil {
		return nil, transformError(err)
	}

	return a.formsSettingsFrom(formsSetting)
}

// formsSettingsFrom builds the Forms settings from the admin forms answer. An
// answer without settings reads null.
func (a *mqlMicrosoftTenant) formsSettingsFrom(formsSetting betamodels.AdminFormsable) (*mqlMicrosoftTenantFormsSettings, error) {
	if formsSetting == nil || formsSetting.GetSettings() == nil {
		a.FormsSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	settings := formsSetting.GetSettings()

	formsSettingId := fmt.Sprintf("%s-forms-settings", a.Id.Data)

	formSetting, err := CreateResource(a.MqlRuntime, "microsoft.tenantFormsSettings",
		map[string]*llx.RawData{
			"__id":                                llx.StringData(formsSettingId),
			"isExternalSendFormEnabled":           llx.BoolDataPtr(settings.GetIsExternalSendFormEnabled()),
			"isExternalShareCollaborationEnabled": llx.BoolDataPtr(settings.GetIsExternalShareCollaborationEnabled()),
			"isExternalShareResultEnabled":        llx.BoolDataPtr(settings.GetIsExternalShareResultEnabled()),
			"isExternalShareTemplateEnabled":      llx.BoolDataPtr(settings.GetIsExternalShareTemplateEnabled()),
			"isRecordIdentityByDefaultEnabled":    llx.BoolDataPtr(settings.GetIsRecordIdentityByDefaultEnabled()),
			"isBingImageSearchEnabled":            llx.BoolDataPtr(settings.GetIsBingImageSearchEnabled()),
			"isInOrgFormsPhishingScanEnabled":     llx.BoolDataPtr(settings.GetIsInOrgFormsPhishingScanEnabled()),
		})
	if err != nil {
		return nil, err
	}

	return formSetting.(*mqlMicrosoftTenantFormsSettings), nil
}

func (a *mqlMicrosoftTenant) fetchRealmData() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.realmDataFetched {
		return a.Realm.Error
	}
	a.realmDataFetched = true

	verifiedDomains := a.GetVerifiedDomains()
	if verifiedDomains.Error != nil {
		err := verifiedDomains.Error
		a.Realm = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		a.Branding = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		return err
	}

	if len(verifiedDomains.Data) == 0 {
		a.Realm = plugin.TValue[[]any]{Data: []any{}, Error: nil, State: plugin.StateIsSet}
		a.Branding = plugin.TValue[[]any]{Data: []any{}, Error: nil, State: plugin.StateIsSet}
		return nil
	}

	var realmInfos []any
	var brandingInfos []any

	for _, domain := range verifiedDomains.Data {
		domainDict, ok := domain.(map[string]any)
		if !ok {
			continue
		}

		domainName, ok := domainDict["name"].(string)
		if !ok || domainName == "" {
			continue
		}

		realmResp, err := a.getUserRealmInfoForDomain(domainName)
		if err != nil {
			logger.DebugDumpJSON("tenant-realm-domain-error", []byte(fmt.Sprintf("domain: %s, error: %v", domainName, err)))
			a.Realm = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
			a.Branding = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
			return err
		}

		// Create realm info resource
		realmId := fmt.Sprintf("%s-realm-info-%s", a.Id.Data, realmResp.DomainName)
		mqlRealm, err := CreateResource(a.MqlRuntime, ResourceMicrosoftTenantRealmInfo,
			map[string]*llx.RawData{
				"__id":                llx.StringData(realmId),
				"federationBrandName": llx.StringData(realmResp.FederationBrandName),
				"domainName":          llx.StringData(realmResp.DomainName),
				"login":               llx.StringData(realmResp.Login),
				"nameSpaceType":       llx.StringData(realmResp.NameSpaceType),
			})
		if err != nil {
			logger.DebugDumpJSON("tenant-realm-create-error", []byte(fmt.Sprintf("domain: %s, error: %v", domainName, err)))
			a.Realm = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
			a.Branding = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
			return err
		}
		realmInfos = append(realmInfos, mqlRealm)

		// Create branding info resources
		for i, info := range realmResp.TenantBrandingInfo {
			brandingId := fmt.Sprintf("%s-branding-info-%s-%d", a.Id.Data, realmResp.DomainName, i)
			mqlBranding, err := CreateResource(a.MqlRuntime, ResourceMicrosoftTenantBrandingInfo,
				map[string]*llx.RawData{
					"__id":                   llx.StringData(brandingId),
					"domainName":             llx.StringData(realmResp.DomainName),
					"keepMeSignedInDisabled": llx.BoolData(info.KeepMeSignedInDisabled),
					"backgroundColor":        llx.StringData(info.BackgroundColor),
					"bannerLogo":             llx.StringData(info.BannerLogo),
					"useTransparentLightbox": llx.BoolData(info.UseTransparentLightbox),
				})
			if err != nil {
				logger.DebugDumpJSON("tenant-branding-create-error", []byte(fmt.Sprintf("domain: %s, index: %d, error: %v", domainName, i, err)))
				a.Realm = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
				a.Branding = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
				return err
			}
			brandingInfos = append(brandingInfos, mqlBranding)
		}
	}

	a.Realm = plugin.TValue[[]any]{Data: realmInfos, Error: nil, State: plugin.StateIsSet}
	a.Branding = plugin.TValue[[]any]{Data: brandingInfos, Error: nil, State: plugin.StateIsSet}
	return nil
}

func (a *mqlMicrosoftTenant) getUserRealmInfoForDomain(domainName string) (*userRealmResponse, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/common/userrealm/%s?api-version=2.0", domainName)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query userrealm endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.DebugDumpJSON("tenant-branding-error", body)
		return nil, fmt.Errorf("userrealm endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var realmResp userRealmResponse
	if err := json.Unmarshal(body, &realmResp); err != nil {
		return nil, fmt.Errorf("failed to parse userrealm response: %w", err)
	}

	return &realmResp, nil
}

func (a *mqlMicrosoftTenant) realm() ([]any, error) {
	return nil, a.fetchRealmData()
}

func (a *mqlMicrosoftTenant) branding() ([]any, error) {
	return nil, a.fetchRealmData()
}
