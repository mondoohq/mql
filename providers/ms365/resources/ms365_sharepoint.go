// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

var sharepointReport = `
$ErrorActionPreference = "Stop"
$token = '%s'
$url = "%s"
Install-Module PnP.PowerShell -Force -Scope CurrentUser
Import-Module PnP.PowerShell
Connect-PnPOnline -AccessToken $token -Url $url

$SPOTenant = (Get-PnPTenant)
$DefaultLinkPermission = (Get-PnPTenant | Select-Object -ExpandProperty DefaultLinkPermission)
$SPOTenantSyncClientRestriction = (Get-PnPTenantSyncClientRestriction)
$SPOSite = (Get-PnPTenantSite)

$sharepoint = New-Object PSObject
Add-Member -InputObject $sharepoint -MemberType NoteProperty -Name SPOTenant -Value $SPOTenant
Add-Member -InputObject $sharepoint -MemberType NoteProperty -Name SPOTenantSyncClientRestriction -Value $SPOTenantSyncClientRestriction
Add-Member -InputObject $sharepoint -MemberType NoteProperty -Name SPOSite -Value $SPOSite
Add-Member -InputObject $sharepoint -MemberType NoteProperty -Name DefaultLinkPermission -Value $DefaultLinkPermission

Disconnect-PnPOnline

ConvertTo-Json -Depth 4 $sharepoint -EnumsAsStrings
`

type SharepointOnlineReport struct {
	SpoTenant                      any        `json:"SPOTenant"`
	SpoTenantSyncClientRestriction any        `json:"SPOTenantSyncClientRestriction"`
	SpoSite                        []*SpoSite `json:"SPOSite"`
	DefaultLinkPermission          string     `json:"DefaultLinkPermission"`
}

type SpoTenantConfig struct {
	SharingCapability                          string `json:"SharingCapability"`
	SharingDomainRestrictionMode               string `json:"SharingDomainRestrictionMode"`
	SharingAllowedDomainList                   string `json:"SharingAllowedDomainList"`
	SharingBlockedDomainList                   string `json:"SharingBlockedDomainList"`
	DefaultSharingLinkType                     string `json:"DefaultSharingLinkType"`
	DefaultLinkPermission                      string `json:"DefaultLinkPermission"`
	RequireAcceptingAccountMatchInvitedAccount bool   `json:"RequireAcceptingAccountMatchInvitedAccount"`
	PreventExternalUsersFromResharing          bool   `json:"PreventExternalUsersFromResharing"`
	ExternalUserExpirationRequired             bool   `json:"ExternalUserExpirationRequired"`
	ExternalUserExpireInDays                   int64  `json:"ExternalUserExpireInDays"`
	EmailAttestationRequired                   bool   `json:"EmailAttestationRequired"`
	EmailAttestationReAuthDays                 int64  `json:"EmailAttestationReAuthDays"`
	RequireAnonymousLinksExpireInDays          int64  `json:"RequireAnonymousLinksExpireInDays"`
	ShowEveryoneClaim                          bool   `json:"ShowEveryoneClaim"`
	ShowAllUsersClaim                          bool   `json:"ShowAllUsersClaim"`
	ShowEveryoneExceptExternalUsersClaim       bool   `json:"ShowEveryoneExceptExternalUsersClaim"`
	NotifyOwnersWhenItemsReshared              bool   `json:"NotifyOwnersWhenItemsReshared"`
	LegacyAuthProtocolsEnabled                 bool   `json:"LegacyAuthProtocolsEnabled"`
	ConditionalAccessPolicy                    string `json:"ConditionalAccessPolicy"`
	IsUnmanagedSyncClientForTenantRestricted   bool   `json:"IsUnmanagedSyncClientForTenantRestricted"`
	DisallowInfectedFileDownload               bool   `json:"DisallowInfectedFileDownload"`
	// pointers so that a tenant which does not report the setting yields null
	// rather than a zero value that reads as "disabled"
	EnableAzureADB2BIntegration            *bool    `json:"EnableAzureADB2BIntegration"`
	OneDriveSharingCapability              *string  `json:"OneDriveSharingCapability"`
	WhoCanShareAuthenticatedGuestAllowList []string `json:"WhoCanShareAuthenticatedGuestAllowList"`
}

type SpoSite struct {
	DenyAddAndCustomizePages string `json:"DenyAddAndCustomizePages"`
	Url                      string `json:"Url"`
	Title                    string `json:"Title"`
	Template                 string `json:"Template"`
	SharingCapability        string `json:"SharingCapability"`
	ConditionalAccessPolicy  string `json:"ConditionalAccessPolicy"`
	LockState                string `json:"LockState"`
	AllowSelfServiceUpgrade  bool   `json:"AllowSelfServiceUpgrade"`
	Owner                    string `json:"Owner"`
	Status                   string `json:"Status"`
}

// stringListData keeps a nil slice null instead of turning it into an empty
// array. convert.SliceAnyToInterface allocates for a nil input, so passing its
// result straight to llx.ArrayData would report a setting the tenant never
// returned as an empty list -- e.g. "no security group restricts guest
// sharing", which is a security answer rather than a missing one.
func stringListData(v []string) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.ArrayData(convert.SliceAnyToInterface(v), types.String)
}

func (m *mqlMs365SharepointonlineSite) id() (string, error) {
	return m.Url.Data, nil
}

type mqlMs365SharepointonlineInternal struct {
	sharepointLock        sync.Mutex
	fetched               bool
	fetchErr              error
	DefaultLinkPermission plugin.TValue[string]
}

func (r *mqlMs365Sharepointonline) getTenant() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)

	microsoft, err := CreateResource(r.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	mqlMicrosoft := microsoft.(*mqlMicrosoft)

	// we prefer the explicitly passed in sharepoint url, if there is one
	spUrl := conn.SharepointUrl()
	if spUrl == "" {
		tenantDomainName := mqlMicrosoft.GetTenantDomainName()
		if tenantDomainName.Error != nil {
			// note: we don't want to err here. maybe the app registration has no perms to get the organization
			// in that case we try and get the report by using the explicitly passed in sharepoint url
			log.Debug().Err(tenantDomainName.Error).Msg("unable to get tenant domain name")
		} else {
			spUrl = tenantDomainName.Data
		}
	}

	return extractSharepointTenant(spUrl)
}

// extractSharepointTenant pulls the bare tenant name out of a user-provided
// sharepoint url. Accepts both the bare form ("contoso.onmicrosoft.com") and
// the full url form ("https://contoso.sharepoint.com[/...]").
func extractSharepointTenant(spUrl string) (string, error) {
	if spUrl == "" {
		return "", errors.New("no sharepoint url provided, unable to fetch sharepoint online report")
	}

	host := spUrl
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}

	domainParts := strings.Split(host, ".")
	if len(domainParts) < 2 || domainParts[0] == "" {
		return "", fmt.Errorf("invalid sharepoint url: %s", spUrl)
	}

	return domainParts[0], nil
}

func (r *mqlMs365Sharepointonline) getSharepointOnlineReport() error {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)

	r.sharepointLock.Lock()
	defer r.sharepointLock.Unlock()

	// only fetch once
	if r.fetched {
		return r.fetchErr
	}

	errHandler := func(err error) error {
		r.fetchErr = err
		r.fetched = true
		return err
	}

	// for some reasons, tokens issued by a client secret do not work. only certificates do
	// TODO: ^ we should try and investigate why, its unclear to me why it happens.
	if !conn.IsCertProvided() {
		return errHandler(fmt.Errorf("only certificate authentication is supported for fetching sharepoint online report"))
	}

	tenant, err := r.getTenant()
	if err != nil {
		return errHandler(fmt.Errorf("cannot fetch sharepoint online report: %w", err))
	}
	if tenant == "" {
		return errHandler(fmt.Errorf("tenant cannot be empty, cannot fetch sharepoint online report"))
	}

	ctx := context.Background()
	token := conn.Token()
	tokenScope := fmt.Sprintf("https://%s-admin.sharepoint.com/.default", tenant)
	sharepointUrl := fmt.Sprintf("https://%s.sharepoint.com", tenant)
	spToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{tokenScope},
	})
	if err != nil {
		return errHandler(err)
	}

	fmtScript := fmt.Sprintf(sharepointReport, spToken.Token, sharepointUrl)
	res, err := conn.CheckAndRunPowershellScript(fmtScript)
	if err != nil {
		return errHandler(err)
	}
	report := &SharepointOnlineReport{}
	if res.ExitStatus == 0 {
		data, err := io.ReadAll(res.Stdout)
		if err != nil {
			return errHandler(err)
		}

		logger.DebugDumpJSON("sharepoint-online-report", string(data))

		err = json.Unmarshal(data, report)
		if err != nil {
			return errHandler(err)
		}
	} else {
		data, err := io.ReadAll(res.Stderr)
		if err != nil {
			return errHandler(err)
		}

		str := string(data)
		if strings.Contains(strings.ToLower(str), "unauthorized") {
			return errHandler(errors.New("access denied, please ensure the credentials have the right permissions in Azure AD"))
		}

		logger.DebugDumpJSON("sharepoint-online-report", string(data))
		return errHandler(fmt.Errorf("failed to generate sharepoint online report (exit code %d): %s", res.ExitStatus, string(data)))
	}

	spoTenant, spoTenantErr := convert.JsonToDict(report.SpoTenant)
	r.SpoTenant = plugin.TValue[any]{Data: spoTenant, State: plugin.StateIsSet, Error: spoTenantErr}

	// decode the same payload into the typed tenant configuration resource
	tenantConfig := &SpoTenantConfig{}
	raw, err := json.Marshal(report.SpoTenant)
	if err == nil {
		err = json.Unmarshal(raw, tenantConfig)
	}
	if err != nil {
		// a decode failure must surface as an error rather than reporting a
		// zero-value config (all false/0/"") as if it were the real tenant state
		r.TenantConfiguration = plugin.TValue[*mqlMs365SharepointonlineTenantConfig]{State: plugin.StateIsSet, Error: err}
	} else {
		mqlTenantConfig, mqlTenantConfigErr := CreateResource(r.MqlRuntime, "ms365.sharepointonline.tenantConfig",
			map[string]*llx.RawData{
				"__id":                                       llx.StringData("ms365.sharepointonline.tenantConfig"),
				"sharingCapability":                          llx.StringData(tenantConfig.SharingCapability),
				"sharingDomainRestrictionMode":               llx.StringData(tenantConfig.SharingDomainRestrictionMode),
				"sharingAllowedDomainList":                   llx.StringData(tenantConfig.SharingAllowedDomainList),
				"sharingBlockedDomainList":                   llx.StringData(tenantConfig.SharingBlockedDomainList),
				"defaultSharingLinkType":                     llx.StringData(tenantConfig.DefaultSharingLinkType),
				"defaultLinkPermission":                      llx.StringData(tenantConfig.DefaultLinkPermission),
				"requireAcceptingAccountMatchInvitedAccount": llx.BoolData(tenantConfig.RequireAcceptingAccountMatchInvitedAccount),
				"preventExternalUsersFromResharing":          llx.BoolData(tenantConfig.PreventExternalUsersFromResharing),
				"externalUserExpirationRequired":             llx.BoolData(tenantConfig.ExternalUserExpirationRequired),
				"externalUserExpireInDays":                   llx.IntData(tenantConfig.ExternalUserExpireInDays),
				"emailAttestationRequired":                   llx.BoolData(tenantConfig.EmailAttestationRequired),
				"emailAttestationReAuthDays":                 llx.IntData(tenantConfig.EmailAttestationReAuthDays),
				"requireAnonymousLinksExpireInDays":          llx.IntData(tenantConfig.RequireAnonymousLinksExpireInDays),
				"showEveryoneClaim":                          llx.BoolData(tenantConfig.ShowEveryoneClaim),
				"showAllUsersClaim":                          llx.BoolData(tenantConfig.ShowAllUsersClaim),
				"showEveryoneExceptExternalUsersClaim":       llx.BoolData(tenantConfig.ShowEveryoneExceptExternalUsersClaim),
				"notifyOwnersWhenItemsReshared":              llx.BoolData(tenantConfig.NotifyOwnersWhenItemsReshared),
				"legacyAuthProtocolsEnabled":                 llx.BoolData(tenantConfig.LegacyAuthProtocolsEnabled),
				"conditionalAccessPolicy":                    llx.StringData(tenantConfig.ConditionalAccessPolicy),
				"isUnmanagedSyncClientForTenantRestricted":   llx.BoolData(tenantConfig.IsUnmanagedSyncClientForTenantRestricted),
				"disallowInfectedFileDownload":               llx.BoolData(tenantConfig.DisallowInfectedFileDownload),
				"enableAzureADB2BIntegration":                llx.BoolDataPtr(tenantConfig.EnableAzureADB2BIntegration),
				"oneDriveSharingCapability":                  llx.StringDataPtr(tenantConfig.OneDriveSharingCapability),
				"whoCanShareAuthenticatedGuestAllowList": stringListData(
					tenantConfig.WhoCanShareAuthenticatedGuestAllowList),
			})
		if mqlTenantConfigErr != nil {
			r.TenantConfiguration = plugin.TValue[*mqlMs365SharepointonlineTenantConfig]{State: plugin.StateIsSet, Error: mqlTenantConfigErr}
		} else {
			r.TenantConfiguration = plugin.TValue[*mqlMs365SharepointonlineTenantConfig]{Data: mqlTenantConfig.(*mqlMs365SharepointonlineTenantConfig), State: plugin.StateIsSet}
		}
	}

	spoTenantSyncClientRestriction, spoTenantSyncClientRestrictionErr := convert.JsonToDict(report.SpoTenantSyncClientRestriction)
	r.SpoTenantSyncClientRestriction = plugin.TValue[any]{Data: spoTenantSyncClientRestriction, State: plugin.StateIsSet, Error: spoTenantSyncClientRestrictionErr}

	sites := []any{}
	var sitesErr error
	for _, s := range report.SpoSite {
		mqlSpoSite, err := CreateResource(r.MqlRuntime, "ms365.sharepointonline.site",
			map[string]*llx.RawData{
				"denyAddAndCustomizePages": llx.BoolData(s.DenyAddAndCustomizePages == "Enabled"),
				"url":                      llx.StringData(s.Url),
				"title":                    llx.StringData(s.Title),
				"template":                 llx.StringData(s.Template),
				"sharingCapability":        llx.StringData(s.SharingCapability),
				"conditionalAccessPolicy":  llx.StringData(s.ConditionalAccessPolicy),
				"lockState":                llx.StringData(s.LockState),
				"allowSelfServiceUpgrade":  llx.BoolData(s.AllowSelfServiceUpgrade),
				"owner":                    llx.StringData(s.Owner),
				"status":                   llx.StringData(s.Status),
			})
		if err != nil {
			sitesErr = err
			break
		}
		sites = append(sites, mqlSpoSite)
	}
	r.SpoSites = plugin.TValue[[]any]{Data: sites, State: plugin.StateIsSet, Error: sitesErr}

	r.DefaultLinkPermission = plugin.TValue[string]{Data: report.DefaultLinkPermission, State: plugin.StateIsSet}

	r.fetched = true
	return nil
}

func (r *mqlMs365Sharepointonline) spoTenant() (any, error) {
	return nil, r.getSharepointOnlineReport()
}

func (r *mqlMs365Sharepointonline) tenantConfiguration() (*mqlMs365SharepointonlineTenantConfig, error) {
	return nil, r.getSharepointOnlineReport()
}

func (r *mqlMs365Sharepointonline) spoTenantSyncClientRestriction() (any, error) {
	return nil, r.getSharepointOnlineReport()
}

func (r *mqlMs365Sharepointonline) spoSites() ([]any, error) {
	return nil, r.getSharepointOnlineReport()
}

func (r *mqlMs365Sharepointonline) defaultLinkPermission() (string, error) {
	return "", r.getSharepointOnlineReport()
}
