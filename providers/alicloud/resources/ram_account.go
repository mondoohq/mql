// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"time"

	imsclient "github.com/alibabacloud-go/ims-20190815/v4/client"
	ramclient "github.com/alibabacloud-go/ram-20150501/v2/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ramAccountState memoizes the account-level identity reads served by IMS, so
// the four SSO fields share one GetUserSsoSettings call. It is embedded in
// mqlAlicloudRamInternal (ram_identity.go).
type ramAccountState struct {
	ssoOnce sync.Once
	sso     *imsclient.GetUserSsoSettingsResponseBodyUserSsoSettings
	ssoErr  error
}

// rootMfaEnabled reads whether the root identity has an MFA device bound.
func (r *mqlAlicloudRam) rootMfaEnabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ImsClient()
	if err != nil {
		return false, err
	}
	resp, err := client.GetAccountMFAInfo()
	if err != nil {
		return false, classifyAlicloudError(err, "ram:GetAccountMFAInfo")
	}
	if resp == nil || resp.Body == nil || resp.Body.IsMFAEnable == nil {
		r.RootMfaEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *resp.Body.IsMFAEnable, nil
}

// rootAccessKeyCount reads the number of access keys the root identity holds
// from the account's security practice report.
func (r *mqlAlicloudRam) rootAccessKeyCount() (int64, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ImsClient()
	if err != nil {
		return 0, err
	}
	resp, err := client.GetAccountSecurityPracticeReport()
	if err != nil {
		return 0, classifyAlicloudError(err, "ram:GetAccountSecurityPracticeReport")
	}
	count := rootAccessKeyCountFrom(resp)
	if count == nil {
		r.RootAccessKeyCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *count, nil
}

// rootAccessKeyCountFrom extracts the root access key count from a security
// practice report. A report without the value yields nil, so the field reads
// null rather than a zero that would claim the root identity holds no key.
func rootAccessKeyCountFrom(resp *imsclient.GetAccountSecurityPracticeReportResponse) *int64 {
	if resp == nil || resp.Body == nil || resp.Body.AccountSecurityPracticeInfo == nil {
		return nil
	}
	info := resp.Body.AccountSecurityPracticeInfo.AccountSecurityPracticeUserInfo
	if info == nil || info.RootWithAccessKey == nil {
		return nil
	}
	v := int64(*info.RootWithAccessKey)
	return &v
}

// ssoSettings reads the account's user-based SSO settings once. The metadata
// document is not exposed: it is the identity provider's signing certificate
// bundle and adds nothing an audit reads.
func (r *mqlAlicloudRam) ssoSettings() (*imsclient.GetUserSsoSettingsResponseBodyUserSsoSettings, error) {
	r.ssoOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.ImsClient()
		if err != nil {
			r.ssoErr = err
			return
		}
		resp, err := client.GetUserSsoSettings()
		if err != nil {
			r.ssoErr = classifyAlicloudError(err, "ram:GetUserSsoSettings")
			return
		}
		if resp != nil && resp.Body != nil {
			r.sso = resp.Body.UserSsoSettings
		}
	})
	return r.sso, r.ssoErr
}

func (r *mqlAlicloudRam) ssoEnabled() (bool, error) {
	s, err := r.ssoSettings()
	if err != nil {
		return false, err
	}
	if s == nil || s.SsoEnabled == nil {
		r.SsoEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.SsoEnabled, nil
}

func (r *mqlAlicloudRam) ssoLoginWithDomain() (bool, error) {
	s, err := r.ssoSettings()
	if err != nil {
		return false, err
	}
	if s == nil || s.SsoLoginWithDomain == nil {
		r.SsoLoginWithDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.SsoLoginWithDomain, nil
}

func (r *mqlAlicloudRam) ssoAuxiliaryDomain() (string, error) {
	s, err := r.ssoSettings()
	if err != nil {
		return "", err
	}
	if s == nil || s.AuxiliaryDomain == nil {
		r.SsoAuxiliaryDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.AuxiliaryDomain, nil
}

func (r *mqlAlicloudRam) ssoAuthnSignAlgorithm() (string, error) {
	s, err := r.ssoSettings()
	if err != nil {
		return "", err
	}
	if s == nil || s.AuthnSignAlgo == nil {
		r.SsoAuthnSignAlgorithm.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.AuthnSignAlgo, nil
}

// ramMarkerDone reports whether a marker-paged IMS listing is complete. A
// truncated page with no marker would repeat the same request forever, so it
// ends the walk too.
func ramMarkerDone(truncated *bool, marker *string) bool {
	return !tea.BoolValue(truncated) || tea.StringValue(marker) == ""
}

func (r *mqlAlicloudRam) samlProviders() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ImsClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &imsclient.ListSAMLProvidersRequest{MaxItems: tea.Int32(100)}
	for {
		resp, err := client.ListSAMLProviders(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "ram:ListSAMLProviders")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		if resp.Body.SAMLProviders != nil {
			for _, p := range resp.Body.SAMLProviders.SAMLProvider {
				if p == nil || tea.StringValue(p.SAMLProviderName) == "" {
					continue
				}
				mqlProvider, err := CreateResource(r.MqlRuntime, "alicloud.ram.samlProvider", map[string]*llx.RawData{
					"__id":             llx.StringData("alicloud.ram.samlProvider/" + tea.StringValue(p.SAMLProviderName)),
					"samlProviderName": llx.StringDataPtr(p.SAMLProviderName),
					"arn":              llx.StringDataPtr(p.Arn),
					"description":      llx.StringDataPtr(p.Description),
					"createDate":       llx.TimeDataPtr(parseAlicloudTime(p.CreateDate)),
					"updateDate":       llx.TimeDataPtr(parseAlicloudTime(p.UpdateDate)),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProvider)
			}
		}
		if ramMarkerDone(resp.Body.IsTruncated, resp.Body.Marker) {
			break
		}
		req.Marker = resp.Body.Marker
	}
	return res, nil
}

func (r *mqlAlicloudRam) oidcProviders() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ImsClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &imsclient.ListOIDCProvidersRequest{MaxItems: tea.Int32(100)}
	for {
		resp, err := client.ListOIDCProviders(req)
		if err != nil {
			return nil, classifyAlicloudError(err, "ram:ListOIDCProviders")
		}
		if resp == nil || resp.Body == nil {
			break
		}
		if resp.Body.OIDCProviders != nil {
			for _, p := range resp.Body.OIDCProviders.OIDCProvider {
				if p == nil || tea.StringValue(p.OIDCProviderName) == "" {
					continue
				}
				mqlProvider, err := newRamOidcProvider(r.MqlRuntime, p)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProvider)
			}
		}
		if ramMarkerDone(resp.Body.IsTruncated, resp.Body.Marker) {
			break
		}
		req.Marker = resp.Body.Marker
	}
	return res, nil
}

func newRamOidcProvider(runtime *plugin.Runtime, p *imsclient.ListOIDCProvidersResponseBodyOIDCProvidersOIDCProvider) (plugin.Resource, error) {
	// IMS reports both CreateDate and GmtCreate; the Gmt* pair is the newer
	// spelling and is read when the older one is absent
	created := parseAlicloudTime(p.CreateDate)
	if created == nil {
		created = parseAlicloudTime(p.GmtCreate)
	}
	updated := parseAlicloudTime(p.UpdateDate)
	if updated == nil {
		updated = parseAlicloudTime(p.GmtModified)
	}
	return CreateResource(runtime, "alicloud.ram.oidcProvider", map[string]*llx.RawData{
		"__id":              llx.StringData("alicloud.ram.oidcProvider/" + tea.StringValue(p.OIDCProviderName)),
		"oidcProviderName":  llx.StringDataPtr(p.OIDCProviderName),
		"arn":               llx.StringDataPtr(p.Arn),
		"description":       llx.StringDataPtr(p.Description),
		"issuerUrl":         llx.StringDataPtr(p.IssuerUrl),
		"clientIds":         llx.ArrayData(stringsToAny(splitCommaList(p.ClientIds)), types.String),
		"fingerprints":      llx.ArrayData(stringsToAny(splitCommaList(p.Fingerprints)), types.String),
		"issuanceLimitTime": llx.IntDataPtr(p.IssuanceLimitTime),
		"createDate":        llx.TimeDataPtr(created),
		"updateDate":        llx.TimeDataPtr(updated),
	})
}

// lastUsedDate reads when the access key last called an API. A key that has
// never been used reads null.
func (r *mqlAlicloudRamAccessKey) lastUsedDate() (*time.Time, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetAccessKeyLastUsed(&ramclient.GetAccessKeyLastUsedRequest{
		UserName:        tea.String(r.UserName.Data),
		UserAccessKeyId: tea.String(r.AccessKeyId.Data),
	})
	if err != nil {
		return nil, classifyAlicloudError(err, "ram:GetAccessKeyLastUsed")
	}
	var last *time.Time
	if resp != nil && resp.Body != nil && resp.Body.AccessKeyLastUsed != nil {
		last = parseAlicloudTime(resp.Body.AccessKeyLastUsed.LastUsedDate)
	}
	if last == nil {
		r.LastUsedDate.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return last, nil
}
