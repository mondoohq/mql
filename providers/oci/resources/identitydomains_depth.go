// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- identity and account recovery settings ----

func (o *mqlOciIdentityDomain) identitySettingRecord() (*identitydomains.IdentitySetting, error) {
	return o.identitySetting.get(func() (*identitydomains.IdentitySetting, error) {
		client, err := o.domainClient()
		if err != nil {
			return nil, err
		}
		response, err := client.ListIdentitySettings(context.Background(), identitydomains.ListIdentitySettingsRequest{
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, ociScimError(err, o.Name.Data, "identity settings")
		}
		if len(response.IdentitySettings.Resources) == 0 {
			return nil, nil
		}
		return &response.IdentitySettings.Resources[0], nil
	})
}

// identitySettingBool reads one switch of the identity settings, null when
// the domain reports no settings record or leaves the switch unset.
func (o *mqlOciIdentityDomain) identitySettingBool(field *plugin.TValue[bool], pick func(*identitydomains.IdentitySetting) *bool) (bool, error) {
	setting, err := o.identitySettingRecord()
	if err != nil {
		return false, err
	}
	var v *bool
	if setting != nil {
		v = pick(setting)
	}
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

func (o *mqlOciIdentityDomain) primaryEmailRequired() (bool, error) {
	return o.identitySettingBool(&o.PrimaryEmailRequired, func(s *identitydomains.IdentitySetting) *bool { return s.PrimaryEmailRequired })
}

func (o *mqlOciIdentityDomain) userAllowedToSetRecoveryEmail() (bool, error) {
	return o.identitySettingBool(&o.UserAllowedToSetRecoveryEmail, func(s *identitydomains.IdentitySetting) *bool { return s.UserAllowedToSetRecoveryEmail })
}

func myProfile(s *identitydomains.IdentitySetting) *identitydomains.IdentitySettingsMyProfile {
	if s.MyProfile == nil {
		return &identitydomains.IdentitySettingsMyProfile{}
	}
	return s.MyProfile
}

func (o *mqlOciIdentityDomain) endUsersCanChangePassword() (bool, error) {
	return o.identitySettingBool(&o.EndUsersCanChangePassword, func(s *identitydomains.IdentitySetting) *bool {
		return myProfile(s).AllowEndUsersToChangeTheirPassword
	})
}

func (o *mqlOciIdentityDomain) endUsersCanUpdateSecuritySettings() (bool, error) {
	return o.identitySettingBool(&o.EndUsersCanUpdateSecuritySettings, func(s *identitydomains.IdentitySetting) *bool {
		return myProfile(s).AllowEndUsersToUpdateTheirSecuritySettings
	})
}

func (o *mqlOciIdentityDomain) endUsersCanManageCapabilities() (bool, error) {
	return o.identitySettingBool(&o.EndUsersCanManageCapabilities, func(s *identitydomains.IdentitySetting) *bool {
		return myProfile(s).AllowEndUsersToManageTheirCapabilities
	})
}

func (o *mqlOciIdentityDomain) recoverySetting() (*identitydomains.AccountRecoverySetting, error) {
	return o.recovery.get(func() (*identitydomains.AccountRecoverySetting, error) {
		client, err := o.domainClient()
		if err != nil {
			return nil, err
		}
		response, err := client.ListAccountRecoverySettings(context.Background(), identitydomains.ListAccountRecoverySettingsRequest{
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, ociScimError(err, o.Name.Data, "account recovery settings")
		}
		if len(response.AccountRecoverySettings.Resources) == 0 {
			return nil, nil
		}
		return &response.AccountRecoverySettings.Resources[0], nil
	})
}

func (o *mqlOciIdentityDomain) accountRecoveryFactors() ([]any, error) {
	setting, err := o.recoverySetting()
	if err != nil {
		return nil, err
	}
	out := []any{}
	if setting != nil {
		for _, f := range setting.Factors {
			out = append(out, string(f))
		}
	}
	return out, nil
}

func optionalIntField(v *int, field *plugin.TValue[int64]) (int64, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*v), nil
}

func (o *mqlOciIdentityDomain) accountRecoveryMaxIncorrectAttempts() (int64, error) {
	setting, err := o.recoverySetting()
	if err != nil {
		return 0, err
	}
	var v *int
	if setting != nil {
		v = setting.MaxIncorrectAttempts
	}
	return optionalIntField(v, &o.AccountRecoveryMaxIncorrectAttempts)
}

func (o *mqlOciIdentityDomain) accountRecoveryLockoutDuration() (int64, error) {
	setting, err := o.recoverySetting()
	if err != nil {
		return 0, err
	}
	var v *int
	if setting != nil {
		v = setting.LockoutDuration
	}
	return optionalIntField(v, &o.AccountRecoveryLockoutDuration)
}

// ---- user credentials ----

// ociDomainCredential is one user credential of any type, without its secret.
type ociDomainCredential struct {
	id, ocid, typ, name, status, fingerprint string
	created, expires                         *time.Time
	userID, userOcid                         string
}

func ociScimCreated(meta *identitydomains.Meta) *time.Time {
	if meta == nil {
		return nil
	}
	return ociScimTime(meta.Created)
}

func firstNonEmpty(values ...*string) string {
	for _, v := range values {
		if v != nil && *v != "" {
			return *v
		}
	}
	return ""
}

func apiKeyCredential(k identitydomains.ApiKey) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(k.Id), ocid: stringValue(k.Ocid), typ: "apiKey",
		name: stringValue(k.Description), fingerprint: stringValue(k.Fingerprint),
		created: ociScimCreated(k.Meta),
	}
	if k.User != nil {
		c.userID, c.userOcid = stringValue(k.User.Value), stringValue(k.User.Ocid)
	}
	return c
}

func authTokenCredential(t identitydomains.AuthToken) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(t.Id), ocid: stringValue(t.Ocid), typ: "authToken",
		name: stringValue(t.Description), status: string(t.Status),
		created: ociScimCreated(t.Meta), expires: ociScimTime(t.ExpiresOn),
	}
	if t.User != nil {
		c.userID, c.userOcid = stringValue(t.User.Value), stringValue(t.User.Ocid)
	}
	return c
}

func customerSecretKeyCredential(k identitydomains.CustomerSecretKey) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(k.Id), ocid: stringValue(k.Ocid), typ: "customerSecretKey",
		name: firstNonEmpty(k.DisplayName, k.Description), status: string(k.Status),
		created: ociScimCreated(k.Meta), expires: ociScimTime(k.ExpiresOn),
	}
	if k.User != nil {
		c.userID, c.userOcid = stringValue(k.User.Value), stringValue(k.User.Ocid)
	}
	return c
}

func oauth2ClientCredential(k identitydomains.OAuth2ClientCredential) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(k.Id), ocid: stringValue(k.Ocid), typ: "oauth2ClientCredential",
		name: firstNonEmpty(k.Name, k.Description), status: string(k.Status),
		created: ociScimCreated(k.Meta), expires: ociScimTime(k.ExpiresOn),
	}
	if k.User != nil {
		c.userID, c.userOcid = stringValue(k.User.Value), stringValue(k.User.Ocid)
	}
	return c
}

func smtpCredential(k identitydomains.SmtpCredential) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(k.Id), ocid: stringValue(k.Ocid), typ: "smtpCredential",
		name: firstNonEmpty(k.UserName, k.Description), status: string(k.Status),
		created: ociScimCreated(k.Meta), expires: ociScimTime(k.ExpiresOn),
	}
	if k.User != nil {
		c.userID, c.userOcid = stringValue(k.User.Value), stringValue(k.User.Ocid)
	}
	return c
}

func dbCredential(k identitydomains.UserDbCredential) ociDomainCredential {
	c := ociDomainCredential{
		id: stringValue(k.Id), ocid: stringValue(k.Ocid), typ: "dbCredential",
		name: firstNonEmpty(k.Name, k.Description), status: string(k.Status),
		created: ociScimCreated(k.Meta), expires: ociScimTime(k.ExpiresOn),
	}
	if k.User != nil {
		c.userID, c.userOcid = stringValue(k.User.Value), stringValue(k.User.Ocid)
	}
	return c
}

// userCredentials lists one user's credentials, one listing per credential
// type. The credential APIs refuse to list a whole domain (400
// BadErrorResponse) and answer only with a filter on the user, so this is
// read per user, and only when the field is queried.
func (o *mqlOciIdentityDomain) userCredentials(userID string) ([]ociDomainCredential, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	filter := common.String(ociScimUserFilter(userID))
	var all []ociDomainCredential

	apiKeys, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.ApiKey, *int, error) {
		r, err := client.ListApiKeys(ctx, identitydomains.ListApiKeysRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "API keys")
		}
		return r.ApiKeys.Resources, r.ApiKeys.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range apiKeys {
		all = append(all, apiKeyCredential(k))
	}

	tokens, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.AuthToken, *int, error) {
		r, err := client.ListAuthTokens(ctx, identitydomains.ListAuthTokensRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "auth tokens")
		}
		return r.AuthTokens.Resources, r.AuthTokens.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		all = append(all, authTokenCredential(t))
	}

	secretKeys, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.CustomerSecretKey, *int, error) {
		r, err := client.ListCustomerSecretKeys(ctx, identitydomains.ListCustomerSecretKeysRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "customer secret keys")
		}
		return r.CustomerSecretKeys.Resources, r.CustomerSecretKeys.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range secretKeys {
		all = append(all, customerSecretKeyCredential(k))
	}

	oauth, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.OAuth2ClientCredential, *int, error) {
		r, err := client.ListOAuth2ClientCredentials(ctx, identitydomains.ListOAuth2ClientCredentialsRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "OAuth 2.0 client credentials")
		}
		return r.OAuth2ClientCredentials.Resources, r.OAuth2ClientCredentials.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range oauth {
		all = append(all, oauth2ClientCredential(k))
	}

	smtp, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.SmtpCredential, *int, error) {
		r, err := client.ListSmtpCredentials(ctx, identitydomains.ListSmtpCredentialsRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "SMTP credentials")
		}
		return r.SmtpCredentials.Resources, r.SmtpCredentials.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range smtp {
		all = append(all, smtpCredential(k))
	}

	db, err := ociScimPaginate(ctx, func(ctx context.Context, start int) ([]identitydomains.UserDbCredential, *int, error) {
		r, err := client.ListUserDbCredentials(ctx, identitydomains.ListUserDbCredentialsRequest{Filter: filter, StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "database credentials")
		}
		return r.UserDbCredentials.Resources, r.UserDbCredentials.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range db {
		all = append(all, dbCredential(k))
	}
	return all, nil
}

// ociScimUserFilter is the SCIM filter selecting the credentials of one user.
// The id is quoted, with any quote or backslash in it escaped.
func ociScimUserFilter(userID string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(userID)
	return `user.value eq "` + escaped + `"`
}

func (o *mqlOciIdentityDomainUser) credentials() ([]any, error) {
	if o.cacheDomain == nil {
		return []any{}, nil
	}
	creds, err := o.cacheDomain.userCredentials(o.Id.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(creds))
	for i, c := range creds {
		m, err := CreateResource(o.MqlRuntime, "oci.identity.domain.user.credential", map[string]*llx.RawData{
			"__id":        llx.StringData(o.cacheDomain.Id.Data + "/" + c.typ + "/" + rowKey(c.id, i)),
			"id":          llx.StringData(c.id),
			"ocid":        llx.StringData(c.ocid),
			"type":        llx.StringData(c.typ),
			"name":        llx.StringData(c.name),
			"status":      llx.StringData(c.status),
			"fingerprint": llx.StringData(c.fingerprint),
			"created":     llx.TimeDataPtr(c.created),
			"expiresOn":   llx.TimeDataPtr(c.expires),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- dynamic resource groups and social identity providers ----

func (o *mqlOciIdentityDomain) dynamicResourceGroups() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}
	groups, err := ociScimPaginate(context.Background(), func(ctx context.Context, start int) ([]identitydomains.DynamicResourceGroup, *int, error) {
		r, err := client.ListDynamicResourceGroups(ctx, identitydomains.ListDynamicResourceGroupsRequest{StartIndex: common.Int(start), Count: common.Int(ociScimPageSize), AttributeSets: ociScimAttributeSets})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "dynamic resource groups")
		}
		return r.DynamicResourceGroups.Resources, r.DynamicResourceGroups.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(groups))
	for i, g := range groups {
		m, err := CreateResource(o.MqlRuntime, "oci.identity.domain.dynamicResourceGroup", map[string]*llx.RawData{
			"__id":         llx.StringData(o.Id.Data + "/dynamicResourceGroup/" + rowKey(stringValue(g.Id), i)),
			"id":           llx.StringDataPtr(g.Id),
			"ocid":         llx.StringData(stringValue(g.Ocid)),
			"displayName":  llx.StringDataPtr(g.DisplayName),
			"description":  llx.StringData(stringValue(g.Description)),
			"matchingRule": llx.StringDataPtr(g.MatchingRule),
			"created":      llx.TimeDataPtr(ociScimCreated(g.Meta)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (o *mqlOciIdentityDomain) socialIdentityProviders() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}
	providers, err := ociScimPaginate(context.Background(), func(ctx context.Context, start int) ([]identitydomains.SocialIdentityProvider, *int, error) {
		r, err := client.ListSocialIdentityProviders(ctx, identitydomains.ListSocialIdentityProvidersRequest{StartIndex: common.Int(start), Count: common.Int(ociScimPageSize)})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "social identity providers")
		}
		return r.SocialIdentityProviders.Resources, r.SocialIdentityProviders.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(providers))
	for i, p := range providers {
		m, err := CreateResource(o.MqlRuntime, "oci.identity.domain.socialIdentityProvider", socialIdentityProviderArgs(o.Id.Data, i, p))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// socialIdentityProviderArgs maps a provider without its consumer secret.
func socialIdentityProviderArgs(domainID string, index int, p identitydomains.SocialIdentityProvider) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(domainID + "/socialIdentityProvider/" + rowKey(stringValue(p.Id), index)),
		"id":                     llx.StringDataPtr(p.Id),
		"name":                   llx.StringDataPtr(p.Name),
		"serviceProviderName":    llx.StringData(stringValue(p.ServiceProviderName)),
		"enabled":                llx.BoolData(boolValue(p.Enabled)),
		"showOnLogin":            llx.BoolData(boolValue(p.ShowOnLogin)),
		"registrationEnabled":    llx.BoolData(boolValue(p.RegistrationEnabled)),
		"accountLinkingEnabled":  llx.BoolData(boolValue(p.AccountLinkingEnabled)),
		"jitProvisioningEnabled": llx.BoolData(boolValue(p.SocialJitProvisioningEnabled)),
		"status":                 llx.StringData(string(p.Status)),
	}
}
