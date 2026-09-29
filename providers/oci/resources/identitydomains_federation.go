// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// ----- identity providers -----

func (o *mqlOciIdentityDomain) identityProviders() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	providers, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.IdentityProvider, *int, error) {
		response, err := client.ListIdentityProviders(ctx, identitydomains.ListIdentityProvidersRequest{
			StartIndex:    common.Int(startIndex),
			Count:         common.Int(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "identity providers")
		}
		return response.IdentityProviders.Resources, response.IdentityProviders.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(providers))
	for i := range providers {
		mqlProvider, err := CreateResource(o.MqlRuntime, "oci.identity.domain.identityProvider", ociIdentityProviderArgs(o.Id.Data, &providers[i]))
		if err != nil {
			return nil, err
		}
		provider := mqlProvider.(*mqlOciIdentityDomainIdentityProvider)
		provider.domain = o
		provider.cacheAssignedGroups = providers[i].JitUserProvAssignedGroups
		res = append(res, provider)
	}
	return res, nil
}

// ociIdentityProviderArgs maps an identity provider onto its resource fields.
//
// Deliberately absent: the social extension, which carries the OAuth client
// secret the domain uses with the social provider, and the raw signing and
// encryption certificates and SAML metadata, which are large blobs that answer
// no configuration question. Booleans the service leaves unset stay null
// rather than reading as a setting that is switched off.
func ociIdentityProviderArgs(domainID string, p *identitydomains.IdentityProvider) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                           llx.StringData(domainID + "/identityProvider/" + stringValue(p.Id)),
		"id":                             llx.StringDataPtr(p.Id),
		"ocid":                           llx.StringDataPtr(p.Ocid),
		"name":                           llx.StringDataPtr(p.PartnerName),
		"description":                    llx.StringDataPtr(p.Description),
		"enabled":                        llx.BoolDataPtr(p.Enabled),
		"type":                           llx.StringData(string(p.Type)),
		"shownOnLoginPage":               llx.BoolDataPtr(p.ShownOnLoginPage),
		"partnerProviderId":              llx.StringDataPtr(p.PartnerProviderId),
		"tenantProviderId":               llx.StringDataPtr(p.TenantProviderId),
		"idpSsoUrl":                      llx.StringDataPtr(p.IdpSsoUrl),
		"signatureHashAlgorithm":         llx.StringData(string(p.SignatureHashAlgorithm)),
		"requiresEncryptedAssertion":     llx.BoolDataPtr(p.RequiresEncryptedAssertion),
		"requireForceAuthn":              llx.BoolDataPtr(p.RequireForceAuthn),
		"samlHoKRequired":                llx.BoolDataPtr(p.SamlHoKRequired),
		"includeSigningCertInSignature":  llx.BoolDataPtr(p.IncludeSigningCertInSignature),
		"authnRequestBinding":            llx.StringData(string(p.AuthnRequestBinding)),
		"logoutEnabled":                  llx.BoolDataPtr(p.LogoutEnabled),
		"nameIdFormat":                   llx.StringDataPtr(p.NameIdFormat),
		"requestedAuthenticationContext": llx.ArrayData(stringsToAny(p.RequestedAuthenticationContext), types.String),
		"userMappingMethod":              llx.StringData(string(p.UserMappingMethod)),
		"userMappingStoreAttribute":      llx.StringDataPtr(p.UserMappingStoreAttribute),
		"assertionAttribute":             llx.StringDataPtr(p.AssertionAttribute),

		"jitUserProvEnabled":                        llx.BoolDataPtr(p.JitUserProvEnabled),
		"jitUserProvCreateUserEnabled":              llx.BoolDataPtr(p.JitUserProvCreateUserEnabled),
		"jitUserProvAttributeUpdateEnabled":         llx.BoolDataPtr(p.JitUserProvAttributeUpdateEnabled),
		"jitUserProvGroupAssertionAttributeEnabled": llx.BoolDataPtr(p.JitUserProvGroupAssertionAttributeEnabled),
		"jitUserProvGroupStaticListEnabled":         llx.BoolDataPtr(p.JitUserProvGroupStaticListEnabled),
		"jitUserProvGroupAssignmentMethod":          llx.StringData(string(p.JitUserProvGroupAssignmentMethod)),
		"jitUserProvGroupMappingMode":               llx.StringData(string(p.JitUserProvGroupMappingMode)),
		"jitUserProvGroupSAMLAttributeName":         llx.StringDataPtr(p.JitUserProvGroupSAMLAttributeName),

		"created": llx.TimeDataPtr(ociScimCreatedAt(p.Meta)),
	}
}

type mqlOciIdentityDomainIdentityProviderInternal struct {
	domain              *mqlOciIdentityDomain
	cacheAssignedGroups []identitydomains.IdentityProviderJitUserProvAssignedGroups
}

// jitUserProvAssignedGroups resolves the fixed groups the provider adds every
// provisioned user to against the domain's own group list. The reference
// carries only the group's SCIM id, so there is no OCID to match on.
func (o *mqlOciIdentityDomainIdentityProvider) jitUserProvAssignedGroups() ([]any, error) {
	if len(o.cacheAssignedGroups) == 0 || o.domain == nil {
		return []any{}, nil
	}
	groups := o.domain.GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	res := make([]any, 0, len(o.cacheAssignedGroups))
	for _, ref := range o.cacheAssignedGroups {
		if g := ociGroupFromList(groups.Data, "", stringValue(ref.Value)); g != nil {
			res = append(res, g)
		}
	}
	return res, nil
}

// ----- domain settings -----

// setting reads the domain's settings record.
//
// A domain has exactly one, but the API only offers it as a list, so the
// single member is picked out here, the same way the keep-me-signed-in
// settings are. A domain that returns none reports nil, and every field below
// then reads null: nothing was read, so nothing is claimed.
func (o *mqlOciIdentityDomain) setting() (*identitydomains.Setting, error) {
	return o.settings.get(func() (*identitydomains.Setting, error) {
		client, err := o.domainClient()
		if err != nil {
			return nil, err
		}

		response, err := client.ListSettings(context.Background(), identitydomains.ListSettingsRequest{
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, ociScimError(err, o.Name.Data, "settings")
		}
		if len(response.Settings.Resources) == 0 {
			return nil, nil
		}
		return &response.Settings.Resources[0], nil
	})
}

// ociSettingBool reports one of the domain's boolean settings, null when the
// domain has no settings record or leaves the flag unset.
func ociSettingBool(setting *identitydomains.Setting, field *plugin.TValue[bool], value func(*identitydomains.Setting) *bool) bool {
	if setting == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false
	}
	v := value(setting)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false
	}
	return *v
}

// ociSettingInt is ociSettingBool for integer settings.
func ociSettingInt(setting *identitydomains.Setting, field *plugin.TValue[int64], value func(*identitydomains.Setting) *int) int64 {
	if setting == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0
	}
	v := value(setting)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0
	}
	return int64(*v)
}

func (o *mqlOciIdentityDomain) signingCertPublicAccess() (bool, error) {
	setting, err := o.setting()
	if err != nil {
		return false, err
	}
	return ociSettingBool(setting, &o.SigningCertPublicAccess, func(s *identitydomains.Setting) *bool {
		return s.SigningCertPublicAccess
	}), nil
}

func (o *mqlOciIdentityDomain) reAuthWhenChangingMyAuthenticationFactors() (bool, error) {
	setting, err := o.setting()
	if err != nil {
		return false, err
	}
	return ociSettingBool(setting, &o.ReAuthWhenChangingMyAuthenticationFactors, func(s *identitydomains.Setting) *bool {
		return s.ReAuthWhenChangingMyAuthenticationFactors
	}), nil
}

func (o *mqlOciIdentityDomain) reAuthFactors() ([]any, error) {
	setting, err := o.setting()
	if err != nil {
		return nil, err
	}
	if setting == nil {
		o.ReAuthFactors.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := make([]any, 0, len(setting.ReAuthFactor))
	for _, f := range setting.ReAuthFactor {
		res = append(res, string(f))
	}
	return res, nil
}

func (o *mqlOciIdentityDomain) customerSupportAccess() (string, error) {
	setting, err := o.setting()
	if err != nil {
		return "", err
	}
	if setting == nil {
		o.CustomerSupportAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(setting.CsrAccess), nil
}

func (o *mqlOciIdentityDomain) auditEventRetentionPeriodInDays() (int64, error) {
	setting, err := o.setting()
	if err != nil {
		return 0, err
	}
	return ociSettingInt(setting, &o.AuditEventRetentionPeriodInDays, func(s *identitydomains.Setting) *int {
		return s.AuditEventRetentionPeriod
	}), nil
}

func (o *mqlOciIdentityDomain) serviceAdminCannotListOtherUsers() (bool, error) {
	setting, err := o.setting()
	if err != nil {
		return false, err
	}
	return ociSettingBool(setting, &o.ServiceAdminCannotListOtherUsers, func(s *identitydomains.Setting) *bool {
		return s.ServiceAdminCannotListOtherUsers
	}), nil
}

func (o *mqlOciIdentityDomain) userPrincipalSessionTokenMaxExpiry() (int64, error) {
	setting, err := o.setting()
	if err != nil {
		return 0, err
	}
	return ociSettingInt(setting, &o.UserPrincipalSessionTokenMaxExpiry, func(s *identitydomains.Setting) *int {
		return s.IamUpstSessionExpiry
	}), nil
}
