// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (s *mqlJamfSsoSettings) id() (string, error) {
	return "jamf.ssoSettings", nil
}

func (r *mqlJamf) sso() (*mqlJamfSsoSettings, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)

	info, err := conn.Client.GetSsoSettings()
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "jamf.ssoSettings", ssoSettingsArgs(info))
	if err != nil {
		return nil, err
	}
	return res.(*mqlJamfSsoSettings), nil
}

// ssoSettingsArgs builds the CreateResource argument map from the SDK
// response. As of go-api-sdk-jamfpro v1.47.0, the protocol-specific
// settings live in separate optional sub-structs: SamlSettings is nil when
// the tenant is OIDC-only, OidcSettings is nil when SAML-only. Fields that
// come from the absent sub-struct surface as null rather than as silently
// zero-filled "0"/"false"/"".
func ssoSettingsArgs(info *jamfpro.ResourceSsoSettings) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                          llx.StringData("jamf.ssoSettings"),
		"ssoEnabled":                    llx.BoolData(info.SsoEnabled),
		"configurationType":             llx.StringData(info.ConfigurationType),
		"ssoForEnrollmentEnabled":       llx.BoolData(info.SsoForEnrollmentEnabled),
		"ssoBypassAllowed":              llx.BoolData(info.SsoBypassAllowed),
		"ssoForMacOsSelfServiceEnabled": llx.BoolData(info.SsoForMacOsSelfServiceEnabled),
		"enrollmentSsoForAccountDrivenEnrollmentEnabled": llx.BoolData(info.EnrollmentSsoForAccountDrivenEnrollmentEnabled),
		"groupEnrollmentAccessEnabled":                   llx.BoolData(info.GroupEnrollmentAccessEnabled),
	}

	if saml := info.SamlSettings; saml != nil {
		args["sessionTimeout"] = llx.IntData(saml.SessionTimeout)
		args["tokenExpirationDisabled"] = llx.BoolData(saml.TokenExpirationDisabled)
		args["userAttributeEnabled"] = llx.BoolData(saml.UserAttributeEnabled)
		args["userAttributeName"] = llx.StringData(saml.UserAttributeName)
		args["userMapping"] = llx.StringData(saml.UserMapping)
		args["idpUrl"] = llx.StringData(saml.IdpUrl)
		args["idpProviderType"] = llx.StringData(saml.IdpProviderType)
		args["groupAttributeName"] = llx.StringData(saml.GroupAttributeName)
		args["entityId"] = llx.StringData(saml.EntityId)
	} else {
		args["sessionTimeout"] = llx.NilData
		args["tokenExpirationDisabled"] = llx.NilData
		args["userAttributeEnabled"] = llx.NilData
		args["userAttributeName"] = llx.NilData
		args["userMapping"] = llx.NilData
		args["idpUrl"] = llx.NilData
		args["idpProviderType"] = llx.NilData
		args["groupAttributeName"] = llx.NilData
		args["entityId"] = llx.NilData
	}

	if oidc := info.OidcSettings; oidc != nil {
		args["oidcUserMapping"] = llx.StringData(oidc.UserMapping)
		args["oidcJamfIdAuthenticationEnabled"] = llx.BoolDataPtr(oidc.JamfIdAuthenticationEnabled)
		args["oidcUsernameAttributeClaimMapping"] = llx.StringData(oidc.UsernameAttributeClaimMapping)
	} else {
		args["oidcUserMapping"] = llx.NilData
		args["oidcJamfIdAuthenticationEnabled"] = llx.NilData
		args["oidcUsernameAttributeClaimMapping"] = llx.NilData
	}

	return args
}
