// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/types"
)

// samlFields are populated from SamlSettings; they must be null when the
// tenant has no SAML config.
var samlFields = []string{
	"sessionTimeout",
	"tokenExpirationDisabled",
	"userAttributeEnabled",
	"userAttributeName",
	"userMapping",
	"idpUrl",
	"idpProviderType",
	"groupAttributeName",
	"entityId",
}

// oidcFields are populated from OidcSettings; they must be null when the
// tenant has no OIDC config.
var oidcFields = []string{
	"oidcUserMapping",
	"oidcJamfIdAuthenticationEnabled",
	"oidcUsernameAttributeClaimMapping",
}

func TestSsoSettingsArgs_OidcOnly_NullsOutSamlFields(t *testing.T) {
	jamfId := true
	info := &jamfpro.ResourceSsoSettings{
		SsoEnabled:        true,
		ConfigurationType: "OIDC",
		SamlSettings:      nil,
		OidcSettings: &jamfpro.OidcSettings{
			UserMapping:                   "EMAIL",
			JamfIdAuthenticationEnabled:   &jamfId,
			UsernameAttributeClaimMapping: "preferred_username",
		},
	}

	args := ssoSettingsArgs(info)

	assert.Equal(t, "OIDC", args["configurationType"].Value, "configurationType must round-trip")
	for _, f := range samlFields {
		assert.Equal(t, types.Nil, args[f].Type,
			"SAML-derived field %q must be null when SamlSettings is nil — otherwise an OIDC-only tenant looks like a SAML tenant with empty values", f)
	}
	assert.Equal(t, "EMAIL", args["oidcUserMapping"].Value)
	assert.Equal(t, true, args["oidcJamfIdAuthenticationEnabled"].Value)
	assert.Equal(t, "preferred_username", args["oidcUsernameAttributeClaimMapping"].Value)
}

func TestSsoSettingsArgs_SamlOnly_NullsOutOidcFields(t *testing.T) {
	info := &jamfpro.ResourceSsoSettings{
		SsoEnabled:        true,
		ConfigurationType: "SAML",
		OidcSettings:      nil,
		SamlSettings: &jamfpro.SamlSettings{
			SessionTimeout:          30,
			TokenExpirationDisabled: false,
			UserAttributeEnabled:    true,
			UserAttributeName:       "uid",
			UserMapping:             "USERNAME",
			IdpUrl:                  "https://idp.example.com/saml",
			IdpProviderType:         "OKTA",
			GroupAttributeName:      "groups",
			EntityId:                "jamf-pro",
		},
	}

	args := ssoSettingsArgs(info)

	assert.Equal(t, "SAML", args["configurationType"].Value)
	assert.Equal(t, int64(30), args["sessionTimeout"].Value)
	assert.Equal(t, "OKTA", args["idpProviderType"].Value)
	assert.Equal(t, "jamf-pro", args["entityId"].Value)
	for _, f := range oidcFields {
		assert.Equal(t, types.Nil, args[f].Type,
			"OIDC-derived field %q must be null when OidcSettings is nil", f)
	}
}

func TestSsoSettingsArgs_BothPresent_PopulatesBoth(t *testing.T) {
	info := &jamfpro.ResourceSsoSettings{
		SsoEnabled:        true,
		ConfigurationType: "OIDC_WITH_SAML",
		SamlSettings: &jamfpro.SamlSettings{
			IdpProviderType: "AZURE",
		},
		OidcSettings: &jamfpro.OidcSettings{
			UserMapping: "USERNAME",
		},
	}

	args := ssoSettingsArgs(info)

	assert.Equal(t, "OIDC_WITH_SAML", args["configurationType"].Value)
	assert.Equal(t, "AZURE", args["idpProviderType"].Value)
	assert.Equal(t, "USERNAME", args["oidcUserMapping"].Value)
}

func TestSsoSettingsArgs_AlwaysSetsId(t *testing.T) {
	args := ssoSettingsArgs(&jamfpro.ResourceSsoSettings{})
	assert.Equal(t, "jamf.ssoSettings", args["__id"].Value)
}
