// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlKeycloakIdentityProviderInternal holds the realm the provider is
// configured for, which the flow accessor resolves against.
type mqlKeycloakIdentityProviderInternal struct {
	parentRealm *mqlKeycloakRealm
}

type identityProviderRecord struct {
	InternalID               string            `json:"internalId"`
	Alias                    string            `json:"alias"`
	DisplayName              string            `json:"displayName"`
	ProviderID               string            `json:"providerId"`
	Enabled                  bool              `json:"enabled"`
	TrustEmail               bool              `json:"trustEmail"`
	StoreToken               bool              `json:"storeToken"`
	AddReadTokenRoleOnCreate bool              `json:"addReadTokenRoleOnCreate"`
	LinkOnly                 bool              `json:"linkOnly"`
	HideOnLogin              bool              `json:"hideOnLogin"`
	FirstBrokerLoginFlow     string            `json:"firstBrokerLoginFlowAlias"`
	PostBrokerLoginFlow      string            `json:"postBrokerLoginFlowAlias"`
	Config                   map[string]string `json:"config"`
}

// Identity provider settings Keycloak keeps in the config map rather than as
// fields of the representation. Every value there is a string, so a boolean
// setting arrives as "true" or "false".
const (
	idpConfigValidateSignature = "validateSignature"
	idpConfigUseJwksURL        = "useJwksUrl"
	idpConfigHideOnLoginPage   = "hideOnLoginPage"
	idpConfigSyncMode          = "syncMode"
	idpConfigIssuer            = "issuer"
	idpConfigAuthorizationURL  = "authorizationUrl"
	idpConfigTokenURL          = "tokenUrl"
	idpConfigJwksURL           = "jwksUrl"
	idpConfigClientID          = "clientId"
	idpConfigClientAuthMethod  = "clientAuthMethod"
	idpConfigPkceEnabled       = "pkceEnabled"
	idpConfigDefaultScope      = "defaultScope"
)

func newKeycloakIdentityProvider(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *identityProviderRecord) (*mqlKeycloakIdentityProvider, error) {
	res, err := CreateResource(runtime, "keycloak.identityProvider", map[string]*llx.RawData{
		"__id":                     llx.StringData(realm.realmName() + "/idp/" + rec.Alias),
		"internalId":               llx.StringData(rec.InternalID),
		"alias":                    llx.StringData(rec.Alias),
		"displayName":              llx.StringData(rec.DisplayName),
		"providerId":               llx.StringData(rec.ProviderID),
		"enabled":                  llx.BoolData(rec.Enabled),
		"trustEmail":               llx.BoolData(rec.TrustEmail),
		"storeToken":               llx.BoolData(rec.StoreToken),
		"addReadTokenRoleOnCreate": llx.BoolData(rec.AddReadTokenRoleOnCreate),
		"linkOnly":                 llx.BoolData(rec.LinkOnly),
		"hideOnLoginPage":          llx.BoolData(HideOnLoginPage(rec)),
		"firstBrokerLoginFlow":     llx.StringData(rec.FirstBrokerLoginFlow),
		"postBrokerLoginFlow":      llx.StringData(rec.PostBrokerLoginFlow),
		"syncMode":                 llx.StringData(rec.Config[idpConfigSyncMode]),
		"validateSignature":        llx.BoolData(configBool(rec.Config[idpConfigValidateSignature])),
		"useJwksUrl":               llx.BoolData(configBool(rec.Config[idpConfigUseJwksURL])),
		"issuer":                   llx.StringData(rec.Config[idpConfigIssuer]),
		"authorizationUrl":         llx.StringData(rec.Config[idpConfigAuthorizationURL]),
		"tokenUrl":                 llx.StringData(rec.Config[idpConfigTokenURL]),
		"jwksUrl":                  llx.StringData(rec.Config[idpConfigJwksURL]),
		"clientId":                 llx.StringData(rec.Config[idpConfigClientID]),
		"clientAuthMethod":         llx.StringData(rec.Config[idpConfigClientAuthMethod]),
		"pkceEnabled":              llx.BoolData(configBool(rec.Config[idpConfigPkceEnabled])),
		"defaultScope":             llx.StringData(rec.Config[idpConfigDefaultScope]),
		"config":                   llx.MapData(mapStrToAny(rec.Config), types.String),
	})
	if err != nil {
		return nil, err
	}

	idp := res.(*mqlKeycloakIdentityProvider)
	idp.parentRealm = realm
	return idp, nil
}

// HideOnLoginPage reports whether the provider is kept off the login page.
// Keycloak moved the setting from the config map onto the representation
// itself, so both places are read and either one is enough.
func HideOnLoginPage(rec *identityProviderRecord) bool {
	return rec.HideOnLogin || configBool(rec.Config[idpConfigHideOnLoginPage])
}

func (i *mqlKeycloakIdentityProvider) id() (string, error) {
	return i.__id, nil
}

func (i *mqlKeycloakIdentityProvider) realm() (*mqlKeycloakRealm, error) {
	if i.parentRealm == nil {
		setNullResource(&i.Realm)
		return nil, nil
	}
	return i.parentRealm, nil
}

func (i *mqlKeycloakIdentityProvider) firstBrokerLoginFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	if i.parentRealm == nil {
		setNullResource(&i.FirstBrokerLoginFlowRef)
		return nil, nil
	}
	return i.parentRealm.flowByAlias(&i.FirstBrokerLoginFlowRef, i.FirstBrokerLoginFlow.Data)
}

func (i *mqlKeycloakIdentityProvider) postBrokerLoginFlowRef() (*mqlKeycloakAuthenticationFlow, error) {
	if i.parentRealm == nil {
		setNullResource(&i.PostBrokerLoginFlowRef)
		return nil, nil
	}
	return i.parentRealm.flowByAlias(&i.PostBrokerLoginFlowRef, i.PostBrokerLoginFlow.Data)
}
