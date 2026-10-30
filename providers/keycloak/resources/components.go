// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlKeycloakComponentInternal holds the realm the component belongs to.
type mqlKeycloakComponentInternal struct {
	parentRealm *mqlKeycloakRealm
}

type componentRecord struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId"`
	SubType      string              `json:"subType"`
	Config       map[string][]string `json:"config"`
}

// userStorageProviderType is the interface a user federation provider
// implements, which is what separates a directory federation from a key
// provider or a mapper.
const userStorageProviderType = "org.keycloak.storage.UserStorageProvider"

// LDAP federation settings Keycloak keeps in the component config.
const (
	componentConfigConnectionURL          = "connectionUrl"
	componentConfigStartTLS               = "startTls"
	componentConfigUseTruststoreSpi       = "useTruststoreSpi"
	componentConfigBindDn                 = "bindDn"
	componentConfigUsersDn                = "usersDn"
	componentConfigAuthType               = "authType"
	componentConfigEditMode               = "editMode"
	componentConfigVendor                 = "vendor"
	componentConfigValidatePasswordPolicy = "validatePasswordPolicy"
	componentConfigTrustEmail             = "trustEmail"
)

func newKeycloakComponent(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *componentRecord) (*mqlKeycloakComponent, error) {
	connectionURL := firstConfigValue(rec.Config, componentConfigConnectionURL)
	startTLS := configBool(firstConfigValue(rec.Config, componentConfigStartTLS))

	res, err := CreateResource(runtime, "keycloak.component", map[string]*llx.RawData{
		"__id":                   llx.StringData(realm.realmName() + "/component/" + rec.ID),
		"id":                     llx.StringData(rec.ID),
		"name":                   llx.StringData(rec.Name),
		"providerId":             llx.StringData(rec.ProviderID),
		"providerType":           llx.StringData(rec.ProviderType),
		"parentId":               llx.StringData(rec.ParentID),
		"subType":                llx.StringData(rec.SubType),
		"config":                 llx.DictData(multiMapToDict(rec.Config)),
		"isUserFederation":       llx.BoolData(rec.ProviderType == userStorageProviderType),
		"connectionUrl":          llx.StringData(connectionURL),
		"startTls":               llx.BoolData(startTLS),
		"connectionEncrypted":    llx.BoolData(ConnectionEncrypted(connectionURL, startTLS)),
		"useTruststoreSpi":       llx.StringData(firstConfigValue(rec.Config, componentConfigUseTruststoreSpi)),
		"bindDn":                 llx.StringData(firstConfigValue(rec.Config, componentConfigBindDn)),
		"usersDn":                llx.StringData(firstConfigValue(rec.Config, componentConfigUsersDn)),
		"authType":               llx.StringData(firstConfigValue(rec.Config, componentConfigAuthType)),
		"editMode":               llx.StringData(firstConfigValue(rec.Config, componentConfigEditMode)),
		"vendor":                 llx.StringData(firstConfigValue(rec.Config, componentConfigVendor)),
		"validatePasswordPolicy": llx.BoolData(configBool(firstConfigValue(rec.Config, componentConfigValidatePasswordPolicy))),
		"trustEmail":             llx.BoolData(configBool(firstConfigValue(rec.Config, componentConfigTrustEmail))),
	})
	if err != nil {
		return nil, err
	}

	component := res.(*mqlKeycloakComponent)
	component.parentRealm = realm
	return component, nil
}

// ConnectionEncrypted reports whether a directory connection is protected. An
// ldaps URL is encrypted from the start, and StartTLS upgrades a plaintext one
// after it opens. A component that names no directory reports false, and its
// isUserFederation field is what tells the two cases apart.
func ConnectionEncrypted(connectionURL string, startTLS bool) bool {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(connectionURL)), "ldaps://") {
		return true
	}
	return connectionURL != "" && startTLS
}

func (c *mqlKeycloakComponent) id() (string, error) {
	return c.__id, nil
}

func (c *mqlKeycloakComponent) realm() (*mqlKeycloakRealm, error) {
	if c.parentRealm == nil {
		setNullResource(&c.Realm)
		return nil, nil
	}
	return c.parentRealm, nil
}
