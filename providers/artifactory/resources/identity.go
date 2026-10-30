// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// ldapsScheme marks an LDAP URL whose transport is encrypted.
const ldapsScheme = "ldaps://"

type mqlArtifactorySecuritySettingsInternal struct {
	// config is the decoded instance descriptor the settings were built from.
	// The identity integrations are read from it rather than fetched again.
	config *securityConfig
}

type mqlArtifactoryLdapGroupSettingInternal struct {
	// serverName is the name of the LDAP server the mapping applies to. It is a
	// configuration name, not a credential.
	serverName string
}

// --- LDAP -----------------------------------------------------------------

func (s *mqlArtifactorySecuritySettings) ldapSettings() ([]any, error) {
	if s.config == nil {
		return []any{}, nil
	}

	records := s.config.Security.LdapSettings
	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		created, err := CreateResource(s.MqlRuntime, "artifactory.ldapSetting", map[string]*llx.RawData{
			"key":                      llx.StringData(rec.Key),
			"enabled":                  llx.BoolData(boolValue(rec.Enabled)),
			"ldapUrl":                  llx.StringData(rec.LdapURL),
			"usesEncryptedTransport":   llx.BoolData(usesEncryptedLdapTransport(rec.LdapURL)),
			"userDnPattern":            optionalString(rec.UserDnPattern),
			"searchFilter":             optionalString(rec.Search.SearchFilter),
			"searchBase":               optionalString(rec.Search.SearchBase),
			"searchSubTree":            llx.BoolData(boolValue(rec.Search.SearchSubTree)),
			"autoCreateUser":           llx.BoolData(boolValue(rec.AutoCreateUser)),
			"hasManagerCredential":     llx.BoolData(strings.TrimSpace(rec.Search.ManagerDn) != ""),
			"emailAttribute":           optionalString(rec.EmailAttribute),
			"ldapPoisoningProtection":  llx.BoolData(boolValue(rec.LdapPoisoningProtection)),
			"allowUserToAccessProfile": llx.BoolData(boolValue(rec.AllowUserToAccessProfile)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, created)
	}
	return res, nil
}

// usesEncryptedLdapTransport reports whether the directory is reached over an
// encrypted connection. A plain ldap URL carries the bind credential in the
// clear.
func usesEncryptedLdapTransport(ldapURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ldapURL)), ldapsScheme)
}

func (l *mqlArtifactoryLdapSetting) id() (string, error) {
	return "artifactory.ldapSetting/" + l.Key.Data, l.Key.Error
}

func (s *mqlArtifactorySecuritySettings) ldapGroupSettings() ([]any, error) {
	if s.config == nil {
		return []any{}, nil
	}

	records := s.config.Security.LdapGroupSettings
	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		created, err := CreateResource(s.MqlRuntime, "artifactory.ldapGroupSetting", map[string]*llx.RawData{
			"name":                 llx.StringData(rec.Name),
			"groupBaseDn":          llx.StringData(rec.GroupBaseDn),
			"groupNameAttribute":   llx.StringData(rec.GroupNameAttribute),
			"groupMemberAttribute": llx.StringData(rec.GroupMemberAttribute),
			"descriptionAttribute": optionalString(rec.DescriptionAttribute),
			"filter":               optionalString(rec.Filter),
			"strategy":             llx.StringData(rec.Strategy),
			"subTree":              llx.BoolData(boolValue(rec.SubTree)),
			"forceAttributeSearch": llx.BoolData(boolValue(rec.ForceAttributeSearch)),
			"ldapSettingKey":       optionalString(rec.EnabledLdap),
		})
		if err != nil {
			return nil, err
		}
		mapping := created.(*mqlArtifactoryLdapGroupSetting)
		mapping.serverName = rec.EnabledLdap
		res = append(res, mapping)
	}
	return res, nil
}

func (g *mqlArtifactoryLdapGroupSetting) id() (string, error) {
	return "artifactory.ldapGroupSetting/" + g.Name.Data, g.Name.Error
}

// ldapSetting resolves the server the mapping applies to. A mapping that names
// a server the instance does not hold reports null rather than an error, since
// the mapping is still real and its other fields are still worth reading.
func (g *mqlArtifactoryLdapGroupSetting) ldapSetting() (*mqlArtifactoryLdapSetting, error) {
	wanted := g.serverName
	if wanted == "" {
		g.LdapSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	security, err := securitySettingsOf(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	settings := security.GetLdapSettings()
	if settings.Error != nil {
		return nil, settings.Error
	}

	for _, it := range settings.Data {
		setting, ok := it.(*mqlArtifactoryLdapSetting)
		if !ok {
			continue
		}
		// Both sides are configuration names the administrator chose, so a
		// plain comparison is what is wanted here.
		if name := setting.Key.Data; name == wanted {
			return setting, nil
		}
	}

	g.LdapSetting.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// securitySettingsOf returns the instance's security settings from the root
// resource, so the descriptor is read once for the whole scan.
func securitySettingsOf(runtime *plugin.Runtime) (*mqlArtifactorySecuritySettings, error) {
	root, err := getArtifactory(runtime)
	if err != nil {
		return nil, err
	}
	security := root.GetSecurity()
	if security.Error != nil {
		return nil, security.Error
	}
	if security.Data == nil {
		return nil, errSecurityUnavailable
	}
	return security.Data, nil
}

// --- SAML -----------------------------------------------------------------

// saml reports the SAML settings, or null when the descriptor carries no SAML
// block at all. Null is not the same answer as disabled: an instance that never
// configured SAML is distinguishable from one that turned it off.
func (s *mqlArtifactorySecuritySettings) saml() (*mqlArtifactorySamlSettings, error) {
	if s.config == nil || s.config.Security.SamlSettings == nil {
		s.Saml.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	rec := s.config.Security.SamlSettings
	created, err := CreateResource(s.MqlRuntime, "artifactory.samlSettings", map[string]*llx.RawData{
		"enabled":                   llx.BoolData(boolValue(rec.EnableIntegration)),
		"loginUrl":                  llx.StringData(rec.LoginURL),
		"logoutUrl":                 optionalString(rec.LogoutURL),
		"serviceProviderName":       llx.StringData(rec.ServiceProviderName),
		"noAutoUserCreation":        llx.BoolData(boolValue(rec.NoAutoUserCreation)),
		"autoRedirect":              llx.BoolData(boolValue(rec.AutoRedirect)),
		"syncGroups":                llx.BoolData(boolValue(rec.SyncGroups)),
		"groupAttribute":            optionalString(rec.GroupAttribute),
		"emailAttribute":            optionalString(rec.EmailAttribute),
		"useEncryptedAssertion":     llx.BoolData(boolValue(rec.UseEncryptedAssertion)),
		"verifyAudienceRestriction": llx.BoolData(boolValue(rec.VerifyAudienceRestriction)),
		"allowUserToAccessProfile":  llx.BoolData(boolValue(rec.AllowUserToAccessProfile)),
		"hasCertificate":            llx.BoolData(strings.TrimSpace(rec.Certificate) != ""),
	})
	if err != nil {
		return nil, err
	}
	return created.(*mqlArtifactorySamlSettings), nil
}

func (s *mqlArtifactorySamlSettings) id() (string, error) {
	return "artifactory.samlSettings", nil
}

// --- OAuth ----------------------------------------------------------------

type mqlArtifactoryOauthSettingsInternal struct {
	// providerRecords is named apart from the providers field so the embedded
	// struct does not collide with the generated accessor.
	providerRecords []oauthProviderRecord
}

func (s *mqlArtifactorySecuritySettings) oauth() (*mqlArtifactoryOauthSettings, error) {
	if s.config == nil || s.config.Security.OauthSettings == nil {
		s.Oauth.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	rec := s.config.Security.OauthSettings
	created, err := CreateResource(s.MqlRuntime, "artifactory.oauthSettings", map[string]*llx.RawData{
		"enabled":                  llx.BoolData(boolValue(rec.EnableIntegration)),
		"persistUsers":             llx.BoolData(boolValue(rec.PersistUsers)),
		"allowUserToAccessProfile": llx.BoolData(boolValue(rec.AllowUserToAccessProfile)),
	})
	if err != nil {
		return nil, err
	}

	settings := created.(*mqlArtifactoryOauthSettings)
	settings.providerRecords = rec.Providers
	return settings, nil
}

func (o *mqlArtifactoryOauthSettings) id() (string, error) {
	return "artifactory.oauthSettings", nil
}

func (o *mqlArtifactoryOauthSettings) providers() ([]any, error) {
	res := make([]any, 0, len(o.providerRecords))
	for i := range o.providerRecords {
		rec := o.providerRecords[i]
		created, err := CreateResource(o.MqlRuntime, "artifactory.oauthProvider", map[string]*llx.RawData{
			"name":         llx.StringData(rec.Name),
			"enabled":      llx.BoolData(boolValue(rec.Enabled)),
			"providerType": llx.StringData(rec.ProviderType),
			"clientId":     optionalString(rec.ID),
			"apiUrl":       optionalString(rec.APIURL),
			"authUrl":      optionalString(rec.AuthURL),
			"tokenUrl":     optionalString(rec.TokenURL),
			"basicUrl":     optionalString(rec.BasicURL),
			"domain":       optionalString(rec.Domain),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, created)
	}
	return res, nil
}

func (p *mqlArtifactoryOauthProvider) id() (string, error) {
	return "artifactory.oauthProvider/" + p.Name.Data, p.Name.Error
}

// --- HTTP single sign-on and Crowd ----------------------------------------

func (s *mqlArtifactorySecuritySettings) httpSso() (*mqlArtifactoryHttpSsoSettings, error) {
	if s.config == nil || s.config.Security.HttpSsoSettings == nil {
		s.HttpSso.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	rec := s.config.Security.HttpSsoSettings
	created, err := CreateResource(s.MqlRuntime, "artifactory.httpSsoSettings", map[string]*llx.RawData{
		"httpSsoProxied":            llx.BoolData(boolValue(rec.HttpSsoProxied)),
		"remoteUserRequestVariable": llx.StringData(rec.RemoteUserRequestVariable),
		"noAutoUserCreation":        llx.BoolData(boolValue(rec.NoAutoUserCreation)),
		"syncLdapGroups":            llx.BoolData(boolValue(rec.SyncLdapGroups)),
		"allowUserToAccessProfile":  llx.BoolData(boolValue(rec.AllowUserToAccessProfile)),
	})
	if err != nil {
		return nil, err
	}
	return created.(*mqlArtifactoryHttpSsoSettings), nil
}

func (h *mqlArtifactoryHttpSsoSettings) id() (string, error) {
	return "artifactory.httpSsoSettings", nil
}

func (s *mqlArtifactorySecuritySettings) crowd() (*mqlArtifactoryCrowdSettings, error) {
	if s.config == nil || s.config.Security.CrowdSettings == nil {
		s.Crowd.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	rec := s.config.Security.CrowdSettings
	created, err := CreateResource(s.MqlRuntime, "artifactory.crowdSettings", map[string]*llx.RawData{
		"enabled":                   llx.BoolData(boolValue(rec.EnableIntegration)),
		"serverUrl":                 llx.StringData(rec.ServerURL),
		"applicationName":           llx.StringData(rec.ApplicationName),
		"sessionValidationInterval": optionalInt(rec.SessionValidationInterval),
		"noAutoUserCreation":        llx.BoolData(boolValue(rec.NoAutoUserCreation)),
		"directAuthentication":      llx.BoolData(boolValue(rec.DirectAuthentication)),
		"useDefaultProxy":           llx.BoolData(boolValue(rec.UseDefaultProxy)),
		"allowUserToAccessProfile":  llx.BoolData(boolValue(rec.AllowUserToAccessProfile)),
	})
	if err != nil {
		return nil, err
	}
	return created.(*mqlArtifactoryCrowdSettings), nil
}

func (c *mqlArtifactoryCrowdSettings) id() (string, error) {
	return "artifactory.crowdSettings", nil
}

// --- backups --------------------------------------------------------------

type mqlArtifactoryBackupInternal struct {
	excludedRepositories []string
}

// backups reports the scheduled exports of the instance. They come from the
// same descriptor the security settings do, so reading both costs one call.
func (a *mqlArtifactory) backups() ([]any, error) {
	security, err := securitySettingsOf(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if security.config == nil {
		return []any{}, nil
	}

	records := security.config.Backups
	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		created, err := CreateResource(a.MqlRuntime, "artifactory.backup", map[string]*llx.RawData{
			"key":                    llx.StringData(rec.Key),
			"enabled":                llx.BoolData(boolValue(rec.Enabled)),
			"cronExpression":         llx.StringData(rec.CronExp),
			"retentionPeriodHours":   optionalInt(rec.RetentionPeriodHours),
			"createArchive":          llx.BoolData(boolValue(rec.CreateArchive)),
			"excludeBuilds":          llx.BoolData(boolValue(rec.ExcludeBuilds)),
			"excludeNewRepositories": llx.BoolData(boolValue(rec.ExcludeNewRepositories)),
			"sendMailOnError":        llx.BoolData(boolValue(rec.SendMailOnError)),
			"excludedRepositories":   llx.ArrayData(strSliceToAny(rec.ExcludedRepositories), types.String),
		})
		if err != nil {
			return nil, err
		}
		backup := created.(*mqlArtifactoryBackup)
		backup.excludedRepositories = rec.ExcludedRepositories
		res = append(res, backup)
	}
	return res, nil
}

func (b *mqlArtifactoryBackup) id() (string, error) {
	return "artifactory.backup/" + b.Key.Data, b.Key.Error
}

func (b *mqlArtifactoryBackup) excludedRepositoryRefs() ([]any, error) {
	return resolveRepositories(b.MqlRuntime, b.excludedRepositories)
}
