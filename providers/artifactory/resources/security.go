// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
)

// securityConfig is the part of the instance configuration descriptor this
// provider reads. The descriptor is served as XML and holds far more than
// this, so only the security settings are decoded.
type securityConfig struct {
	Security securitySection `xml:"security"`
	Backups  []backupRecord  `xml:"backups>backup"`
}

type securitySection struct {
	AnonAccessEnabled                *bool                  `xml:"anonAccessEnabled"`
	AnonAccessToBuildInfosDisabled   *bool                  `xml:"anonAccessToBuildInfosDisabled"`
	HideUnauthorizedResources        *bool                  `xml:"hideUnauthorizedResources"`
	BuildGlobalBasicReadAllowed      *bool                  `xml:"buildGlobalBasicReadAllowed"`
	BuildGlobalBasicReadForAnonymous *bool                  `xml:"buildGlobalBasicReadForAnonymous"`
	UserLockPolicy                   userLockPolicy         `xml:"userLockPolicy"`
	PasswordSettings                 passwordSettingsRecord `xml:"passwordSettings"`

	// Identity integrations. Each block is absent altogether on an instance
	// that never configured it, so every flag inside is a pointer and stays
	// null rather than reading as off.
	LdapSettings      []ldapSettingRecord      `xml:"ldapSettings>ldapSetting"`
	LdapGroupSettings []ldapGroupSettingRecord `xml:"ldapGroupSettings>ldapGroupSetting"`
	SamlSettings      *samlSettingsRecord      `xml:"samlSettings"`
	OauthSettings     *oauthSettingsRecord     `xml:"oauthSettings"`
	HttpSsoSettings   *httpSsoSettingsRecord   `xml:"httpSsoSettings"`
	CrowdSettings     *crowdSettingsRecord     `xml:"crowdSettings"`
}

// ldapSettingRecord is one LDAP server the instance authenticates against.
type ldapSettingRecord struct {
	Key                      string `xml:"key"`
	Enabled                  *bool  `xml:"enabled"`
	LdapURL                  string `xml:"ldapUrl"`
	UserDnPattern            string `xml:"userDnPattern"`
	AutoCreateUser           *bool  `xml:"autoCreateUser"`
	EmailAttribute           string `xml:"emailAttribute"`
	LdapPoisoningProtection  *bool  `xml:"ldapPoisoningProtection"`
	AllowUserToAccessProfile *bool  `xml:"allowUserToAccessProfile"`
	Search                   struct {
		SearchFilter  string `xml:"searchFilter"`
		SearchBase    string `xml:"searchBase"`
		SearchSubTree *bool  `xml:"searchSubTree"`
		ManagerDn     string `xml:"managerDn"`
	} `xml:"search"`
}

// ldapGroupSettingRecord maps an LDAP group tree onto instance groups.
type ldapGroupSettingRecord struct {
	Name                 string `xml:"name"`
	GroupBaseDn          string `xml:"groupBaseDn"`
	GroupNameAttribute   string `xml:"groupNameAttribute"`
	GroupMemberAttribute string `xml:"groupMemberAttribute"`
	DescriptionAttribute string `xml:"descriptionAttribute"`
	Filter               string `xml:"filter"`
	Strategy             string `xml:"strategy"`
	SubTree              *bool  `xml:"subTree"`
	ForceAttributeSearch *bool  `xml:"forceAttributeSearch"`
	EnabledLdap          string `xml:"enabledLdap"`
}

type samlSettingsRecord struct {
	EnableIntegration         *bool  `xml:"enableIntegration"`
	LoginURL                  string `xml:"loginUrl"`
	LogoutURL                 string `xml:"logoutUrl"`
	ServiceProviderName       string `xml:"serviceProviderName"`
	NoAutoUserCreation        *bool  `xml:"noAutoUserCreation"`
	AllowUserToAccessProfile  *bool  `xml:"allowUserToAccessProfile"`
	AutoRedirect              *bool  `xml:"autoRedirect"`
	SyncGroups                *bool  `xml:"syncGroups"`
	GroupAttribute            string `xml:"groupAttribute"`
	EmailAttribute            string `xml:"emailAttribute"`
	UseEncryptedAssertion     *bool  `xml:"useEncryptedAssertion"`
	VerifyAudienceRestriction *bool  `xml:"verifyAudienceRestriction"`
	Certificate               string `xml:"certificate"`
}

type oauthSettingsRecord struct {
	EnableIntegration        *bool                 `xml:"enableIntegration"`
	PersistUsers             *bool                 `xml:"persistUsers"`
	AllowUserToAccessProfile *bool                 `xml:"allowUserToAccessProfile"`
	Providers                []oauthProviderRecord `xml:"oauthProvidersSettings>oauthProviderSettings"`
}

type oauthProviderRecord struct {
	Name         string `xml:"name"`
	Enabled      *bool  `xml:"enabled"`
	ProviderType string `xml:"providerType"`
	ID           string `xml:"id"`
	APIURL       string `xml:"apiUrl"`
	AuthURL      string `xml:"authUrl"`
	TokenURL     string `xml:"tokenUrl"`
	BasicURL     string `xml:"basicUrl"`
	Domain       string `xml:"domain"`
}

type httpSsoSettingsRecord struct {
	HttpSsoProxied            *bool  `xml:"httpSsoProxied"`
	RemoteUserRequestVariable string `xml:"remoteUserRequestVariable"`
	AllowUserToAccessProfile  *bool  `xml:"allowUserToAccessProfile"`
	NoAutoUserCreation        *bool  `xml:"noAutoUserCreation"`
	SyncLdapGroups            *bool  `xml:"syncLdapGroups"`
}

type crowdSettingsRecord struct {
	EnableIntegration         *bool  `xml:"enableIntegration"`
	ServerURL                 string `xml:"serverUrl"`
	ApplicationName           string `xml:"applicationName"`
	SessionValidationInterval *int64 `xml:"sessionValidationInterval"`
	NoAutoUserCreation        *bool  `xml:"noAutoUserCreation"`
	AllowUserToAccessProfile  *bool  `xml:"allowUserToAccessProfile"`
	DirectAuthentication      *bool  `xml:"directAuthentication"`
	UseDefaultProxy           *bool  `xml:"useDefaultProxy"`
}

// backupRecord is a scheduled export of the instance.
type backupRecord struct {
	Key                    string   `xml:"key"`
	Enabled                *bool    `xml:"enabled"`
	CronExp                string   `xml:"cronExp"`
	RetentionPeriodHours   *int64   `xml:"retentionPeriodHours"`
	CreateArchive          *bool    `xml:"createArchive"`
	ExcludeBuilds          *bool    `xml:"excludeBuilds"`
	ExcludeNewRepositories *bool    `xml:"excludeNewRepositories"`
	SendMailOnError        *bool    `xml:"sendMailOnError"`
	ExcludedRepositories   []string `xml:"excludedRepositories>repositoryRef"`
}

// userLockPolicy locks an account after repeated failed sign-ins.
type userLockPolicy struct {
	Enabled       *bool  `xml:"enabled"`
	LoginAttempts *int64 `xml:"loginAttempts"`
}

// passwordSettingsRecord holds how internal passwords are stored and how long
// they stay valid.
type passwordSettingsRecord struct {
	EncryptionPolicy string                 `xml:"encryptionPolicy"`
	ExpirationPolicy expirationPolicyRecord `xml:"expirationPolicy"`
}

type expirationPolicyRecord struct {
	Enabled *bool `xml:"enabled"`
	// MaxAgeDays is the number of days a password stays valid.
	MaxAgeDays *int64 `xml:"passwordMaxAge"`
}

// security reads the instance configuration descriptor. It is an
// administrator-only endpoint, so a token without those rights fails the field
// rather than reporting an instance that permits nothing.
func (a *mqlArtifactory) security() (*mqlArtifactorySecuritySettings, error) {
	conn := artifactoryConn(a.MqlRuntime)

	var config securityConfig
	if err := conn.GetXML(context.Background(), conn.ArtifactoryURL("/api/system/configuration"), &config); err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "artifactory.securitySettings", securityArgs(&config))
	if err != nil {
		return nil, err
	}

	// The identity integrations and the backups come from the same descriptor,
	// so it is kept rather than fetched again for each of them.
	settings := res.(*mqlArtifactorySecuritySettings)
	settings.config = &config
	return settings, nil
}

// errSecurityUnavailable reports that the instance descriptor could not be
// read, so nothing derived from it can be answered.
var errSecurityUnavailable = errors.New("the Artifactory instance configuration could not be read")

// securityArgs maps the decoded descriptor onto the resource's fields. A
// setting the descriptor does not carry stays null, so an instance that never
// configured password expiry is distinguishable from one that set it to zero
// days.
func securityArgs(config *securityConfig) map[string]*llx.RawData {
	security := config.Security

	loginAttempts := llx.NilData
	// The attempt count only means something while locking is on. Reporting it
	// otherwise would suggest a limit the instance does not apply.
	if boolValue(security.UserLockPolicy.Enabled) && security.UserLockPolicy.LoginAttempts != nil {
		loginAttempts = llx.IntData(*security.UserLockPolicy.LoginAttempts)
	}

	passwordExpiryDays := llx.NilData
	if boolValue(security.PasswordSettings.ExpirationPolicy.Enabled) && security.PasswordSettings.ExpirationPolicy.MaxAgeDays != nil {
		passwordExpiryDays = llx.IntData(*security.PasswordSettings.ExpirationPolicy.MaxAgeDays)
	}

	return map[string]*llx.RawData{
		"anonymousAccessEnabled":              llx.BoolData(boolValue(security.AnonAccessEnabled)),
		"anonymousAccessToBuildInfosDisabled": llx.BoolData(boolValue(security.AnonAccessToBuildInfosDisabled)),
		"hideUnauthorizedResources":           llx.BoolData(boolValue(security.HideUnauthorizedResources)),
		"passwordEncryptionPolicy":            llx.StringData(security.PasswordSettings.EncryptionPolicy),
		"userLockPolicyEnabled":               llx.BoolData(boolValue(security.UserLockPolicy.Enabled)),
		"loginAttempts":                       loginAttempts,
		"passwordExpiryEnabled":               llx.BoolData(boolValue(security.PasswordSettings.ExpirationPolicy.Enabled)),
		"passwordExpiryDays":                  passwordExpiryDays,
		"buildGlobalBasicReadAllowed":         llx.BoolData(boolValue(security.BuildGlobalBasicReadAllowed)),
		"buildGlobalBasicReadForAnonymous":    llx.BoolData(boolValue(security.BuildGlobalBasicReadForAnonymous)),
	}
}

func (s *mqlArtifactorySecuritySettings) id() (string, error) {
	return "artifactory.securitySettings", nil
}

// anonymousCanRead reports whether an unauthenticated caller reaches any
// repository. Both halves must hold: anonymous access is on instance-wide, and
// a permission target gives the anonymous user a read action.
func (s *mqlArtifactorySecuritySettings) anonymousCanRead() (bool, error) {
	if !s.AnonymousAccessEnabled.Data {
		return false, nil
	}

	targets, err := allPermissionTargets(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	for _, target := range targets {
		if target.GrantsAnonymousRead.Data {
			return true, nil
		}
	}
	return false, nil
}

// anonymousCanDeploy reports whether an unauthenticated caller can publish.
// This is the state in which anyone who reaches the instance can replace the
// artifacts it serves.
func (s *mqlArtifactorySecuritySettings) anonymousCanDeploy() (bool, error) {
	if !s.AnonymousAccessEnabled.Data {
		return false, nil
	}

	// Read through the cached field so that asking for both this and the
	// target list walks the permission targets once.
	targets := s.GetAnonymousDeployTargets()
	if targets.Error != nil {
		return false, targets.Error
	}
	return len(targets.Data) > 0, nil
}

// anonymousDeployTargets lists the targets that would let an unauthenticated
// caller publish. They are listed whether or not anonymous access is on, so
// that turning it on shows what would immediately apply.
func (s *mqlArtifactorySecuritySettings) anonymousDeployTargets() ([]any, error) {
	targets, err := allPermissionTargets(s.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, target := range targets {
		if target.GrantsAnonymousDeploy.Data {
			res = append(res, target)
		}
	}
	return res, nil
}
