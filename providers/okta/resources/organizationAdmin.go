// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

// Okta reports the support access grant as a status string rather than a
// boolean. Only these two values are defined; anything else is left null
// rather than guessed at, because both guesses are wrong in a way an audit
// cannot see.
const (
	oktaSupportStatusEnabled  = "ENABLED"
	oktaSupportStatusDisabled = "DISABLED"
)

// mqlOktaOrganizationInternal memoizes the two org endpoints that back more
// than one field. Field accessors run per field, so without this a query
// reading the three Okta Support fields would issue the same request three
// times.
type mqlOktaOrganizationInternal struct {
	supportOnce sync.Once
	support     *okta.OrgOktaSupportSettingsObj
	supportErr  error

	captchaOnce     sync.Once
	captchaSettings *okta.OrgCAPTCHASettings
	captchaErr      error
}

// supportSettings reads the Okta Support access grant once per organization
// resource. A nil result with a nil error means the org does not answer for
// the setting at all, which every caller reports as a null field.
func (o *mqlOktaOrganization) supportSettings() (*okta.OrgOktaSupportSettingsObj, error) {
	o.supportOnce.Do(func() {
		conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
		settings, resp, err := conn.Client().OrgSettingSupportAPI.
			GetOrgOktaSupportSettings(context.Background()).
			Execute()
		if err != nil {
			if !isOktaFeatureUnavailable(resp, err) {
				o.supportErr = err
			}
			return
		}
		o.support = settings
	})
	return o.support, o.supportErr
}

// oktaSupportEnabled reports whether Okta Support staff currently hold
// administrator access to the org.
//
// An unrecognized status is reported as null rather than mapped to either
// boolean. Reading it as false would say Okta Support holds no access, which
// is the answer a check hopes for and would let it pass on a grant this code
// did not recognize.
func (o *mqlOktaOrganization) oktaSupportEnabled() (bool, error) {
	settings, err := o.supportSettings()
	if err != nil {
		return false, err
	}
	if settings == nil {
		o.OktaSupportEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	enabled, known := oktaSupportEnabledFrom(settings.Support)
	if !known {
		o.OktaSupportEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return enabled, nil
}

// oktaSupportEnabledFrom maps the support status string to a boolean. known is
// false for an absent status and for one this code does not recognize, which
// the caller reports as null.
func oktaSupportEnabledFrom(support *string) (enabled bool, known bool) {
	if support == nil {
		return false, false
	}
	switch strings.ToUpper(*support) {
	case oktaSupportStatusEnabled:
		return true, true
	case oktaSupportStatusDisabled:
		return false, true
	default:
		return false, false
	}
}

func (o *mqlOktaOrganization) oktaSupportExpiration() (*time.Time, error) {
	settings, err := o.supportSettings()
	if err != nil {
		return nil, err
	}
	// An absent expiration stays null. Left to fall through it would reach the
	// field as the zero time and report the year 1 as a real date.
	if settings == nil || settings.Expiration.Get() == nil {
		o.OktaSupportExpiration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return settings.Expiration.Get(), nil
}

func (o *mqlOktaOrganization) oktaSupportCaseNumber() (string, error) {
	settings, err := o.supportSettings()
	if err != nil {
		return "", err
	}
	if settings == nil || settings.CaseNumber.Get() == nil {
		o.OktaSupportCaseNumber.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *settings.CaseNumber.Get(), nil
}

func (o *mqlOktaOrganization) superAdminGrantedToNewPublicClients() (bool, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	setting, resp, err := conn.Client().OrgSettingAdminAPI.
		GetClientPrivilegesSetting(context.Background()).
		Execute()
	if err != nil {
		if !isOktaFeatureUnavailable(resp, err) {
			return false, err
		}
		o.SuperAdminGrantedToNewPublicClients.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if setting == nil || setting.ClientPrivilegesSetting == nil {
		o.SuperAdminGrantedToNewPublicClients.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *setting.ClientPrivilegesSetting, nil
}

func (o *mqlOktaOrganization) thirdPartyAdminEnabled() (bool, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	setting, resp, err := conn.Client().OrgSettingAdminAPI.
		GetThirdPartyAdminSetting(context.Background()).
		Execute()
	if err != nil {
		if !isOktaFeatureUnavailable(resp, err) {
			return false, err
		}
		o.ThirdPartyAdminEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if setting == nil || setting.ThirdPartyAdmin == nil {
		o.ThirdPartyAdminEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *setting.ThirdPartyAdmin, nil
}

// orgCaptchaSettings reads the org-wide CAPTCHA binding once per organization
// resource, since the instance and the protected pages come from one endpoint.
func (o *mqlOktaOrganization) orgCaptchaSettings() (*okta.OrgCAPTCHASettings, error) {
	o.captchaOnce.Do(func() {
		conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
		settings, resp, err := conn.Client().CAPTCHAAPI.
			GetOrgCaptchaSettings(context.Background()).
			Execute()
		if err != nil {
			if !isOktaFeatureUnavailable(resp, err) {
				o.captchaErr = err
			}
			return
		}
		o.captchaSettings = settings
	})
	return o.captchaSettings, o.captchaErr
}

// captcha resolves the CAPTCHA instance the org enforces. An org with no
// CAPTCHA answers with no instance id, which is reported as a null field
// rather than as an error.
func (o *mqlOktaOrganization) captcha() (*mqlOktaCaptcha, error) {
	settings, err := o.orgCaptchaSettings()
	if err != nil {
		return nil, err
	}
	if settings == nil || oktaStr(settings.CaptchaId) == "" {
		o.Captcha.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	instance, resp, err := conn.Client().CAPTCHAAPI.
		GetCaptchaInstance(context.Background(), oktaStr(settings.CaptchaId)).
		Execute()
	if err != nil {
		// The binding can outlive the instance it named.
		if isOktaNotFound(resp) {
			o.Captcha.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if instance == nil {
		o.Captcha.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return newMqlOktaCaptcha(o.MqlRuntime, instance)
}

// captchaEnabledPages reports which end-user pages the org protects. An org
// that does not answer for the setting reports null, since an empty list would
// say every page is unprotected as a fact.
func (o *mqlOktaOrganization) captchaEnabledPages() ([]any, error) {
	settings, err := o.orgCaptchaSettings()
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return oktaUnreadableList(&o.CaptchaEnabledPages)
	}
	return convert.SliceAnyToInterface(settings.EnabledPages), nil
}
