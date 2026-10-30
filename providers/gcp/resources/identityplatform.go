// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	identitytoolkit "google.golang.org/api/identitytoolkit/v2"
	"google.golang.org/api/option"
)

type mqlGcpProjectIdentityPlatformServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) identityPlatform() (*mqlGcpProjectIdentityPlatformService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.identityPlatformService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_identityplatform)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectIdentityPlatformService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_identityplatform).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectIdentityPlatformService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args = map[string]*llx.RawData{
		"projectId": llx.StringData(conn.ResourceID()),
	}
	return args, nil, nil
}

func (g *mqlGcpProjectIdentityPlatformService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/identityPlatformService", g.ProjectId.Data), nil
}

// identityPlatformClient builds an Identity Platform (identitytoolkit) admin client.
func (g *mqlGcpProjectIdentityPlatformService) identityPlatformClient() (*identitytoolkit.Service, error) {
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(identitytoolkit.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return identitytoolkit.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProjectIdentityPlatformService) config() (*mqlGcpProjectIdentityPlatformServiceConfig, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		g.Config.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	svc, err := g.identityPlatformClient()
	if err != nil {
		return nil, err
	}

	cfg, err := svc.Projects.GetConfig(fmt.Sprintf("projects/%s/config", projectId)).Do()
	if err != nil {
		if isSkippable(err) {
			g.Config.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	args := map[string]*llx.RawData{
		"__id":                     llx.StringData(cfg.Name),
		"projectId":                llx.StringData(projectId),
		"subtype":                  llx.StringData(cfg.Subtype),
		"authorizedDomains":        llx.ArrayData(convert.SliceAnyToInterface(cfg.AuthorizedDomains), types.String),
		"autodeleteAnonymousUsers": llx.BoolData(cfg.AutodeleteAnonymousUsers),

		// multi-factor authentication
		"mfaState":            llx.StringData(""),
		"mfaEnabledProviders": llx.ArrayData([]any{}, types.String),
		"mfaProviderConfigs":  llx.ArrayData([]any{}, types.Dict),

		// sign-in methods
		"signInEmailEnabled":          llx.BoolData(false),
		"signInEmailPasswordRequired": llx.BoolData(false),
		"signInPhoneEnabled":          llx.BoolData(false),
		"signInAnonymousEnabled":      llx.BoolData(false),
		"signInAllowDuplicateEmails":  llx.BoolData(false),

		// email privacy
		"improvedEmailPrivacyEnabled": llx.BoolData(false),

		// password policy
		"passwordPolicyEnforcementState":     llx.StringData(""),
		"passwordPolicyForceUpgradeOnSignin": llx.BoolData(false),
		"passwordPolicyConstraints":          llx.DictData(nil),

		// reCAPTCHA
		"recaptchaEmailPasswordEnforcementState": llx.StringData(""),
		"recaptchaPhoneEnforcementState":         llx.StringData(""),
		"recaptchaUseAccountDefender":            llx.BoolData(false),

		// blocking functions
		"blockingFunctions": llx.DictData(nil),

		// client self-service restrictions
		"clientDisabledUserSignup":   llx.BoolData(false),
		"clientDisabledUserDeletion": llx.BoolData(false),

		// monitoring
		"requestLoggingEnabled": llx.BoolData(false),

		// multi-tenancy
		"multiTenantAllowed":               llx.BoolData(false),
		"multiTenantDefaultTenantLocation": llx.StringData(""),

		// sms regions
		"smsRegionConfig": llx.DictData(nil),
	}

	if mfa := cfg.Mfa; mfa != nil {
		args["mfaState"] = llx.StringData(mfa.State)
		args["mfaEnabledProviders"] = llx.ArrayData(convert.SliceAnyToInterface(mfa.EnabledProviders), types.String)
		providerConfigs, err := convert.JsonToDictSlice(mfa.ProviderConfigs)
		if err != nil {
			return nil, err
		}
		args["mfaProviderConfigs"] = llx.ArrayData(providerConfigs, types.Dict)
	}

	if signIn := cfg.SignIn; signIn != nil {
		args["signInAllowDuplicateEmails"] = llx.BoolData(signIn.AllowDuplicateEmails)
		if signIn.Email != nil {
			args["signInEmailEnabled"] = llx.BoolData(signIn.Email.Enabled)
			args["signInEmailPasswordRequired"] = llx.BoolData(signIn.Email.PasswordRequired)
		}
		if signIn.PhoneNumber != nil {
			args["signInPhoneEnabled"] = llx.BoolData(signIn.PhoneNumber.Enabled)
		}
		if signIn.Anonymous != nil {
			args["signInAnonymousEnabled"] = llx.BoolData(signIn.Anonymous.Enabled)
		}
	}

	if ep := cfg.EmailPrivacyConfig; ep != nil {
		args["improvedEmailPrivacyEnabled"] = llx.BoolData(ep.EnableImprovedEmailPrivacy)
	}

	if pp := cfg.PasswordPolicyConfig; pp != nil {
		args["passwordPolicyEnforcementState"] = llx.StringData(pp.PasswordPolicyEnforcementState)
		args["passwordPolicyForceUpgradeOnSignin"] = llx.BoolData(pp.ForceUpgradeOnSignin)
		if len(pp.PasswordPolicyVersions) > 0 && pp.PasswordPolicyVersions[0].CustomStrengthOptions != nil {
			constraints, err := convert.JsonToDict(pp.PasswordPolicyVersions[0].CustomStrengthOptions)
			if err != nil {
				return nil, err
			}
			args["passwordPolicyConstraints"] = llx.DictData(constraints)
		}
	}

	if rc := cfg.RecaptchaConfig; rc != nil {
		args["recaptchaEmailPasswordEnforcementState"] = llx.StringData(rc.EmailPasswordEnforcementState)
		args["recaptchaPhoneEnforcementState"] = llx.StringData(rc.PhoneEnforcementState)
		args["recaptchaUseAccountDefender"] = llx.BoolData(rc.UseAccountDefender)
	}

	if bf := cfg.BlockingFunctions; bf != nil {
		blockingFunctions, err := convert.JsonToDict(bf)
		if err != nil {
			return nil, err
		}
		args["blockingFunctions"] = llx.DictData(blockingFunctions)
	}

	if client := cfg.Client; client != nil && client.Permissions != nil {
		args["clientDisabledUserSignup"] = llx.BoolData(client.Permissions.DisabledUserSignup)
		args["clientDisabledUserDeletion"] = llx.BoolData(client.Permissions.DisabledUserDeletion)
	}

	if mon := cfg.Monitoring; mon != nil && mon.RequestLogging != nil {
		args["requestLoggingEnabled"] = llx.BoolData(mon.RequestLogging.Enabled)
	}

	if mt := cfg.MultiTenant; mt != nil {
		args["multiTenantAllowed"] = llx.BoolData(mt.AllowTenants)
		args["multiTenantDefaultTenantLocation"] = llx.StringData(mt.DefaultTenantLocation)
	}

	if sms := cfg.SmsRegionConfig; sms != nil {
		smsRegionConfig, err := convert.JsonToDict(sms)
		if err != nil {
			return nil, err
		}
		args["smsRegionConfig"] = llx.DictData(smsRegionConfig)
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.identityPlatformService.config", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIdentityPlatformServiceConfig), nil
}

func (g *mqlGcpProjectIdentityPlatformServiceTenant) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectIdentityPlatformService) tenants() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	svc, err := g.identityPlatformClient()
	if err != nil {
		return nil, err
	}

	var res []any
	err = svc.Projects.Tenants.List(fmt.Sprintf("projects/%s", projectId)).Pages(context.Background(),
		func(page *identitytoolkit.GoogleCloudIdentitytoolkitAdminV2ListTenantsResponse) error {
			for _, t := range page.Tenants {
				mqlTenant, err := newMqlIdentityPlatformTenant(g.MqlRuntime, t)
				if err != nil {
					return err
				}
				res = append(res, mqlTenant)
			}
			return nil
		})
	if err != nil {
		if isSkippable(err) {
			return nil, nil
		}
		return nil, err
	}

	return res, nil
}

func newMqlIdentityPlatformTenant(runtime *plugin.Runtime, t *identitytoolkit.GoogleCloudIdentitytoolkitAdminV2Tenant) (plugin.Resource, error) {
	tenantId := t.Name
	if _, after, ok := strings.CutLast(t.Name, "/"); ok {
		tenantId = after
	}

	args := map[string]*llx.RawData{
		"name":                     llx.StringData(t.Name),
		"tenantId":                 llx.StringData(tenantId),
		"displayName":              llx.StringData(t.DisplayName),
		"allowPasswordSignup":      llx.BoolData(t.AllowPasswordSignup),
		"enableEmailLinkSignin":    llx.BoolData(t.EnableEmailLinkSignin),
		"enableAnonymousUser":      llx.BoolData(t.EnableAnonymousUser),
		"disableAuth":              llx.BoolData(t.DisableAuth),
		"autodeleteAnonymousUsers": llx.BoolData(t.AutodeleteAnonymousUsers),

		"mfaState":            llx.StringData(""),
		"mfaEnabledProviders": llx.ArrayData([]any{}, types.String),

		"improvedEmailPrivacyEnabled":    llx.BoolData(false),
		"passwordPolicyEnforcementState": llx.StringData(""),

		"recaptchaEmailPasswordEnforcementState": llx.StringData(""),
		"recaptchaPhoneEnforcementState":         llx.StringData(""),

		"testPhoneNumbers": llx.MapData(convert.MapToInterfaceMap(t.TestPhoneNumbers), types.String),
	}

	if mfa := t.MfaConfig; mfa != nil {
		args["mfaState"] = llx.StringData(mfa.State)
		args["mfaEnabledProviders"] = llx.ArrayData(convert.SliceAnyToInterface(mfa.EnabledProviders), types.String)
	}
	if ep := t.EmailPrivacyConfig; ep != nil {
		args["improvedEmailPrivacyEnabled"] = llx.BoolData(ep.EnableImprovedEmailPrivacy)
	}
	if pp := t.PasswordPolicyConfig; pp != nil {
		args["passwordPolicyEnforcementState"] = llx.StringData(pp.PasswordPolicyEnforcementState)
	}
	if rc := t.RecaptchaConfig; rc != nil {
		args["recaptchaEmailPasswordEnforcementState"] = llx.StringData(rc.EmailPasswordEnforcementState)
		args["recaptchaPhoneEnforcementState"] = llx.StringData(rc.PhoneEnforcementState)
	}

	return CreateResource(runtime, "gcp.project.identityPlatformService.tenant", args)
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectIdentityPlatformService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_identityplatform)
}
