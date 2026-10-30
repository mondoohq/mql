// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/databricks/databricks-sdk-go/service/settings"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/types"
)

// mqlDatabricksAccountConfInternal caches the account console settings. Each
// toggle is a separate settings API call, so they are fetched once together and
// shared across the fields that expose them.
type mqlDatabricksAccountConfInternal struct {
	settingsOnce sync.Once
	settings     accountConsoleSettings
	settingsErr  error
}

// accountConsoleSettings holds the resolved account console settings. Every
// value is a pointer, and a setting whose call failed stays nil so the field
// reports null rather than a fabricated "off". An account-wide exfiltration or
// enforcement toggle that reads false when it was never actually read would
// satisfy every assertion written against it.
type accountConsoleSettings struct {
	ipAccessListsEnabled   *bool
	cspEnforced            *bool
	cspStandards           []any
	esmEnforced            *bool
	legacyFeaturesDisabled *bool
	personalComputeAccess  *string
}

// accountSettings exposes the account console access controls. It requires an
// account console connection: the account allowlist and the account-wide
// defaults are a different boundary from the per-workspace settings, and a
// workspace connection holds no account client to read them with. Rather than
// answering with workspace-scoped data, this reports the same account-plane
// error every other account resource in this provider reports.
func (r *mqlDatabricks) accountSettings() (*mqlDatabricksAccountConf, error) {
	if _, err := accountClient(r.MqlRuntime); err != nil {
		return nil, err
	}
	conn := r.MqlRuntime.Connection.(*connection.DatabricksConnection)

	res, err := CreateResource(r.MqlRuntime, "databricks.accountConf", map[string]*llx.RawData{
		"__id":      llx.StringData("databricks.accountConf/" + conn.AccountID()),
		"accountId": llx.StringData(conn.AccountID()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksAccountConf), nil
}

// loadSettings fetches the account console settings once and caches the result.
// A per-setting failure leaves that value nil, which the field reports as null.
func (r *mqlDatabricksAccountConf) loadSettings() (accountConsoleSettings, error) {
	r.settingsOnce.Do(func() {
		acc, err := accountClient(r.MqlRuntime)
		if err != nil {
			r.settingsErr = err
			return
		}
		ctx := context.Background()
		var s accountConsoleSettings

		if v, err := acc.Settings.EnableIpAccessLists().Get(ctx, settings.GetAccountIpAccessEnableRequest{}); err == nil && v != nil {
			enabled := v.AcctIpAclEnable.Value
			s.ipAccessListsEnabled = &enabled
		}

		if v, err := acc.Settings.CspEnablementAccount().Get(ctx, settings.GetCspEnablementAccountSettingRequest{}); err == nil && v != nil {
			enforced := v.CspEnablementAccount.IsEnforced
			s.cspEnforced = &enforced
			standards := []any{}
			for _, std := range v.CspEnablementAccount.ComplianceStandards {
				standards = append(standards, string(std))
			}
			s.cspStandards = standards
		}

		if v, err := acc.Settings.EsmEnablementAccount().Get(ctx, settings.GetEsmEnablementAccountSettingRequest{}); err == nil && v != nil {
			enforced := v.EsmEnablementAccount.IsEnforced
			s.esmEnforced = &enforced
		}

		if v, err := acc.Settings.DisableLegacyFeatures().Get(ctx, settings.GetDisableLegacyFeaturesRequest{}); err == nil && v != nil {
			disabled := v.DisableLegacyFeatures.Value
			s.legacyFeaturesDisabled = &disabled
		}

		if v, err := acc.Settings.PersonalCompute().Get(ctx, settings.GetPersonalComputeSettingRequest{}); err == nil && v != nil {
			access := string(v.PersonalCompute.Value)
			s.personalComputeAccess = &access
		}

		r.settings = s
	})
	return r.settings, r.settingsErr
}

func (r *mqlDatabricksAccountConf) ipAccessListsEnabled() (bool, error) {
	s, err := r.loadSettings()
	if err != nil {
		return false, err
	}
	return nullableBool(s.ipAccessListsEnabled, &r.IpAccessListsEnabled.State)
}

func (r *mqlDatabricksAccountConf) complianceSecurityProfileEnforced() (bool, error) {
	s, err := r.loadSettings()
	if err != nil {
		return false, err
	}
	return nullableBool(s.cspEnforced, &r.ComplianceSecurityProfileEnforced.State)
}

func (r *mqlDatabricksAccountConf) complianceSecurityStandards() ([]any, error) {
	s, err := r.loadSettings()
	if err != nil {
		return nil, err
	}
	return nullableList(s.cspStandards, &r.ComplianceSecurityStandards.State)
}

func (r *mqlDatabricksAccountConf) enhancedSecurityMonitoringEnforced() (bool, error) {
	s, err := r.loadSettings()
	if err != nil {
		return false, err
	}
	return nullableBool(s.esmEnforced, &r.EnhancedSecurityMonitoringEnforced.State)
}

func (r *mqlDatabricksAccountConf) legacyFeaturesDisabled() (bool, error) {
	s, err := r.loadSettings()
	if err != nil {
		return false, err
	}
	return nullableBool(s.legacyFeaturesDisabled, &r.LegacyFeaturesDisabled.State)
}

func (r *mqlDatabricksAccountConf) personalComputeAccess() (string, error) {
	s, err := r.loadSettings()
	if err != nil {
		return "", err
	}
	return nullableString(s.personalComputeAccess, &r.PersonalComputeAccess.State)
}

// ipAccessLists reads the IP access lists registered on the account console.
// These are separate objects from the workspace lists that databricks
// ipAccessLists returns: the account lists gate the admin console and the
// account API, the workspace lists gate a single workspace.
func (r *mqlDatabricksAccountConf) ipAccessLists() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	lists, err := acc.IpAccessLists.ListAll(context.Background())
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.IpAccessLists = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range lists {
		l := lists[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.ipAccessList", map[string]*llx.RawData{
			// The account console lists live in their own namespace: a
			// workspace list and an account list must never share a cache key.
			"__id":         llx.StringData("databricks.accountIpAccessList/" + l.ListId),
			"id":           llx.StringData(l.ListId),
			"label":        llx.StringData(l.Label),
			"listType":     llx.StringData(string(l.ListType)),
			"ipAddresses":  llx.ArrayData(strSlice(l.IpAddresses), types.String),
			"addressCount": llx.IntData(l.AddressCount),
			"enabled":      llx.BoolData(l.Enabled),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
