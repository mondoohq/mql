// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/databricks/databricks-sdk-go/service/settings"
)

// mqlDatabricksWorkspaceConfInternal caches the workspace settings that are
// read through the settings API rather than the workspace conf. Each one is a
// distinct call, so they are fetched once together and shared across the
// fields that expose them.
type mqlDatabricksWorkspaceConfInternal struct {
	hardeningOnce sync.Once
	hardening     workspaceHardening
	hardeningErr  error
}

// workspaceHardening holds the workspace settings read through the settings
// API: the security-hardening controls, and the controls governing what may
// leave the workspace.
//
// Every value is a pointer or a nil-able slice, and a setting whose call failed
// stays unset so the field reports null. A setting that is not available on the
// workspace's tier and a setting the caller may not read both land here, and
// neither is the same claim as "the control is off". Reporting false would be
// worse than reporting nothing: MQL evaluates `null && null` as true, but a
// concrete false is what makes an assertion such as
// `enableResultsDownloading == false` pass on a workspace nobody read.
type workspaceHardening struct {
	cspEnabled          *bool
	cspStandards        []any
	esmEnabled          *bool
	restrictAdminStatus *string
	autoClusterUpdate   *bool
	disableLegacyAccess *bool

	notebookExport              *bool
	notebookTableClipboard      *bool
	notebookResultsDownload     *bool
	sqlResultsDownload          *bool
	dashboardEmailSubscriptions *bool
	dashboardEmbeddingPolicy    *string
	dashboardEmbeddingDomains   []any
}

// loadHardening fetches the settings-API workspace settings once and caches the
// result. The plane error (connecting to the account console rather than a
// workspace) is captured so every field reports it consistently. An individual
// setting that could not be read is left unset, and its field reports null.
func (r *mqlDatabricksWorkspaceConf) loadHardening() (workspaceHardening, error) {
	r.hardeningOnce.Do(func() {
		ws, err := workspaceClient(r.MqlRuntime)
		if err != nil {
			r.hardeningErr = err
			return
		}
		ctx := context.Background()
		var h workspaceHardening

		if csp, err := ws.Settings.ComplianceSecurityProfile().Get(ctx, settings.GetComplianceSecurityProfileSettingRequest{}); err == nil && csp != nil {
			enabled := csp.ComplianceSecurityProfileWorkspace.IsEnabled
			h.cspEnabled = &enabled
			standards := []any{}
			for _, std := range csp.ComplianceSecurityProfileWorkspace.ComplianceStandards {
				standards = append(standards, string(std))
			}
			h.cspStandards = standards
		}

		if esm, err := ws.Settings.EnhancedSecurityMonitoring().Get(ctx, settings.GetEnhancedSecurityMonitoringSettingRequest{}); err == nil && esm != nil {
			enabled := esm.EnhancedSecurityMonitoringWorkspace.IsEnabled
			h.esmEnabled = &enabled
		}

		if rwa, err := ws.Settings.RestrictWorkspaceAdmins().Get(ctx, settings.GetRestrictWorkspaceAdminsSettingRequest{}); err == nil && rwa != nil {
			status := string(rwa.RestrictWorkspaceAdmins.Status)
			h.restrictAdminStatus = &status
		}

		if acu, err := ws.Settings.AutomaticClusterUpdate().Get(ctx, settings.GetAutomaticClusterUpdateSettingRequest{}); err == nil && acu != nil {
			enabled := acu.AutomaticClusterUpdateWorkspace.Enabled
			h.autoClusterUpdate = &enabled
		}

		if dla, err := ws.Settings.DisableLegacyAccess().Get(ctx, settings.GetDisableLegacyAccessRequest{}); err == nil && dla != nil {
			h.disableLegacyAccess = boolMessageValue(&dla.DisableLegacyAccess)
		}

		// The three notebook controls report their value through a nil-able
		// boolean_val, so a response that omits it stays null here rather than
		// becoming a false the workspace never set.
		if v, err := ws.Settings.EnableExportNotebook().GetEnableExportNotebook(ctx); err == nil && v != nil {
			h.notebookExport = boolMessageValue(v.BooleanVal)
		}

		if v, err := ws.Settings.EnableNotebookTableClipboard().GetEnableNotebookTableClipboard(ctx); err == nil && v != nil {
			h.notebookTableClipboard = boolMessageValue(v.BooleanVal)
		}

		if v, err := ws.Settings.EnableResultsDownloading().GetEnableResultsDownloading(ctx); err == nil && v != nil {
			h.notebookResultsDownload = boolMessageValue(v.BooleanVal)
		}

		// SqlResultsDownload and DashboardEmailSubscriptions carry boolean_val
		// as a value rather than a pointer, so the only signal available is
		// whether the call itself succeeded. A call that failed leaves the
		// field null; a call that succeeded reports what came back.
		if v, err := ws.Settings.SqlResultsDownload().Get(ctx, settings.GetSqlResultsDownloadRequest{}); err == nil && v != nil {
			h.sqlResultsDownload = boolMessageValue(&v.BooleanVal)
		}

		if v, err := ws.Settings.DashboardEmailSubscriptions().Get(ctx, settings.GetDashboardEmailSubscriptionsRequest{}); err == nil && v != nil {
			h.dashboardEmailSubscriptions = boolMessageValue(&v.BooleanVal)
		}

		if v, err := ws.Settings.AibiDashboardEmbeddingAccessPolicy().Get(ctx, settings.GetAibiDashboardEmbeddingAccessPolicySettingRequest{}); err == nil && v != nil {
			policy := string(v.AibiDashboardEmbeddingAccessPolicy.AccessPolicyType)
			h.dashboardEmbeddingPolicy = &policy
		}

		if v, err := ws.Settings.AibiDashboardEmbeddingApprovedDomains().Get(ctx, settings.GetAibiDashboardEmbeddingApprovedDomainsSettingRequest{}); err == nil && v != nil {
			h.dashboardEmbeddingDomains = strSlice(v.AibiDashboardEmbeddingApprovedDomains.ApprovedDomains)
		}

		r.hardening = h
	})
	return r.hardening, r.hardeningErr
}

// boolMessageValue reads the value out of a settings boolean message,
// returning nil when the message itself is absent.
func boolMessageValue(m *settings.BooleanMessage) *bool {
	if m == nil {
		return nil
	}
	v := m.Value
	return &v
}

func (r *mqlDatabricksWorkspaceConf) complianceSecurityProfileEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.cspEnabled, &r.ComplianceSecurityProfileEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) complianceSecurityStandards() ([]any, error) {
	h, err := r.loadHardening()
	if err != nil {
		return nil, err
	}
	return nullableList(h.cspStandards, &r.ComplianceSecurityStandards.State)
}

func (r *mqlDatabricksWorkspaceConf) enhancedSecurityMonitoringEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.esmEnabled, &r.EnhancedSecurityMonitoringEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) restrictWorkspaceAdminsStatus() (string, error) {
	h, err := r.loadHardening()
	if err != nil {
		return "", err
	}
	return nullableString(h.restrictAdminStatus, &r.RestrictWorkspaceAdminsStatus.State)
}

func (r *mqlDatabricksWorkspaceConf) automaticClusterUpdateEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.autoClusterUpdate, &r.AutomaticClusterUpdateEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) disableLegacyAccess() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.disableLegacyAccess, &r.DisableLegacyAccess.State)
}

func (r *mqlDatabricksWorkspaceConf) notebookExportEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.notebookExport, &r.NotebookExportEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) notebookTableClipboardEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.notebookTableClipboard, &r.NotebookTableClipboardEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) notebookResultsDownloadEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.notebookResultsDownload, &r.NotebookResultsDownloadEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) sqlResultsDownloadEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.sqlResultsDownload, &r.SqlResultsDownloadEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) dashboardEmailSubscriptionsEnabled() (bool, error) {
	h, err := r.loadHardening()
	if err != nil {
		return false, err
	}
	return nullableBool(h.dashboardEmailSubscriptions, &r.DashboardEmailSubscriptionsEnabled.State)
}

func (r *mqlDatabricksWorkspaceConf) dashboardEmbeddingAccessPolicy() (string, error) {
	h, err := r.loadHardening()
	if err != nil {
		return "", err
	}
	return nullableString(h.dashboardEmbeddingPolicy, &r.DashboardEmbeddingAccessPolicy.State)
}

func (r *mqlDatabricksWorkspaceConf) dashboardEmbeddingApprovedDomains() ([]any, error) {
	h, err := r.loadHardening()
	if err != nil {
		return nil, err
	}
	return nullableList(h.dashboardEmbeddingDomains, &r.DashboardEmbeddingApprovedDomains.State)
}
