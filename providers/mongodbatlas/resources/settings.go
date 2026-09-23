// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// isAccessDenied reports whether the API response indicates the credential is
// not authorized to read the resource (a feature-gated or elevated-privilege
// endpoint). Such resources degrade to null rather than failing the scan.
func isAccessDenied(resp *http.Response) bool {
	return resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden)
}

// projectConfigFields maps the project settings payload onto the
// mongodbatlas.projectConfig fields.
//
// Every flag is read from its pointer field rather than the SDK's Get accessor.
// The accessors dereference a *bool and return the zero value when the pointer
// is nil, so a flag the API did not report would become a fabricated false. In
// MQL `null && null` evaluates to true, so a fabricated false on a flag whose
// secure reading is false (isDataExplorerEnabled and the generative AI flags)
// makes a "must be disabled" assertion pass on a project where the flag was
// never read at all.
func projectConfigFields(pid string, s *admin.GroupSettings) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                                            llx.StringData("mongodbatlas.projectConfig/" + pid),
		"isDataExplorerEnabled":                           llx.BoolDataPtr(s.IsDataExplorerEnabled),
		"isDataExplorerGenAIFeaturesEnabled":              llx.BoolDataPtr(s.IsDataExplorerGenAIFeaturesEnabled),
		"isExtendedStorageSizesEnabled":                   llx.BoolDataPtr(s.IsExtendedStorageSizesEnabled),
		"isPerformanceAdvisorEnabled":                     llx.BoolDataPtr(s.IsPerformanceAdvisorEnabled),
		"isRealtimePerformancePanelEnabled":               llx.BoolDataPtr(s.IsRealtimePerformancePanelEnabled),
		"isSchemaAdvisorEnabled":                          llx.BoolDataPtr(s.IsSchemaAdvisorEnabled),
		"isCollectDatabaseSpecificsStatisticsEnabled":     llx.BoolDataPtr(s.IsCollectDatabaseSpecificsStatisticsEnabled),
		"isDataExplorerGenAISampleDocumentPassingEnabled": llx.BoolDataPtr(s.IsDataExplorerGenAISampleDocumentPassingEnabled),
		"isClusterAiAssistantEnabled":                     llx.BoolDataPtr(s.IsClusterAiAssistantEnabled),
		"isNativeRerankingEnabled":                        llx.BoolDataPtr(s.IsNativeRerankingEnabled),
		"isDataValidationEnabled":                         llx.BoolDataPtr(s.IsDataValidationEnabled),
	}
}

func (r *mqlMongodbatlas) projectSettings() (*mqlMongodbatlasProjectConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	s, _, err := atlasClient(r.MqlRuntime).ProjectsAPI.GetGroupSettings(context.Background(), pid).Execute()
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.projectConfig", projectConfigFields(pid, s))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasProjectConfig), nil
}

func (r *mqlMongodbatlas) auditing() (*mqlMongodbatlasAuditConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	a, httpResp, err := atlasClient(r.MqlRuntime).AuditingAPI.GetGroupAuditLog(context.Background(), pid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.Auditing.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.auditConfig", map[string]*llx.RawData{
		"__id":                      llx.StringData("mongodbatlas.auditConfig/" + pid),
		"enabled":                   llx.BoolData(a.GetEnabled()),
		"auditAuthorizationSuccess": llx.BoolData(a.GetAuditAuthorizationSuccess()),
		"auditFilter":               llx.StringData(a.GetAuditFilter()),
		"configurationType":         llx.StringData(a.GetConfigurationType()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasAuditConfig), nil
}

func (r *mqlMongodbatlas) encryptionAtRest() (*mqlMongodbatlasEncryptionConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	e, httpResp, err := atlasClient(r.MqlRuntime).EncryptionAtRestUsingCustomerKeyManagementAPI.GetEncryptionAtRest(context.Background(), pid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.EncryptionAtRest.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	aws := e.GetAwsKms()
	azure := e.GetAzureKeyVault()
	gcp := e.GetGoogleCloudKms()
	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.encryptionConfig", map[string]*llx.RawData{
		"__id":                  llx.StringData("mongodbatlas.encryptionConfig/" + pid),
		"awsKmsEnabled":         llx.BoolData(aws.GetEnabled()),
		"awsKmsValid":           llx.BoolData(aws.GetValid()),
		"azureKeyVaultEnabled":  llx.BoolData(azure.GetEnabled()),
		"azureKeyVaultValid":    llx.BoolData(azure.GetValid()),
		"googleCloudKmsEnabled": llx.BoolData(gcp.GetEnabled()),
		"googleCloudKmsValid":   llx.BoolData(gcp.GetValid()),
		"enabledForSearchNodes": llx.BoolData(e.GetEnabledForSearchNodes()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasEncryptionConfig), nil
}
