// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

func (r *mqlMongodbatlas) backupCompliancePolicy() (*mqlMongodbatlasBackupComplianceConfig, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	settings, httpResp, err := atlasClient(r.MqlRuntime).CloudBackupsAPI.GetCompliancePolicy(context.Background(), pid).Execute()
	if err != nil {
		// The Backup Compliance Policy is a feature-gated guardrail that is not
		// configured on every project; degrade to null rather than failing the
		// scan when it is unavailable or the credential cannot read it.
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.BackupCompliancePolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.backupComplianceConfig", map[string]*llx.RawData{
		"__id":                    llx.StringData("mongodbatlas.backupComplianceConfig/" + pid),
		"state":                   llx.StringData(settings.GetState()),
		"copyProtectionEnabled":   llx.BoolData(settings.GetCopyProtectionEnabled()),
		"encryptionAtRestEnabled": llx.BoolData(settings.GetEncryptionAtRestEnabled()),
		"pitEnabled":              llx.BoolData(settings.GetPitEnabled()),
		"restoreWindowDays":       llx.IntData(int64(settings.GetRestoreWindowDays())),
		"authorizedEmail":         llx.StringData(settings.GetAuthorizedEmail()),
		"onDemandPolicyItem":      llx.DictData(onDemandPolicyItemDict(settings.OnDemandPolicyItem)),
		"scheduledPolicyItems":    llx.ArrayData(scheduledPolicyItemDicts(settings.ScheduledPolicyItems), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasBackupComplianceConfig), nil
}

func onDemandPolicyItemDict(item *admin.BackupComplianceOnDemandPolicyItem) any {
	if item == nil {
		return nil
	}
	return map[string]any{
		"id":                item.GetId(),
		"frequencyType":     item.GetFrequencyType(),
		"frequencyInterval": int64(item.GetFrequencyInterval()),
		"retentionUnit":     item.GetRetentionUnit(),
		"retentionValue":    int64(item.GetRetentionValue()),
	}
}

func scheduledPolicyItemDicts(items *[]admin.BackupComplianceScheduledPolicyItem) []any {
	out := []any{}
	if items == nil {
		return out
	}
	for _, item := range *items {
		out = append(out, map[string]any{
			"id":                item.GetId(),
			"frequencyType":     item.GetFrequencyType(),
			"frequencyInterval": int64(item.GetFrequencyInterval()),
			"retentionUnit":     item.GetRetentionUnit(),
			"retentionValue":    int64(item.GetRetentionValue()),
		})
	}
	return out
}
