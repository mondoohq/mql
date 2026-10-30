// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations that back windows.telemetry. Both are GPO-only policy keys
// holding DWORD values. When a value is absent the policy is "not configured",
// which is reported as null rather than an explicit 0 — the two states are
// security-relevant and must remain distinguishable.
const (
	telemetryDataCollectionPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
	telemetryCloudContentPath   = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
)

func (r *mqlWindowsTelemetry) id() (string, error) {
	return "windows.telemetry", nil
}

// readTelemetryKey reads a single registry key and returns its values keyed by
// the lower-cased value name. A missing key yields an empty map rather than an
// error, so every value resolves to null (not configured) instead of failing.
// The registrykey resource is de-duplicated by the runtime, so the per-field
// accessors that share a key path do not trigger repeated registry reads.
func (r *mqlWindowsTelemetry) readTelemetryKey(path string) (map[string]registry.RegistryKeyItem, error) {
	items := map[string]registry.RegistryKeyItem{}
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. no Group Policy configured); treat it
		// as empty so each value resolves to null
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return items, nil
		}
		return nil, err
	}

	for i := range entries {
		items[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return items, nil
}

// telemetryValues holds the nullable DataCollection diagnostic-data settings.
type telemetryValues struct {
	allowTelemetry                 *int64
	disableEnterpriseAuthProxy     *bool
	disableOneSettingsDownloads    *bool
	doNotShowFeedbackNotifications *bool
	enableOneSettingsAuditing      *bool
	limitDiagnosticLogCollection   *bool
	limitDumpCollection            *bool
}

// consumerContentValues holds the nullable CloudContent consumer settings.
type consumerContentValues struct {
	disableCloudOptimizedContent       *bool
	disableConsumerAccountStateContent *bool
	disableWindowsConsumerFeatures     *bool
}

// computeTelemetry extracts the DataCollection diagnostic-data DWORDs from the
// raw registry values. Each field is nil when its value is absent. Pure function
// for unit testing.
func computeTelemetry(items map[string]registry.RegistryKeyItem) telemetryValues {
	return telemetryValues{
		allowTelemetry:                 regIntPtr(items, "AllowTelemetry"),
		disableEnterpriseAuthProxy:     regBoolPtr(items, "DisableEnterpriseAuthProxy"),
		disableOneSettingsDownloads:    regBoolPtr(items, "DisableOneSettingsDownloads"),
		doNotShowFeedbackNotifications: regBoolPtr(items, "DoNotShowFeedbackNotifications"),
		enableOneSettingsAuditing:      regBoolPtr(items, "EnableOneSettingsAuditing"),
		limitDiagnosticLogCollection:   regBoolPtr(items, "LimitDiagnosticLogCollection"),
		limitDumpCollection:            regBoolPtr(items, "LimitDumpCollection"),
	}
}

// computeConsumerContent extracts the CloudContent consumer DWORDs from the raw
// registry values. Each field is nil when its value is absent. Pure function for
// unit testing.
func computeConsumerContent(items map[string]registry.RegistryKeyItem) consumerContentValues {
	return consumerContentValues{
		disableCloudOptimizedContent:       regBoolPtr(items, "DisableCloudOptimizedContent"),
		disableConsumerAccountStateContent: regBoolPtr(items, "DisableConsumerAccountStateContent"),
		disableWindowsConsumerFeatures:     regBoolPtr(items, "DisableWindowsConsumerFeatures"),
	}
}

// telemetryIntField converts a nullable DWORD pointer into a TValue, marking the
// field null (rather than an explicit 0) when the policy value was absent.
func telemetryIntField(v *int64) plugin.TValue[int64] {
	if v == nil {
		return plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[int64]{Data: *v, State: plugin.StateIsSet}
}

// populate reads the DataCollection and CloudContent keys once and sets every
// field directly. The runtime's GetOrCompute wrapper only invokes this until the
// fields are set, so the registry items are parsed a single time and all ten
// accessors share one error-handling path.
func (r *mqlWindowsTelemetry) populate() error {
	dataCollection, err := r.readTelemetryKey(telemetryDataCollectionPath)
	if err != nil {
		return err
	}
	cloudContent, err := r.readTelemetryKey(telemetryCloudContentPath)
	if err != nil {
		return err
	}
	v := computeTelemetry(dataCollection)
	c := computeConsumerContent(cloudContent)

	r.AllowTelemetry = telemetryIntField(v.allowTelemetry)
	r.DisableEnterpriseAuthProxy = boolFieldPtr(v.disableEnterpriseAuthProxy)
	r.DisableOneSettingsDownloads = boolFieldPtr(v.disableOneSettingsDownloads)
	r.DoNotShowFeedbackNotifications = boolFieldPtr(v.doNotShowFeedbackNotifications)
	r.EnableOneSettingsAuditing = boolFieldPtr(v.enableOneSettingsAuditing)
	r.LimitDiagnosticLogCollection = boolFieldPtr(v.limitDiagnosticLogCollection)
	r.LimitDumpCollection = boolFieldPtr(v.limitDumpCollection)
	r.DisableCloudOptimizedContent = boolFieldPtr(c.disableCloudOptimizedContent)
	r.DisableConsumerAccountStateContent = boolFieldPtr(c.disableConsumerAccountStateContent)
	r.DisableWindowsConsumerFeatures = boolFieldPtr(c.disableWindowsConsumerFeatures)
	return nil
}

func (r *mqlWindowsTelemetry) allowTelemetry() (int64, error)             { return 0, r.populate() }
func (r *mqlWindowsTelemetry) disableEnterpriseAuthProxy() (bool, error)  { return false, r.populate() }
func (r *mqlWindowsTelemetry) disableOneSettingsDownloads() (bool, error) { return false, r.populate() }
func (r *mqlWindowsTelemetry) doNotShowFeedbackNotifications() (bool, error) {
	return false, r.populate()
}
func (r *mqlWindowsTelemetry) enableOneSettingsAuditing() (bool, error) { return false, r.populate() }
func (r *mqlWindowsTelemetry) limitDiagnosticLogCollection() (bool, error) {
	return false, r.populate()
}
func (r *mqlWindowsTelemetry) limitDumpCollection() (bool, error) { return false, r.populate() }

func (r *mqlWindowsTelemetry) disableCloudOptimizedContent() (bool, error) {
	return false, r.populate()
}
func (r *mqlWindowsTelemetry) disableConsumerAccountStateContent() (bool, error) {
	return false, r.populate()
}
func (r *mqlWindowsTelemetry) disableWindowsConsumerFeatures() (bool, error) {
	return false, r.populate()
}
