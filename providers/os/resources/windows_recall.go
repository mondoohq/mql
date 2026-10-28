// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
)

// The WindowsAI policy key exists under both hives: Microsoft documents
// DisableAIDataAnalysis, DisableClickToDo, SetDenyAppListForRecall,
// SetDenyUriListForRecall and the two storage limits as Computer and User
// Configuration policies, and AllowRecallEnablement and AllowRecallExport as
// Computer Configuration only (Policy CSP - WindowsAI).
const (
	windowsAIMachinePolicyPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI`
	windowsAIUserPolicyPath    = `HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\WindowsAI`

	// recallOptionalFeatureName is the feature name Microsoft documents for
	// Enable-WindowsOptionalFeature -FeatureName "Recall".
	recallOptionalFeatureName = "Recall"
)

type mqlWindowsRecallInternal struct {
	lock      sync.Mutex
	populated bool
	err       error
}

func (r *mqlWindowsRecall) id() (string, error) {
	return "windows.recall", nil
}

// recallPolicyValues holds the WindowsAI policy values of one hive. A nil
// pointer or slice means the value is absent, the policy is not configured.
type recallPolicyValues struct {
	enablementAllowed        *bool
	exportAllowed            *bool
	snapshotsDisabled        *bool
	clickToDoDisabled        *bool
	filteredApps             []string
	filteredUris             []string
	maxSnapshotRetentionDays *int64
	maxSnapshotStorageMB     *int64
}

// computeRecallPolicy extracts the WindowsAI policy values from the raw
// registry values of one hive.
func computeRecallPolicy(items map[string]registry.RegistryKeyItem) recallPolicyValues {
	return recallPolicyValues{
		enablementAllowed:        regBoolPtr(items, "AllowRecallEnablement"),
		exportAllowed:            regBoolPtr(items, "AllowRecallExport"),
		snapshotsDisabled:        regBoolPtr(items, "DisableAIDataAnalysis"),
		clickToDoDisabled:        regBoolPtr(items, "DisableClickToDo"),
		filteredApps:             regSemicolonList(items, "SetDenyAppListForRecall"),
		filteredUris:             regSemicolonList(items, "SetDenyUriListForRecall"),
		maxSnapshotRetentionDays: regIntPtr(items, "SetMaximumStorageDurationForRecallSnapshots"),
		maxSnapshotStorageMB:     regIntPtr(items, "SetMaximumStorageSpaceForRecallSnapshots"),
	}
}

// regSemicolonList splits a semicolon-separated REG_SZ policy value into its
// entries, trimming whitespace and dropping empty entries. It returns nil when
// the value is absent and an empty, non-nil slice when the value is present
// but lists nothing, so "not configured" stays distinguishable from "configured
// with an empty list".
func regSemicolonList(items map[string]registry.RegistryKeyItem, name string) []string {
	it, ok := items[strings.ToLower(name)]
	if !ok {
		return nil
	}
	res := []string{}
	for entry := range strings.SplitSeq(it.Value.String, ";") {
		if entry = strings.TrimSpace(entry); entry != "" {
			res = append(res, entry)
		}
	}
	return res
}

// stringListField converts a nullable string list into a TValue, marking the
// field null when the source slice is nil.
func stringListField(v []string) plugin.TValue[[]any] {
	if v == nil {
		return plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	res := make([]any, len(v))
	for i := range v {
		res[i] = v[i]
	}
	return plugin.TValue[[]any]{Data: res, State: plugin.StateIsSet}
}

// populate reads both policy hives once and sets every policy field.
func (r *mqlWindowsRecall) populate() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.populated {
		return r.err
	}
	r.populated = true

	machineItems, err := readRegistryValues(r.MqlRuntime, windowsAIMachinePolicyPath)
	if err != nil {
		r.err = err
		return err
	}
	userItems, err := readRegistryValues(r.MqlRuntime, windowsAIUserPolicyPath)
	if err != nil {
		r.err = err
		return err
	}
	machine := computeRecallPolicy(machineItems)
	user := computeRecallPolicy(userItems)

	r.EnablementAllowed = boolFieldPtr(machine.enablementAllowed)
	r.ExportAllowed = boolFieldPtr(machine.exportAllowed)
	r.SnapshotsDisabled = boolFieldPtr(machine.snapshotsDisabled)
	r.UserSnapshotsDisabled = boolFieldPtr(user.snapshotsDisabled)
	r.ClickToDoDisabled = boolFieldPtr(machine.clickToDoDisabled)
	r.UserClickToDoDisabled = boolFieldPtr(user.clickToDoDisabled)
	r.FilteredApps = stringListField(machine.filteredApps)
	r.UserFilteredApps = stringListField(user.filteredApps)
	r.FilteredUris = stringListField(machine.filteredUris)
	r.UserFilteredUris = stringListField(user.filteredUris)
	r.MaxSnapshotRetentionDays = intFieldPtr(machine.maxSnapshotRetentionDays)
	r.UserMaxSnapshotRetentionDays = intFieldPtr(user.maxSnapshotRetentionDays)
	r.MaxSnapshotStorageMB = intFieldPtr(machine.maxSnapshotStorageMB)
	r.UserMaxSnapshotStorageMB = intFieldPtr(user.maxSnapshotStorageMB)
	return nil
}

func (r *mqlWindowsRecall) enablementAllowed() (bool, error)     { return false, r.populate() }
func (r *mqlWindowsRecall) exportAllowed() (bool, error)         { return false, r.populate() }
func (r *mqlWindowsRecall) snapshotsDisabled() (bool, error)     { return false, r.populate() }
func (r *mqlWindowsRecall) userSnapshotsDisabled() (bool, error) { return false, r.populate() }
func (r *mqlWindowsRecall) clickToDoDisabled() (bool, error)     { return false, r.populate() }
func (r *mqlWindowsRecall) userClickToDoDisabled() (bool, error) { return false, r.populate() }
func (r *mqlWindowsRecall) filteredApps() ([]any, error)         { return nil, r.populate() }
func (r *mqlWindowsRecall) userFilteredApps() ([]any, error)     { return nil, r.populate() }
func (r *mqlWindowsRecall) filteredUris() ([]any, error)         { return nil, r.populate() }
func (r *mqlWindowsRecall) userFilteredUris() ([]any, error)     { return nil, r.populate() }
func (r *mqlWindowsRecall) maxSnapshotRetentionDays() (int64, error) {
	return 0, r.populate()
}

func (r *mqlWindowsRecall) userMaxSnapshotRetentionDays() (int64, error) {
	return 0, r.populate()
}
func (r *mqlWindowsRecall) maxSnapshotStorageMB() (int64, error) { return 0, r.populate() }
func (r *mqlWindowsRecall) userMaxSnapshotStorageMB() (int64, error) {
	return 0, r.populate()
}

// optionalFeature resolves the Recall optional feature. A device that does not
// offer Recall has no such feature, which is a null rather than an error.
func (r *mqlWindowsRecall) optionalFeature() (*mqlWindowsOptionalFeature, error) {
	conn, ok := r.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		r.OptionalFeature.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// the optional feature is Windows-only, like the policy keys
	if err := registryApplicable(conn); err != nil {
		return nil, err
	}
	obj, err := NewResource(r.MqlRuntime, "windows", nil)
	if err != nil {
		return nil, err
	}
	lookup, err := obj.(*mqlWindows).lookupOptionalFeature(conn, recallOptionalFeatureName)
	if err != nil {
		return nil, err
	}
	if lookup.notFound {
		r.OptionalFeature.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "windows.optionalFeature", map[string]*llx.RawData{
		"name": llx.StringData(recallOptionalFeatureName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWindowsOptionalFeature), nil
}
