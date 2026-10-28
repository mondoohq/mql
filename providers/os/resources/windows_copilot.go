// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/os/registry"
)

// Microsoft documents TurnOffWindowsCopilot as a User Configuration policy
// only (Policy CSP - WindowsAI), so only the user hive is read.
const windowsCopilotUserPolicyPath = `HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot`

func (r *mqlWindowsCopilot) id() (string, error) {
	return "windows.copilot", nil
}

// computeCopilotTurnedOff reads TurnOffWindowsCopilot from the raw registry
// values: 1 turns Copilot off, 0 leaves it on, and an absent value is nil.
func computeCopilotTurnedOff(items map[string]registry.RegistryKeyItem) *bool {
	return regBoolPtr(items, "TurnOffWindowsCopilot")
}

func (r *mqlWindowsCopilot) turnedOff() (bool, error) {
	items, err := readRegistryValues(r.MqlRuntime, windowsCopilotUserPolicyPath)
	if err != nil {
		return false, err
	}
	v := computeCopilotTurnedOff(items)
	r.TurnedOff = boolFieldPtr(v)
	if v == nil {
		return false, nil
	}
	return *v, nil
}
