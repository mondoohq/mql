// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// QUERY_OPTIONAL_FEATURES lists every optional feature with its state. Without
// -FeatureName, DISM answers from the feature list alone; the display name and
// description are not part of that list, they require a per-feature image query
// (see QUERY_OPTIONAL_FEATURE_DETAILS).
const QUERY_OPTIONAL_FEATURES = "Get-WindowsOptionalFeature -Online | Select-Object -Property FeatureName,State | ConvertTo-Json"

// QUERY_OPTIONAL_FEATURE_DETAILS is the expensive form: -FeatureName makes DISM
// look up detailed information for every feature it matches, which is why it is
// only used to back the lazily loaded display name and description fields.
const QUERY_OPTIONAL_FEATURE_DETAILS = "Get-WindowsOptionalFeature -Online -FeatureName * | Select-Object -Property FeatureName,DisplayName,Description,State | ConvertTo-Json"

// OptionalFeatureQuery builds a PowerShell command that retrieves a single
// optional feature by name, which is much cheaper than enumerating the whole
// image with `-FeatureName *`. The name is wrapped in a single-quoted string
// with embedded quotes doubled. PowerShell single-quoted strings are fully
// literal — no $variable, no $(...) subexpression, no backtick escapes — so
// the value cannot break out of the string or inject commands. DISM does
// still treat `*` and `?` in the name as wildcards, so the caller must match
// the returned feature name exactly (see initWindowsOptionalFeature).
func OptionalFeatureQuery(name string) string {
	escaped := strings.ReplaceAll(name, "'", "''")
	return "Get-WindowsOptionalFeature -Online -FeatureName '" + escaped + "' | Select-Object -Property FeatureName,DisplayName,Description,State | ConvertTo-Json"
}

type WindowsOptionalFeature struct {
	Name        string `json:"FeatureName"`
	DisplayName string `json:"DisplayName"`
	Description string `json:"Description"`
	Enabled     bool   `json:"Enabled"`
	State       int64  `json:"State"`
}

func ParseWindowsOptionalFeatures(input io.Reader) ([]WindowsOptionalFeature, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return []WindowsOptionalFeature{}, nil
	}

	// ConvertTo-Json emits a single object (not an array) for one feature;
	// handle both shapes so callers get a consistent slice.
	var winFeatures []WindowsOptionalFeature
	if data[0] == '{' {
		var single WindowsOptionalFeature
		if err = json.Unmarshal(data, &single); err != nil {
			return nil, err
		}
		winFeatures = []WindowsOptionalFeature{single}
	} else if err = json.Unmarshal(data, &winFeatures); err != nil {
		return nil, err
	}

	for i := range winFeatures {
		if winFeatures[i].State == 2 {
			winFeatures[i].Enabled = true
		}
	}

	return winFeatures, nil
}
