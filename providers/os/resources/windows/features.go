// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"io"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const QUERY_FEATURES = "Get-WindowsFeature | Select-Object -Property Path,Name,DisplayName,Description,Installed,InstallState,FeatureType,DependsOn,Parent,SubFeatures | ConvertTo-Json"

type WindowsFeature struct {
	Name         string   `json:"Name"`
	DisplayName  string   `json:"DisplayName"`
	Description  string   `json:"Description"`
	Installed    bool     `json:"Installed"`
	InstallState int64    `json:"InstallState"`
	FeatureType  string   `json:"FeatureType"`
	Path         string   `json:"Path"`
	DependsOn    []string `json:"DependsOn"`
	Parent       *string  `json:"Parent"`
	SubFeatures  []string `json:"SubFeatures"`
}

func ParseWindowsFeatures(input io.Reader) ([]WindowsFeature, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	if len(data) == 0 {
		return []WindowsFeature{}, nil
	}

	winFeatures, err := powershell.UnmarshalList[WindowsFeature](data)
	if err != nil {
		return nil, err
	}

	return winFeatures, nil
}
