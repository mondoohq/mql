// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "huggingface-user",
		Title:   "Hugging Face User",
		Family:  []string{"huggingface"},
		Kind:    []string{"api"},
		Runtime: []string{"huggingface"},
	},
	{
		Name:    "huggingface-org",
		Title:   "Hugging Face Organization",
		Family:  []string{"huggingface"},
		Kind:    []string{"api"},
		Runtime: []string{"huggingface"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
