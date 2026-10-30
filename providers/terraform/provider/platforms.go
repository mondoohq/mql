// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "terraform-state",
		Title:   "Terraform State",
		Family:  []string{"terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"terraform"},
	},
	{
		Name:    "terraform-plan",
		Title:   "Terraform Plan",
		Family:  []string{"terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"terraform"},
	},
	{
		Name:    "terraform-hcl",
		Title:   "Terraform HCL",
		Family:  []string{"terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"terraform"},
	},
	// OpenTofu assets carry "terraform" in their family chain as well as their
	// own name. The two tools share the HCL language and the `show -json`
	// representation, so a policy written against the terraform family applies
	// unchanged to an OpenTofu asset, while the platform name and title still
	// identify which tool the configuration is for.
	{
		Name:    "opentofu-state",
		Title:   "OpenTofu State",
		Family:  []string{"opentofu", "terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"opentofu"},
	},
	{
		Name:    "opentofu-plan",
		Title:   "OpenTofu Plan",
		Family:  []string{"opentofu", "terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"opentofu"},
	},
	{
		Name:    "opentofu-hcl",
		Title:   "OpenTofu HCL",
		Family:  []string{"opentofu", "terraform"},
		Kind:    []string{"code"},
		Runtime: []string{"opentofu"},
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
