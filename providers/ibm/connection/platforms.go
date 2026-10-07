// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms this provider can emit. The
// build exports it into dist/ibm.json so the CLI and generated docs can list
// what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "ibm-account", Title: "IBM Cloud Account", Family: []string{"ibm"}, Kind: []string{"api"}, Runtime: []string{"ibm"}},
	{Name: "ibm-vpc-instance", Title: "IBM Cloud VPC Virtual Server", Family: []string{"ibm"}, Kind: []string{"api"}, Runtime: []string{"ibm"}},
	{Name: "ibm-vpc-security-group", Title: "IBM Cloud VPC Security Group", Family: []string{"ibm"}, Kind: []string{"api"}, Runtime: []string{"ibm"}},
	{Name: "ibm-power-workspace", Title: "IBM Power Virtual Server Workspace", Family: []string{"ibm"}, Kind: []string{"api"}, Runtime: []string{"ibm"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
