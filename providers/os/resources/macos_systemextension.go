// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/types"
)

func (m *mqlMacos) systemExtensions() ([]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)

	f, err := conn.FileSystem().Open("/Library/SystemExtensions/db.plist")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	systemExtensionDb, err := plist.Decode(f)
	if err != nil {
		return nil, err
	}

	extensions := systemExtensionDb["extensions"].([]any)
	extensionPolicies := systemExtensionDb["extensionPolicies"].([]any)

	list := []any{}
	for i := range extensions {
		ex, err := newMacosSystemExtension(m.MqlRuntime, extensions[i].(map[string]any), extensionPolicies)
		if err != nil {
			return nil, err
		}
		list = append(list, ex)
	}

	return list, nil
}

func newMacosSystemExtension(runtime *plugin.Runtime, extension plist.Data, extensionPolicies []any) (*mqlMacosSystemExtension, error) {
	uuid, _ := extension.GetString("uniqueID")
	identifier, _ := extension.GetString("identifier")
	teamID, _ := extension.GetString("teamID")
	isMdmManaged := false
	for i := range extensionPolicies {
		policy, ok := extensionPolicies[i].(map[string]any)
		if !ok {
			continue
		}
		plistPolicy := plist.Data(policy)

		// check if the team id is in allowedTeamIDs list
		allowedTeams := plistPolicy.GetPlistData("allowedTeamIDs")
		for k := range allowedTeams {
			list := allowedTeams[k].([]any)
			for j := range list {
				if list[j].(string) == teamID {
					isMdmManaged = true
					break
				}
			}
		}

		// if it is not in the team id list, check allowedExtensions list
		allowedExtensions := plistPolicy.GetPlistData("allowedExtensions")
		for k := range allowedExtensions {
			list := allowedExtensions[k].([]any)
			for j := range list {
				if list[j].(string) == identifier {
					isMdmManaged = true
					break
				}
			}
		}
	}

	version, _ := extension.GetString("bundleVersion", "CFBundleShortVersionString")
	state, _ := extension.GetString("state")
	categories, _ := extension.GetList("categories")
	bundlePath, _ := extension.GetString("container", "bundlePath")

	pkg, err := CreateResource(runtime, "macos.systemExtension", map[string]*llx.RawData{
		"__id":       llx.StringData(uuid),
		"identifier": llx.StringData(identifier),
		"uuid":       llx.StringData(uuid),
		"version":    llx.StringData(version),
		"categories": llx.ArrayData(convert.SliceAnyToInterface(categories), types.String),
		"state":      llx.StringData(state),
		"teamID":     llx.StringData(teamID),
		"bundlePath": llx.StringData(bundlePath),
		"mdmManaged": llx.BoolData(isMdmManaged),
	})
	if err != nil {
		return nil, err
	}

	s := pkg.(*mqlMacosSystemExtension)
	return s, nil
}

func (m *mqlMacosSystemExtension) enabled() (bool, error) {
	state := m.GetState()
	return strings.Contains(state.Data, "enabled"), nil
}

func (m *mqlMacosSystemExtension) active() (bool, error) {
	state := m.GetState()
	return strings.Contains(state.Data, "activated"), nil
}
