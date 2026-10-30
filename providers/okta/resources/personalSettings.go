// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

// initOktaPersonalSettings populates the singleton on construction. It is an
// init rather than an okta accessor because a field accessor on a resource of
// the same name is skipped when the runtime constructs the bare resource.
//
// An org that is not licensed for Okta Personal reports the block list as null
// rather than as an empty list. The two readings are opposite: an empty list
// bars no email domain from carrying application credentials out of the org,
// which is a finding, while a null says the question was never answered.
func initOktaPersonalSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	args["__id"] = llx.StringData("okta.personalSettings")
	args["blockedEmailDomains"] = llx.NilData

	blockList, resp, err := client.OktaPersonalSettingsAPI.ListPersonalAppsExportBlockList(ctx).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return args, nil, nil
		}
		return nil, nil, err
	}
	if blockList == nil {
		return args, nil, nil
	}

	args["blockedEmailDomains"] = llx.ArrayData(convert.SliceAnyToInterface(blockList.Domains), types.String)

	return args, nil, nil
}
