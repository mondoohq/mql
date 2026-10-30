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

// initOktaBotProtection populates the singleton on construction. It is an init
// rather than an okta accessor because a field accessor on a resource of the
// same name is skipped when the runtime constructs the bare resource.
//
// Bot protection is a licensed add-on, so most orgs answer that it is
// unavailable. Every field then stays null rather than taking a value: a mode
// of "" would read as a configured-and-inactive protection, and a check
// written against it would pass on an org that has no bot protection at all.
func initOktaBotProtection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	args["__id"] = llx.StringData("okta.botProtection")
	args["mode"] = llx.NilData
	args["level"] = llx.NilData
	args["enforcementType"] = llx.NilData
	args["supportedFlows"] = llx.NilData

	config, resp, err := client.BotProtectionAPI.GetBotProtectionConfiguration(ctx).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return args, nil, nil
		}
		return nil, nil, err
	}
	if config == nil {
		return args, nil, nil
	}

	args["mode"] = llx.StringData(config.Mode)
	args["level"] = llx.StringData(config.Level)
	args["enforcementType"] = llx.StringDataPtr(config.EnforcementType)
	args["supportedFlows"] = llx.ArrayData(convert.SliceAnyToInterface(config.SupportedFlows), types.String)

	return args, nil, nil
}
