// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/shodan/connection"
)

func (r *mqlShodan) id() (string, error) {
	return "shodan", nil
}

func initShodanProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.ShodanConnection)
	client := conn.Client()
	if client == nil {
		return nil, nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	profile, err := client.AccountProfile(context.Background())
	if err != nil {
		return nil, nil, err
	}

	args["member"] = llx.BoolData(profile.Member)
	args["credits"] = llx.IntData(profile.Credits)
	args["displayName"] = llx.StringData(profile.DisplayName)
	// Shodan account timestamps come back without a timezone, so use the shared
	// parser (which also accepts RFC3339) rather than a strict RFC3339 parse
	// that would silently leave createdAt null.
	args["createdAt"] = optionalShodanTime(profile.Created)

	return args, nil, nil
}

func (r *mqlShodanProfile) id() (string, error) {
	return "shodan/profile", nil
}

func initShodanApiPlan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.ShodanConnection)
	client := conn.Client()
	if client == nil {
		return nil, nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	apiInfo, err := client.ApiInfo(context.Background())
	if err != nil {
		return nil, nil, err
	}

	args["scanCredits"] = llx.IntData(apiInfo.ScanCredits)
	args["plan"] = llx.StringData(apiInfo.Plan)
	args["unlocked"] = llx.BoolData(apiInfo.Unlocked)
	args["unlockedLeft"] = llx.IntData(apiInfo.UnlockedLeft)
	args["telnet"] = llx.BoolData(apiInfo.Telnet)
	args["monitoredIps"] = llx.IntData(apiInfo.MonitoredIps)

	return args, nil, nil
}

func (r *mqlShodanApiPlan) id() (string, error) {
	return "shodan/api-plan", nil
}
