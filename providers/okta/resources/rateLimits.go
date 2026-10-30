// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// initOktaRateLimitSettings assembles the singleton from the three endpoints
// Okta splits rate limit configuration across. Each is fetched through the init
// (rather than as a field accessor) because a field accessor on a resource of
// the same name is skipped when the runtime constructs the bare resource.
//
// Every field is given an explicit value even when its endpoint is unavailable:
// leaving a bool null would make an `a && b` assertion pass without anything
// having been verified.
func initOktaRateLimitSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	args["__id"] = llx.StringData("okta.rateLimitSettings")
	args["perClientDefaultMode"] = llx.StringData("")
	args["useCaseModeOverrides"] = llx.DictData(map[string]any{})
	args["adminNotificationsEnabled"] = llx.BoolData(false)
	args["warningThreshold"] = llx.IntData(0)

	perClient, resp, err := client.RateLimitSettingsAPI.GetRateLimitSettingsPerClient(ctx).Execute()
	if err != nil {
		if !isOktaFeatureUnavailable(resp, err) {
			return nil, nil, err
		}
	} else if perClient != nil {
		args["perClientDefaultMode"] = llx.StringData(perClient.DefaultMode)

		overrides := map[string]any{}
		if o := perClient.UseCaseModeOverrides; o != nil {
			for key, value := range map[string]*string{
				"LOGIN_PAGE":       o.LOGIN_PAGE,
				"OAUTH2_AUTHORIZE": o.OAUTH2AUTHORIZE,
				"OIE_APP_INTENT":   o.OIE_APP_INTENT,
			} {
				if value != nil {
					overrides[key] = *value
				}
			}
		}
		args["useCaseModeOverrides"] = llx.DictData(overrides)
	}

	notifications, resp, err := client.RateLimitSettingsAPI.GetRateLimitSettingsAdminNotifications(ctx).Execute()
	if err != nil {
		if !isOktaFeatureUnavailable(resp, err) {
			return nil, nil, err
		}
	} else if notifications != nil {
		args["adminNotificationsEnabled"] = llx.BoolData(notifications.NotificationsEnabled)
	}

	threshold, resp, err := client.RateLimitSettingsAPI.GetRateLimitSettingsWarningThreshold(ctx).Execute()
	if err != nil {
		if !isOktaFeatureUnavailable(resp, err) {
			return nil, nil, err
		}
	} else if threshold != nil && threshold.WarningThreshold != nil {
		args["warningThreshold"] = llx.IntData(int64(*threshold.WarningThreshold))
	}

	return args, nil, nil
}
