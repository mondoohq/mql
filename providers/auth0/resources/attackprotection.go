// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

// initAuth0AttackProtection reads the tenant-wide brute-force, suspicious-IP,
// and breached-password defenses. It is queried directly
// (auth0.attackProtection); its cache key is the tenant domain, since there is
// exactly one attack-protection configuration per tenant.
func initAuth0AttackProtection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	client := conn.Client()
	ctx := context.Background()

	bruteForce, err := client.AttackProtection.GetBruteForceProtection(ctx)
	if err != nil {
		return nil, nil, err
	}
	suspicious, err := client.AttackProtection.GetSuspiciousIPThrottling(ctx)
	if err != nil {
		return nil, nil, err
	}
	breached, err := client.AttackProtection.GetBreachedPasswordDetection(ctx)
	if err != nil {
		return nil, nil, err
	}

	var preLoginMaxAttempts, preRegistrationMaxAttempts *int
	if suspicious.Stage != nil {
		if suspicious.Stage.PreLogin != nil {
			preLoginMaxAttempts = suspicious.Stage.PreLogin.MaxAttempts
		}
		if suspicious.Stage.PreUserRegistration != nil {
			preRegistrationMaxAttempts = suspicious.Stage.PreUserRegistration.MaxAttempts
		}
	}

	args["__id"] = llx.StringData(conn.Domain())
	args["bruteForceEnabled"] = llx.BoolDataPtr(bruteForce.Enabled)
	args["bruteForceMode"] = llx.StringDataPtr(bruteForce.Mode)
	args["bruteForceMaxAttempts"] = llx.IntDataPtr(bruteForce.MaxAttempts)
	args["bruteForceAllowlist"] = llx.ArrayData(strList(bruteForce.AllowList), types.String)
	args["suspiciousIpThrottlingEnabled"] = llx.BoolDataPtr(suspicious.Enabled)
	args["suspiciousIpThrottlingAllowlist"] = llx.ArrayData(strList(suspicious.AllowList), types.String)
	args["suspiciousIpThrottlingPreLoginMaxAttempts"] = llx.IntDataPtr(preLoginMaxAttempts)
	args["suspiciousIpThrottlingPreRegistrationMaxAttempts"] = llx.IntDataPtr(preRegistrationMaxAttempts)
	args["breachedPasswordDetectionEnabled"] = llx.BoolDataPtr(breached.Enabled)
	args["breachedPasswordDetectionMethod"] = llx.StringDataPtr(breached.Method)
	args["breachedPasswordDetectionShields"] = llx.ArrayData(strList(breached.Shields), types.String)
	args["breachedPasswordDetectionAdminNotificationFrequency"] = llx.ArrayData(strList(breached.AdminNotificationFrequency), types.String)
	return args, nil, nil
}
