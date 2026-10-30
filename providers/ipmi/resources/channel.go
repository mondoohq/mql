// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
	"go.mondoo.com/mql/types"
)

func (r *mqlIpmi) channels() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)

	channels, err := conn.Client().Channels()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(channels))
	for i := range channels {
		ch := channels[i]

		// The channel number is the only dimension a channel repeats along:
		// a controller reports each number at most once.
		args := map[string]*llx.RawData{
			"__id":               llx.StringData("ipmi.channel/" + strconv.FormatInt(ch.ID, 10)),
			"id":                 llx.IntData(ch.ID),
			"mediumType":         llx.StringData(ch.MediumType),
			"protocolType":       llx.StringData(ch.ProtocolType),
			"sessionSupport":     llx.StringData(ch.SessionSupport),
			"activeSessionCount": llx.IntData(ch.ActiveSessionCount),
		}
		setChannelAccessArgs(args, ch.Access, "accessMode", "privilegeLimit", "alertingEnabled")
		setChannelAccessArgs(args, ch.NonVolatileAccess, "nonVolatileAccessMode", "nonVolatilePrivilegeLimit", "")
		setChannelAuthArgs(args, ch.Auth)

		mqlChannel, err := CreateResource(r.MqlRuntime, "ipmi.channel", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlChannel)
	}

	return res, nil
}

// setChannelAccessArgs fills one set of channel access fields. A controller
// that implements a channel may still refuse Get Channel Access on it, in
// which case the fields stay null rather than reporting a disabled channel
// that was never read.
func setChannelAccessArgs(args map[string]*llx.RawData, access *client.ChannelAccess, modeField, privilegeField, alertingField string) {
	if access == nil {
		args[modeField] = llx.NilData
		args[privilegeField] = llx.NilData
		if alertingField != "" {
			args[alertingField] = llx.NilData
		}
		return
	}
	args[modeField] = llx.StringData(access.AccessMode)
	args[privilegeField] = llx.StringData(access.PrivilegeLimit)
	if alertingField != "" {
		args[alertingField] = llx.BoolData(access.AlertingEnabled)
	}
}

func setChannelAuthArgs(args map[string]*llx.RawData, auth *client.ChannelAuthCapabilities) {
	if auth == nil {
		for _, field := range []string{
			"authTypes",
			"anonymousLoginEnabled",
			"nullUsernamesEnabled",
			"nonNullUsernamesEnabled",
			"perMessageAuthenticationEnabled",
			"userLevelAuthenticationEnabled",
			"kgConfigured",
			"supportsIpmi15",
			"supportsIpmi20",
		} {
			args[field] = llx.NilData
		}
		return
	}

	authTypes := make([]any, 0, len(auth.AuthTypes))
	for _, t := range auth.AuthTypes {
		authTypes = append(authTypes, t)
	}

	args["authTypes"] = llx.ArrayData(authTypes, types.String)
	args["anonymousLoginEnabled"] = llx.BoolData(auth.AnonymousLoginEnabled)
	args["nullUsernamesEnabled"] = llx.BoolData(auth.NullUsernamesEnabled)
	args["nonNullUsernamesEnabled"] = llx.BoolData(auth.NonNullUsernamesEnabled)
	args["perMessageAuthenticationEnabled"] = llx.BoolData(auth.PerMessageAuthenticationEnabled)
	args["userLevelAuthenticationEnabled"] = llx.BoolData(auth.UserLevelAuthenticationEnabled)
	args["kgConfigured"] = llx.BoolData(auth.KgConfigured)
	args["supportsIpmi15"] = llx.BoolData(auth.SupportsIpmi15)
	args["supportsIpmi20"] = llx.BoolData(auth.SupportsIpmi20)
}
