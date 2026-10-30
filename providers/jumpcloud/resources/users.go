// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jumpcloud/connection"
)

func newMqlJumpcloudUser(runtime *plugin.Runtime, u *connection.SystemUser) (*mqlJumpcloudUser, error) {
	res, err := CreateResource(runtime, "jumpcloud.user", map[string]*llx.RawData{
		"id":                         llx.StringData(u.EffectiveID()),
		"username":                   llx.StringData(u.Username),
		"email":                      llx.StringData(u.Email),
		"firstname":                  llx.StringData(u.Firstname),
		"lastname":                   llx.StringData(u.Lastname),
		"displayname":                llx.StringData(u.Displayname),
		"activated":                  llx.BoolData(u.Activated),
		"suspended":                  llx.BoolData(u.Suspended),
		"accountLocked":              llx.BoolData(u.AccountLocked),
		"passwordExpired":            llx.BoolData(u.PasswordExpired),
		"passwordNeverExpires":       llx.BoolDataPtr(u.PasswordNeverExpires),
		"passwordExpirationDate":     llx.TimeDataPtr(connection.ParseTimePtr(u.PasswordExpirationDate)),
		"mfaConfigured":              llx.BoolData(connection.UserMFAConfigured(u)),
		"mfaExclusion":               llx.BoolDataPtr(connection.UserMFAExclusion(u)),
		"mfaExclusionUntil":          llx.TimeDataPtr(connection.UserMFAExclusionUntil(u)),
		"mfaEnrollmentOverallStatus": llx.StringDataPtr(connection.UserMFAEnrollmentOverallStatus(u)),
		"totpEnabled":                llx.BoolData(u.TotpEnabled),
		"totpStatus":                 llx.StringDataPtr(connection.UserMFATotpStatus(u)),
		"webAuthnStatus":             llx.StringDataPtr(connection.UserMFAWebAuthnStatus(u)),
		"pushStatus":                 llx.StringDataPtr(connection.UserMFAPushStatus(u)),
		"passwordlessSudo":           llx.BoolData(u.PasswordlessSudo),
		"sudo":                       llx.BoolData(u.Sudo),
		"ldapBindingUser":            llx.BoolData(u.LdapBindingUser),
		"enableManagedUid":           llx.BoolData(u.EnableManagedUID),
		"state":                      llx.StringData(u.State),
		"created":                    llx.TimeDataPtr(connection.ParseTime(u.Created)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJumpcloudUser), nil
}

func (u *mqlJumpcloudUser) id() (string, error) {
	return "jumpcloud.user/" + u.Id.Data, nil
}

// userGroups resolves the user groups the account is a member of via the
// v2 membership graph, mapping each target id to the group already cached on
// the connection.
func (u *mqlJumpcloudUser) userGroups() ([]any, error) {
	conn := resolveConn(u.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/users", u.Id.Data, "memberof"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.UserGroups(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		g, ok := idx[id]
		if !ok {
			g, err = conn.Client().GetUserGroup(ctx, id)
			if err != nil {
				log.Warn().Str("userGroup", id).Err(err).Msg("jumpcloud: failed to resolve associated user group")
				continue
			}
		}
		res, err := newMqlJumpcloudUserGroup(u.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// systems resolves the systems the account is associated with via the v2
// association graph, mapping each target id to the system already cached on the
// connection.
func (u *mqlJumpcloudUser) systems() ([]any, error) {
	conn := resolveConn(u.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/users", u.Id.Data, "systems"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.Systems(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		s, ok := idx[id]
		if !ok {
			s, err = conn.Client().GetSystem(ctx, id)
			if err != nil {
				log.Warn().Str("system", id).Err(err).Msg("jumpcloud: failed to resolve associated system")
				continue
			}
		}
		res, err := newMqlJumpcloudSystem(u.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
