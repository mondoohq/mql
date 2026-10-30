// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jumpcloud/connection"
)

func (r *mqlJumpcloud) id() (string, error) {
	return "jumpcloud", nil
}

func (r *mqlJumpcloud) conn() *connection.JumpcloudConnection {
	return r.MqlRuntime.Connection.(*connection.JumpcloudConnection)
}

func (r *mqlJumpcloud) users() ([]any, error) {
	conn := r.conn()
	list, _, err := conn.Users(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, u := range list {
		res, err := newMqlJumpcloudUser(r.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) systems() ([]any, error) {
	conn := r.conn()
	list, _, err := conn.Systems(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, s := range list {
		res, err := newMqlJumpcloudSystem(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) userGroups() ([]any, error) {
	conn := r.conn()
	list, _, err := conn.UserGroups(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, g := range list {
		res, err := newMqlJumpcloudUserGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) systemGroups() ([]any, error) {
	conn := r.conn()
	list, _, err := conn.SystemGroups(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, g := range list {
		res, err := newMqlJumpcloudSystemGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) applications() ([]any, error) {
	conn := r.conn()
	list, _, err := conn.Applications(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, a := range list {
		res, err := newMqlJumpcloudApplication(r.MqlRuntime, a)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) policies() ([]any, error) {
	conn := r.conn()
	list, err := conn.Client().Policies(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, p := range list {
		res, err := CreateResource(r.MqlRuntime, "jumpcloud.policy", map[string]*llx.RawData{
			"id":           llx.StringData(p.ID),
			"name":         llx.StringData(p.Name),
			"active":       llx.BoolData(p.Active),
			"templateName": llx.StringData(p.TemplateName()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) commands() ([]any, error) {
	conn := r.conn()
	list, err := conn.Client().Commands(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, c := range list {
		res, err := CreateResource(r.MqlRuntime, "jumpcloud.command", map[string]*llx.RawData{
			"id":          llx.StringData(c.EffectiveID()),
			"name":        llx.StringData(c.Name),
			"commandType": llx.StringData(c.CommandType),
			"launchType":  llx.StringData(c.LaunchType),
			"sudo":        llx.BoolData(c.Sudo),
			"timeout":     llx.StringData(c.Timeout),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) radiusServers() ([]any, error) {
	conn := r.conn()
	list, err := conn.Client().RadiusServers(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, rs := range list {
		res, err := CreateResource(r.MqlRuntime, "jumpcloud.radiusServer", map[string]*llx.RawData{
			"id":              llx.StringData(rs.ID),
			"name":            llx.StringData(rs.Name),
			"networkSourceIp": llx.StringData(rs.NetworkSourceIP),
			"mfa":             llx.StringData(rs.MFA),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloud) directories() ([]any, error) {
	conn := r.conn()
	list, err := conn.Client().Directories(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, d := range list {
		res, err := CreateResource(r.MqlRuntime, "jumpcloud.directory", map[string]*llx.RawData{
			"id":   llx.StringData(d.ID),
			"name": llx.StringData(d.Name),
			"type": llx.StringData(d.Type),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlJumpcloudPolicy) id() (string, error) {
	return "jumpcloud.policy/" + r.Id.Data, nil
}

func (r *mqlJumpcloudCommand) id() (string, error) {
	return "jumpcloud.command/" + r.Id.Data, nil
}

func (r *mqlJumpcloudRadiusServer) id() (string, error) {
	return "jumpcloud.radiusServer/" + r.Id.Data, nil
}

func (r *mqlJumpcloudDirectory) id() (string, error) {
	return "jumpcloud.directory/" + r.Id.Data, nil
}

// resolveConn is a small helper shared by the resource files to reach the
// JumpCloud connection from any resource's runtime.
func resolveConn(runtime *plugin.Runtime) *connection.JumpcloudConnection {
	return runtime.Connection.(*connection.JumpcloudConnection)
}
