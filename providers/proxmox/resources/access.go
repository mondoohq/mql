// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// mqlProxmoxUserInternal caches the inline token list from
// /access/users?full=1 so `proxmox.users { tokens }` doesn't fan out
// into a per-user /access/users/<id>/token fetch (N+1). It also holds the
// raw group-membership names that groupRefs() resolves, since /access/users
// returns them inline and GetUsers() is not cached.
type mqlProxmoxUserInternal struct {
	cachedTokens    []any
	cachedTokensSet bool
	cachedGroups    []string
}

// splitProxmoxGroups splits the comma-separated group list that
// /access/users returns inline. Returns nil for an empty list.
func splitProxmoxGroups(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func (r *mqlProxmox) groups() ([]any, error) {
	conn := proxmoxConn(r)
	groups, err := conn.GetGroups()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(groups))
	for i, g := range groups {
		var memberIds []any
		if g.Users != "" {
			for _, u := range strings.Split(g.Users, ",") {
				if u = strings.TrimSpace(u); u != "" {
					memberIds = append(memberIds, u)
				}
			}
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.group", map[string]*llx.RawData{
			"id":        llx.StringData(g.GroupID),
			"comment":   llx.StringData(g.Comment),
			"memberIds": llx.ArrayData(memberIds, "\x02"),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxGroup) id() (string, error) {
	return "proxmox.group/" + r.Id.Data, nil
}

func (r *mqlProxmoxGroup) members() ([]any, error) {
	var out []any
	for _, raw := range r.MemberIds.Data {
		uid, ok := raw.(string)
		if !ok || uid == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "proxmox.user", map[string]*llx.RawData{
			"id": llx.StringData(uid),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

func (r *mqlProxmox) acl() ([]any, error) {
	conn := proxmoxConn(r)
	entries, err := conn.GetACL()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(entries))
	for i, e := range entries {
		res, err := CreateResource(r.MqlRuntime, "proxmox.acl", map[string]*llx.RawData{
			"path":      llx.StringData(e.Path),
			"type":      llx.StringData(e.Type),
			"ugid":      llx.StringData(e.UGID),
			"roleId":    llx.StringData(e.RoleID),
			"propagate": llx.BoolData(e.Propagate == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxAcl) id() (string, error) {
	// path + ugid + roleId uniquely identifies an entry; propagate
	// doesn't, but the same path/ugid/roleId can't repeat with
	// different propagation in PVE so this is safe.
	return "proxmox.acl/" + r.Path.Data + "|" + r.Type.Data + "|" + r.Ugid.Data + "|" + r.RoleId.Data, nil
}

func (r *mqlProxmoxAcl) role() (*mqlProxmoxRole, error) {
	res, err := NewResource(r.MqlRuntime, "proxmox.role", map[string]*llx.RawData{
		"id": llx.StringData(r.RoleId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxRole), nil
}

func (r *mqlProxmoxAcl) user() (*mqlProxmoxUser, error) {
	if r.Type.Data != "user" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.user", map[string]*llx.RawData{
		"id": llx.StringData(r.Ugid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxUser), nil
}

func (r *mqlProxmoxAcl) group() (*mqlProxmoxGroup, error) {
	if r.Type.Data != "group" {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.group", map[string]*llx.RawData{
		"id": llx.StringData(r.Ugid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxGroup), nil
}

func (r *mqlProxmoxAcl) token() (*mqlProxmoxToken, error) {
	if r.Type.Data != "token" {
		r.Token.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.token", map[string]*llx.RawData{
		"id": llx.StringData(r.Ugid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxToken), nil
}

// ---------------------------------------------------------------------------
// Realms
// ---------------------------------------------------------------------------

type mqlProxmoxRealmInternal struct {
	configOnce sync.Once
	cfg        map[string]any
	cfgErr     error
}

func (r *mqlProxmox) realms() ([]any, error) {
	conn := proxmoxConn(r)
	realms, err := conn.GetRealms()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(realms))
	for i, rm := range realms {
		res, err := CreateResource(r.MqlRuntime, "proxmox.realm", map[string]*llx.RawData{
			"realm":   llx.StringData(rm.Realm),
			"type":    llx.StringData(rm.Type),
			"comment": llx.StringData(rm.Comment),
			"default": llx.BoolData(rm.Default == 1),
			"tfaType": llx.StringData(realmTFAType(rm.TFA)),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxRealm) id() (string, error) {
	return "proxmox.realm/" + r.Realm.Data, nil
}

func (r *mqlProxmoxRealm) config() (any, error) {
	r.configOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.PveConnection)
		r.cfg, r.cfgErr = conn.GetRealmConfig(r.Realm.Data)
	})
	return r.cfg, r.cfgErr
}

// ---------------------------------------------------------------------------
// User additions — realmType, tfaLockedUntil already populated by users();
// only the lazy tfaFactors() lookup lives here.
// ---------------------------------------------------------------------------

func (r *mqlProxmoxUser) tfaFactors() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	entries, err := conn.GetUserTFA(r.Id.Data)
	if err != nil {
		// /access/tfa/<userid> 403s for non-admins and 404s when the
		// user has nothing enrolled; treat those as "no factors" so an
		// audit over many users isn't blocked by one missing row. Real
		// failures (timeout, 5xx) bubble up.
		if connection.IsAccessDeniedOrNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Type)
	}
	return out, nil
}

// realmTFAType pulls the challenge type out of a realm's `tfa` setting.
//
// /access/domains serializes it as a property string such as
// `type=oath,step=30,digits=6`, and the type is the part that says which
// second factor the realm demands. A value that carries no `type` is returned
// as it stands rather than dropped, since an unparsed setting still means the
// realm enforces something.
//
// Shared by the listing and the single-realm lookup so the two cannot report
// different values for the same realm.
func realmTFAType(raw string) string {
	if raw == "" {
		return ""
	}
	if t := connection.ParsePropertyString(raw, "")["type"]; t != "" {
		return t
	}
	return raw
}
