// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"sync"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/groups"
)

type mqlGroupInternal struct {
	membersArr []string
}

func initGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	// if user is only initialized with a name or uid, we will try to look it up
	rawName, nameOk := args["name"]
	rawGID, idOk := args["gid"]
	if !nameOk && !idOk {
		return args, nil, nil
	}

	raw, err := CreateResource(runtime, "groups", nil)
	if err != nil {
		return nil, nil, errors.New("cannot get list of groups: " + err.Error())
	}
	groups := raw.(*mqlGroups)

	if err := groups.refreshCache(nil); err != nil {
		return nil, nil, err
	}

	if nameOk {
		name, ok := rawName.Value.(string)
		if !ok {
			return nil, nil, errors.New("cannot detect group, invalid type for name (expected string)")
		}
		group, ok := groups.groupsByName[name]
		if !ok {
			return nil, nil, errors.New("cannot find group with name '" + name + "'")
		}
		return nil, group, nil
	}

	if idOk {
		id, ok := rawGID.Value.(int64)
		if !ok {
			return nil, nil, errors.New("cannot detect group, invalid type for name (expected int)")
		}
		group, ok := groups.groupsByID[id]
		if !ok {
			return nil, nil, errors.New("cannot find group with UID '" + strconv.Itoa(int(id)) + "'")
		}
		return nil, group, nil
	}

	return nil, nil, errors.New("cannot find group, no search criteria provided")
}

func (x *mqlGroup) id() (string, error) {
	var id string
	if len(x.Sid.Data) > 0 {
		id = x.Sid.Data
	} else {
		id = strconv.FormatInt(x.Gid.Data, 10)
	}

	return "group/" + id + "/" + x.Name.Data, nil
}

func (x *mqlGroup) members() ([]any, error) {
	raw, err := CreateResource(x.MqlRuntime, "users", nil)
	if err != nil {
		return nil, errors.New("cannot get users info for group: " + err.Error())
	}
	users := raw.(*mqlUsers)

	if err := users.refreshCache(nil); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(x.membersArr))
	for _, name := range x.membersArr {
		if name == "" {
			continue
		}
		user, ok := users.usersByName[name]
		if !ok {
			continue
		}
		res = append(res, user)
	}

	return res, nil
}

type mqlGroupsInternal struct {
	lock         sync.Mutex
	groupsByID   map[int64]*mqlGroup
	groupsByName map[string]*mqlGroup
}

func (x *mqlGroups) list() ([]any, error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	// in the unlikely case that we get called twice into the same method,
	// any subsequent calls are locked until user detection finishes; at this point
	// we only need to return a non-nil error field and it will pull the data from cache
	if x.groupsByID != nil {
		return nil, nil
	}
	x.groupsByID = map[int64]*mqlGroup{}

	conn := x.MqlRuntime.Connection.(shared.Connection)
	gm, err := groups.ResolveManager(conn)
	if gm == nil || err != nil {
		return nil, errors.New("cannot find groups manager")
	}

	groups, err := gm.List()
	if err != nil {
		return nil, errors.New("could not retrieve groups list")
	}

	var res []any
	for i := range groups {
		group := groups[i]
		nu, err := CreateResource(x.MqlRuntime, "group", map[string]*llx.RawData{
			"name": llx.StringData(group.Name),
			"gid":  llx.IntData(group.Gid),
			"sid":  llx.StringData(group.Sid),
		})
		if err != nil {
			return nil, err
		}

		res = append(res, nu)

		g := nu.(*mqlGroup)
		g.membersArr = group.Members
	}

	return res, x.refreshCache(res)
}

func (x *mqlGroups) refreshCache(all []any) error {
	if all == nil {
		raw := x.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	x.groupsByID = map[int64]*mqlGroup{}
	x.groupsByName = map[string]*mqlGroup{}

	for i := range all {
		g := all[i].(*mqlGroup)
		x.groupsByID[g.Gid.Data] = g
		x.groupsByName[g.Name.Data] = g
	}

	return nil
}

func (x *mqlGroups) findID(id int64) (*mqlGroup, error) {
	if x := x.GetList(); x.Error != nil {
		return nil, x.Error
	}

	res, ok := x.groupsByID[id]
	if !ok {
		return nil, errors.New("cannot find group for uid " + strconv.Itoa(int(id)))
	}
	return res, nil
}
