// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sort"

	"github.com/gocql/gocql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlYugabyteYcql) id() (string, error) {
	return "yugabyte.ycql", nil
}

func (r *mqlYugabyteYcql) authenticationEnabled() (bool, error) {
	return tserverFlagEverywhere(r.MqlRuntime, "use_cassandra_authentication")
}

func (r *mqlYugabyteYcql) tlsEnabled() (bool, error) {
	return tserverFlagEverywhere(r.MqlRuntime, "use_client_to_server_encryption")
}

// cqlErrUnauthorized is the CQL error code for a refused read (0x2100).
const cqlErrUnauthorized = 0x2100

func isCQLUnauthorized(err error) bool {
	var re gocql.RequestError
	return errors.As(err, &re) && re.Code() == cqlErrUnauthorized
}

// ycqlRoleRow is one role of system_auth.roles. The password hash stays in
// this unexported row, which no field returns; it is only checked, on
// demand, because a bcrypt check costs about a quarter second.
type ycqlRoleRow struct {
	name        string
	isSuperuser bool
	canLogin    bool
	memberOf    []string
	hasPassword bool
	hash        string
}

func ycqlRoleRows(runtime *plugin.Runtime) ([]ycqlRoleRow, error) {
	v, err := ybConnection(runtime).Memo("ycqlRoles", func() (any, error) {
		session, err := ybConnection(runtime).YCQL()
		if err != nil {
			return nil, err
		}
		iter := session.Query(`SELECT role, is_superuser, can_login, member_of, salted_hash FROM system_auth.roles`).Iter()
		list := []ycqlRoleRow{}
		var name, hash string
		var isSuperuser, canLogin bool
		var memberOf []string
		for iter.Scan(&name, &isSuperuser, &canLogin, &memberOf, &hash) {
			mo := append([]string{}, memberOf...)
			sort.Strings(mo)
			list = append(list, ycqlRoleRow{
				name:        name,
				isSuperuser: isSuperuser,
				canLogin:    canLogin,
				memberOf:    mo,
				hasPassword: trimNUL(hash) != "",
				hash:        hash,
			})
			hash = ""
		}
		if err := iter.Close(); err != nil {
			if isCQLUnauthorized(err) {
				return nil, llx.Forbidden(err, llx.WithPermissions("SELECT ON system_auth.roles"))
			}
			return nil, err
		}
		sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
		return list, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]ycqlRoleRow), nil
}

func trimNUL(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

func ycqlRoleArgs(row ycqlRoleRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("yugabyte.ycql.role/" + row.name),
		"name":        llx.StringData(row.name),
		"isSuperuser": llx.BoolData(row.isSuperuser),
		"canLogin":    llx.BoolData(row.canLogin),
		"hasPassword": llx.BoolData(row.hasPassword),
	}
}

func (r *mqlYugabyteYcqlRole) id() (string, error) {
	return "yugabyte.ycql.role/" + r.Name.Data, nil
}

// initYugabyteYcqlRole resolves a role by name, for memberOf.
func initYugabyteYcqlRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["name"]
	if !ok {
		return nil, nil, fmt.Errorf("yugabyte.ycql.role needs a name")
	}
	name, _ := raw.Value.(string)
	row, err := findYcqlRole(runtime, name)
	if err != nil {
		return nil, nil, err
	}
	return ycqlRoleArgs(row), nil, nil
}

func findYcqlRole(runtime *plugin.Runtime, name string) (ycqlRoleRow, error) {
	rows, err := ycqlRoleRows(runtime)
	if err != nil {
		return ycqlRoleRow{}, err
	}
	for _, row := range rows {
		if row.name == name {
			return row, nil
		}
	}
	return ycqlRoleRow{}, fmt.Errorf("yugabyte.ycql.role %q not found", name)
}

func (r *mqlYugabyteYcql) roles() ([]any, error) {
	rows, err := ycqlRoleRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(rows))
	for _, row := range rows {
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ycql.role", ycqlRoleArgs(row))
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteYcqlRole) memberOf() ([]any, error) {
	row, err := findYcqlRole(r.MqlRuntime, r.Name.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(row.memberOf))
	for _, name := range row.memberOf {
		res, err := NewResource(r.MqlRuntime, "yugabyte.ycql.role", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteYcqlRole) passwordEqualsName() (bool, error) {
	row, err := findYcqlRole(r.MqlRuntime, r.Name.Data)
	if err != nil {
		return false, err
	}
	return ycqlPasswordMatches(row.hash, row.name), nil
}

func (r *mqlYugabyteYcql) keyspaces() ([]any, error) {
	session, err := ybConnection(r.MqlRuntime).YCQL()
	if err != nil {
		return nil, err
	}
	iter := session.Query(`SELECT keyspace_name, durable_writes, replication FROM system_schema.keyspaces`).Iter()
	type ks struct {
		name        string
		durable     bool
		replication map[string]string
	}
	var all []ks
	var name string
	var durable bool
	var replication map[string]string
	for iter.Scan(&name, &durable, &replication) {
		rep := make(map[string]string, len(replication))
		for k, v := range replication {
			rep[k] = v
		}
		all = append(all, ks{name: name, durable: durable, replication: rep})
		replication = nil
	}
	if err := iter.Close(); err != nil {
		if isCQLUnauthorized(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("SELECT ON system_schema.keyspaces"))
		}
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	list := make([]any, 0, len(all))
	for _, k := range all {
		rep := make(map[string]any, len(k.replication))
		for key, v := range k.replication {
			rep[key] = v
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ycql.keyspace", map[string]*llx.RawData{
			"__id":          llx.StringData("yugabyte.ycql.keyspace/" + k.name),
			"name":          llx.StringData(k.name),
			"durableWrites": llx.BoolData(k.durable),
			"replication":   llx.MapData(rep, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
