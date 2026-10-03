// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func (r *mqlMongo) id() (string, error) {
	return "mongo", nil
}

// isUnauthorized reports whether an error is a MongoDB authorization failure
// (command error code 13). Only these should be treated as "not visible";
// every other error must propagate.
func isUnauthorized(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.Code == 13
	}
	return false
}

// classifyRefusal wraps a MongoDB authorization failure (code 13) in the error
// kind it stands for, naming the action the command needed. MongoDB answers an
// unauthenticated connection with the same code, so the message decides
// between the two. Any other error is returned unchanged.
func classifyRefusal(err error, action string) error {
	if !isUnauthorized(err) {
		return err
	}
	var ce mongo.CommandError
	errors.As(err, &ce)
	if strings.Contains(ce.Message, "requires authentication") {
		return llx.Unauthenticated(err)
	}
	return llx.Forbidden(err, llx.WithPermissions(action))
}

func mongoConnection(runtime *plugin.Runtime) *connection.MongoConnection {
	return runtime.Connection.(*connection.MongoConnection)
}

func mongoContext() context.Context {
	return context.Background()
}

func intToStr(i int64) string {
	return strconv.FormatInt(i, 10)
}

// privilegedRoles are the built-in roles the CIS superuser review cares about:
// holding any of these grants broad, cross-database, or administrative access.
var privilegedRoles = map[string]struct{}{
	"root":                 {},
	"__system":             {},
	"dbOwner":              {},
	"userAdmin":            {},
	"userAdminAnyDatabase": {},
	"dbAdminAnyDatabase":   {},
	"readWriteAnyDatabase": {},
	"readAnyDatabase":      {},
	"clusterAdmin":         {},
	"clusterManager":       {},
	"hostManager":          {},
	"backup":               {},
	"restore":              {},
}

// builtinRoles is the set of MongoDB-provided role names, used to mark a role
// as built-in without a per-role catalog lookup.
var builtinRoles = map[string]struct{}{
	"read": {}, "readWrite": {}, "dbAdmin": {}, "dbOwner": {}, "userAdmin": {},
	"clusterAdmin": {}, "clusterManager": {}, "clusterMonitor": {}, "hostManager": {},
	"backup": {}, "restore": {}, "readAnyDatabase": {}, "readWriteAnyDatabase": {},
	"userAdminAnyDatabase": {}, "dbAdminAnyDatabase": {}, "root": {}, "__system": {},
	"enableSharding": {}, "directShardOperations": {},
}

// --- defensive bson navigation ----------------------------------------------
// mongo-driver decodes documents into bson.M (map[string]any) with nested
// documents also bson.M. Every accessor is nil-safe and type-checked so a
// missing or unexpected field never panics.

// asMap normalizes a decoded BSON value to a bson.M. The driver decodes nested
// documents as bson.M in some positions and bson.D (ordered) in others —
// notably inside arrays — so both must be handled or array elements silently
// vanish.
func asMap(v any) bson.M {
	switch t := v.(type) {
	case bson.M:
		return t
	case bson.D:
		m := make(bson.M, len(t))
		for _, e := range t {
			m[e.Key] = e.Value
		}
		return m
	case map[string]any:
		return bson.M(t)
	default:
		return nil
	}
}

// asArray normalizes a decoded BSON array to []any (bson.A and []any both).
func asArray(v any) []any {
	switch t := v.(type) {
	case bson.A:
		return []any(t)
	case []any:
		return t
	default:
		return nil
	}
}

// deepGet walks nested bson.M documents by key path, returning nil on any miss.
func deepGet(m bson.M, path ...string) any {
	cur := m
	for i, k := range path {
		if cur == nil {
			return nil
		}
		v, ok := cur[k]
		if !ok {
			return nil
		}
		if i == len(path)-1 {
			return v
		}
		cur = asMap(v)
	}
	return nil
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	default:
		return 0
	}
}

// --- id builders ------------------------------------------------------------

func roleResourceID(serverID, db, role string) string {
	return serverID + "/role/" + db + "." + role
}

func userResourceID(serverID, db, user string) string {
	return serverID + "/user/" + db + "." + user
}

func databaseResourceID(serverID, name string) string {
	return serverID + "/database/" + name
}

// --- shared role builder ----------------------------------------------------

// newMongoRole creates a role resource. Privileges and inherited roles are
// resolved lazily by the role's own accessors.
func newMongoRole(runtime *plugin.Runtime, serverID, db, role string) (*mqlMongoRole, error) {
	_, isBuiltin := builtinRoles[role]
	res, err := CreateResource(runtime, "mongo.role", map[string]*llx.RawData{
		"__id":      llx.StringData(roleResourceID(serverID, db, role)),
		"role":      llx.StringData(role),
		"db":        llx.StringData(db),
		"isBuiltin": llx.BoolData(isBuiltin),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongoRole), nil
}
