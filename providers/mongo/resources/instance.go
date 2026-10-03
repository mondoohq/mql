// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// initMongoInstance fetches the server's version and command-line options once
// and populates the instance's scalar fields. getCmdLineOpts only reports
// options that were explicitly set, so absent values fall back to MongoDB's
// documented defaults (auth disabled, javascript enabled, TLS disabled).
func initMongoInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := mongoConnection(runtime)
	serverID := conn.ServerID()

	var buildInfo bson.M
	if err := conn.RunAdminCommand(bson.D{{Key: "buildInfo", Value: 1}}, &buildInfo); err != nil {
		return nil, nil, err
	}

	var cmdLine bson.M
	// getCmdLineOpts needs a privilege; degrade to buildInfo-only rather than fail.
	_ = conn.RunAdminCommand(bson.D{{Key: "getCmdLineOpts", Value: 1}}, &cmdLine)
	parsed := asMap(deepGet(cmdLine, "parsed"))

	// TLS block lives under net.tls (7.x) or net.ssl (legacy).
	tls := asMap(deepGet(parsed, "net", "tls"))
	if tls == nil {
		tls = asMap(deepGet(parsed, "net", "ssl"))
	}
	tlsMode := toStr(tls["mode"])
	if tlsMode == "" {
		tlsMode = "disabled"
	}

	authz := toStr(deepGet(parsed, "security", "authorization"))
	authEnabled := authz == "enabled"

	// javascriptEnabled defaults to true when unset.
	jsEnabled := true
	if v := deepGet(parsed, "security", "javascriptEnabled"); v != nil {
		jsEnabled = toBool(v)
	}

	// getCmdLineOpts only reports explicitly-set options, and may be unauthorized
	// entirely, so fall back to the values the connection already knows.
	port := toInt(deepGet(parsed, "net", "port"))
	if port == 0 {
		port = int64(conn.Port())
	}
	bindIp := toStr(deepGet(parsed, "net", "bindIp"))
	if bindIp == "" {
		bindIp = conn.Host()
	}

	args["__id"] = llx.StringData(serverID)
	args["version"] = llx.StringData(toStr(buildInfo["version"]))
	args["gitVersion"] = llx.StringData(toStr(buildInfo["gitVersion"]))
	args["port"] = llx.IntData(port)
	args["bindIp"] = llx.StringData(bindIp)
	args["authenticationEnabled"] = llx.BoolData(authEnabled)
	args["authorizationEnabled"] = llx.BoolData(authEnabled)
	args["clusterAuthMode"] = llx.StringData(toStr(deepGet(parsed, "security", "clusterAuthMode")))
	args["tlsMode"] = llx.StringData(tlsMode)
	args["tlsDisabledProtocols"] = llx.StringData(toStr(tls["disabledProtocols"]))
	args["tlsFIPSMode"] = llx.BoolData(toBool(tls["FIPSMode"]))
	args["javascriptEnabled"] = llx.BoolData(jsEnabled)
	args["auditLogDestination"] = llx.StringData(toStr(deepGet(parsed, "auditLog", "destination")))
	args["logVerbosity"] = llx.IntData(toInt(deepGet(parsed, "systemLog", "verbosity")))
	// logAppend is not a runtime parameter, so getCmdLineOpts is the only
	// source; absent means the server default, which replaces the log file.
	args["logAppend"] = llx.BoolData(toBool(deepGet(parsed, "systemLog", "logAppend")))
	return args, nil, nil
}

func (r *mqlMongoInstance) parameters() ([]any, error) {
	conn := mongoConnection(r.MqlRuntime)
	var res bson.M
	if err := conn.RunAdminCommand(bson.D{{Key: "getParameter", Value: "*"}}, &res); err != nil {
		return nil, err
	}

	// Sort keys for stable output.
	keys := make([]string, 0, len(res))
	for k := range res {
		if k == "ok" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	serverID := r.__id
	list := []any{}
	for _, name := range keys {
		p, err := CreateResource(r.MqlRuntime, "mongo.parameter", map[string]*llx.RawData{
			"__id":  llx.StringData(serverID + "/param/" + name),
			"name":  llx.StringData(name),
			"value": llx.StringData(parameterValue(res[name])),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, nil
}

func (r *mqlMongoInstance) databases() ([]any, error) {
	conn := mongoConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	result, err := client.ListDatabases(mongoContext(), bson.D{})
	if err != nil {
		return nil, err
	}

	serverID := r.__id
	list := []any{}
	for _, db := range result.Databases {
		res, err := CreateResource(r.MqlRuntime, "mongo.database", map[string]*llx.RawData{
			"__id":       llx.StringData(databaseResourceID(serverID, db.Name)),
			"name":       llx.StringData(db.Name),
			"sizeOnDisk": llx.IntData(db.SizeOnDisk),
			"empty":      llx.BoolData(db.Empty),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

var _ = types.String
