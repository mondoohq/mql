// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
	// Everything but the version comes from getCmdLineOpts. When it is
	// refused, those fields carry the error instead of the defaults below: a
	// default would report auth and TLS as disabled on a server that enforces
	// both.
	cmdLineErr := conn.RunAdminCommand(bson.D{{Key: "getCmdLineOpts", Value: 1}}, &cmdLine)
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

	authEnabled := authEnforced(parsed)

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
		// Unset means the server default, localhost only (MongoDB 3.6+). The
		// host this scan connected through says nothing about what the server
		// binds to. --bind_ip_all is reported as bindIp "*".
		bindIp = "localhost"
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

	// Not gated on plugin.StructuredErrors: the opt-in keeps a v13 null or
	// empty, and these fields never were one. They reported the defaults
	// above as facts, which states the opposite of a hardened server's
	// posture, so there is no v13 answer worth keeping.
	if cmdLineErr != nil {
		setCmdLineError(args, classifyRefusal(cmdLineErr, "getCmdLineOpts"))
	}
	return args, nil, nil
}

// cmdLineFields are the instance fields read from getCmdLineOpts, with their
// types. port is not among them: it falls back to the port the connection
// reached, which is a fact rather than a default.
var cmdLineFields = map[string]types.Type{
	"bindIp":                types.String,
	"authenticationEnabled": types.Bool,
	"authorizationEnabled":  types.Bool,
	"clusterAuthMode":       types.String,
	"tlsMode":               types.String,
	"tlsDisabledProtocols":  types.String,
	"tlsFIPSMode":           types.Bool,
	"javascriptEnabled":     types.Bool,
	"auditLogDestination":   types.String,
	"logVerbosity":          types.Int,
	"logAppend":             types.Bool,
}

// setCmdLineError replaces every getCmdLineOpts-derived field with err.
func setCmdLineError(args map[string]*llx.RawData, err error) {
	for name, typ := range cmdLineFields {
		args[name] = &llx.RawData{Type: typ, Error: err}
	}
}

func (r *mqlMongoInstance) parameters() ([]any, error) {
	conn := mongoConnection(r.MqlRuntime)
	var res bson.M
	if err := conn.RunAdminCommand(bson.D{{Key: "getParameter", Value: "*"}}, &res); err != nil {
		return nil, classifyRefusal(err, "getParameter")
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
	// Without the listDatabases action the server silently narrows the answer
	// to the databases the account can read. authorizedDatabases=false makes
	// it refuse instead, so a partial list never passes for the full one.
	opts := options.ListDatabases()
	if plugin.StructuredErrors() {
		opts.SetAuthorizedDatabases(false)
	}
	result, err := client.ListDatabases(mongoContext(), bson.D{}, opts)
	if err != nil {
		return nil, classifyRefusal(err, "listDatabases")
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
