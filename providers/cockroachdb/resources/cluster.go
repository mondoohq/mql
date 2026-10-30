// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cockroachdb/connection"
	"go.mondoo.com/mql/types"
)

// initCockroachdbCluster reads the cluster identity and version, from sources
// every user may read.
func initCockroachdbCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := crdbConnection(runtime)
	info, err := conn.Cluster()
	if err != nil {
		return nil, nil, err
	}

	clusterVersion, err := activeVersion(runtime)
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(connection.NewCockroachdbClusterIdentifier(info.ID))
	args["id"] = llx.StringData(info.ID)
	args["version"] = llx.StringData(info.Version)
	args["buildInfo"] = llx.StringData(info.BuildInfo)
	args["clusterVersion"] = llx.StringData(clusterVersion)
	args["organization"] = llx.StringData(info.Organization)
	return args, nil, nil
}

// activeVersion returns the active cluster version as the version cluster
// setting shows it, "25.4", or "25.3-12" for an internal version during an
// upgrade. crdb_internal.active_version() needs no privilege, unlike the
// setting.
func activeVersion(runtime *plugin.Runtime) (string, error) {
	rows, err := query(runtime, `SELECT crdb_internal.active_version()`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var raw []byte
	for rows.Next() {
		if err := rows.Scan(&raw); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if raw == nil {
		return "", errors.New("crdb_internal.active_version() returned no rows")
	}
	return formatClusterVersion(raw)
}

// formatClusterVersion formats the JSON crdb_internal.active_version() returns.
func formatClusterVersion(raw []byte) (string, error) {
	var v struct {
		Major    int64 `json:"major"`
		Minor    int64 `json:"minor"`
		Internal int64 `json:"internal"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	out := strconv.FormatInt(v.Major, 10) + "." + strconv.FormatInt(v.Minor, 10)
	if v.Internal != 0 {
		out += "-" + strconv.FormatInt(v.Internal, 10)
	}
	return out, nil
}

// insecure reports whether the connected node runs in insecure mode. The SQL
// URL a node reports for itself carries sslmode=disable only when it was
// started with --insecure; a secure node reports verify-full.
func (r *mqlCockroachdbCluster) insecure() (bool, error) {
	rows, err := query(r.MqlRuntime, `SELECT value FROM crdb_internal.node_runtime_info WHERE component = 'DB' AND field = 'URL'`)
	if err != nil {
		return false, refused(err, viewClusterMetadata)
	}
	defer rows.Close()
	var url string
	found := false
	for rows.Next() {
		if err := rows.Scan(&url); err != nil {
			return false, err
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return false, refused(err, viewClusterMetadata)
	}
	if !found {
		return false, errors.New("crdb_internal.node_runtime_info reported no SQL URL")
	}
	return isInsecureURL(url), nil
}

// isInsecureURL reports whether a node's SQL URL is one CockroachDB reports in
// insecure mode.
func isInsecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Query().Get("sslmode"), "disable")
}

func (r *mqlCockroachdbCluster) settings() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT variable, value, default_value, type, origin, public, sensitive, description
		FROM crdb_internal.cluster_settings ORDER BY variable`)
	if err != nil {
		return nil, refused(err, "VIEWCLUSTERSETTING")
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, value, defaultValue, typ, origin, description string
		var public, sensitive bool
		if err := rows.Scan(&name, &value, &defaultValue, &typ, &origin, &public, &sensitive, &description); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.setting", map[string]*llx.RawData{
			"__id":         llx.StringData(r.__id + "/setting/" + name),
			"name":         llx.StringData(name),
			"value":        llx.StringData(value),
			"defaultValue": llx.StringData(defaultValue),
			"type":         llx.StringData(settingType(typ)),
			"origin":       llx.StringData(origin),
			"isDefault":    llx.BoolData(origin == "default"),
			"isDocumented": llx.BoolData(public),
			"isSensitive":  llx.BoolData(sensitive),
			"description":  llx.StringData(description),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	if err := rows.Err(); err != nil {
		return nil, refused(err, "VIEWCLUSTERSETTING")
	}
	return list, nil
}

// settingType names the one-letter type code crdb_internal.cluster_settings
// reports. An unknown code is returned as is.
func settingType(code string) string {
	switch code {
	case "b":
		return "bool"
	case "i":
		return "int"
	case "f":
		return "float"
	case "s":
		return "string"
	case "e":
		return "enum"
	case "d":
		return "duration"
	case "z":
		return "byteSize"
	case "m":
		return "version"
	default:
		return code
	}
}

// redactedValue is what CockroachDB shows instead of a sensitive setting's
// value to a user who may not read it.
const redactedValue = "<redacted>"

func (r *mqlCockroachdbCluster) hbaRules() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT value FROM crdb_internal.cluster_settings
		WHERE variable = 'server.host_based_authentication.configuration'`)
	if err != nil {
		return nil, refused(err, "VIEWCLUSTERSETTING")
	}
	defer rows.Close()
	var conf string
	for rows.Next() {
		if err := rows.Scan(&conf); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, refused(err, "VIEWCLUSTERSETTING")
	}
	if conf == redactedValue {
		return nil, llx.Forbidden(
			errors.New("server.host_based_authentication.configuration is redacted for this user"),
			llx.WithPermissions("MODIFYCLUSTERSETTING"))
	}

	list := []any{}
	for _, rule := range parseHBA(conf) {
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.hbaRule", map[string]*llx.RawData{
			"__id":           llx.StringData(r.__id + "/hba/" + strconv.Itoa(rule.position)),
			"position":       llx.IntData(int64(rule.position)),
			"connectionType": llx.StringData(rule.connectionType),
			"databases":      llx.ArrayData(toAnySlice(rule.databases), types.String),
			"users":          llx.ArrayData(toAnySlice(rule.users), types.String),
			"address":        llx.StringData(rule.address),
			"method":         llx.StringData(rule.method),
			"options":        llx.MapData(rule.optionsAny(), types.String),
			"line":           llx.StringData(rule.line),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
