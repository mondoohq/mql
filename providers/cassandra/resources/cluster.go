// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/gocql/gocql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cassandra/connection"
	"go.mondoo.com/mql/types"
)

// initCassandraCluster fetches the cluster identity from system.local.
func initCassandraCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fast path: the resource was constructed with its fields already populated
	// (more than just the __id/host pair), so there is nothing to fetch.
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := cassandraConnection(runtime)
	session, err := conn.Session()
	if err != nil {
		return nil, nil, err
	}

	var name, version, cqlVersion, protoVersion, partitioner, hostID string
	err = session.Query(`SELECT cluster_name, release_version, cql_version, native_protocol_version, partitioner, host_id FROM system.local`).
		Scan(&name, &version, &cqlVersion, &protoVersion, &partitioner, &hostID)
	if err != nil {
		return nil, nil, err
	}
	// native_protocol_version is stored as text (e.g. "5").
	protoVersionInt, err := strconv.ParseInt(protoVersion, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing native_protocol_version %q: %w", protoVersion, err)
	}

	clusterID := hostID
	if clusterID == "" {
		clusterID = conn.ServerID()
	}

	args["__id"] = llx.StringData(connection.NewCassandraClusterIdentifier(clusterID))
	args["name"] = llx.StringData(name)
	args["version"] = llx.StringData(version)
	args["cqlVersion"] = llx.StringData(cqlVersion)
	args["nativeProtocolVersion"] = llx.IntData(protoVersionInt)
	args["partitioner"] = llx.StringData(partitioner)
	return args, nil, nil
}

// setting returns the first present value among the candidate keys, trimmed.
func setting(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (r *mqlCassandraCluster) security() (*mqlCassandraSecurity, error) {
	conn := cassandraConnection(r.MqlRuntime)
	session, err := conn.Session()
	if err != nil {
		return nil, err
	}

	// system_views.settings is a virtual table of the running config. Read it
	// all once; setting names vary by version (dotted, underscore, .class_name),
	// so each logical value probes a candidate list.
	settings := map[string]string{}
	iter := session.Query(`SELECT name, value FROM system_views.settings`).Iter()
	var name, value string
	for iter.Scan(&name, &value) {
		settings[name] = value
	}
	if err := iter.Close(); err != nil {
		if connection.IsUnauthorized(err) {
			if !plugin.StructuredErrors() {
				r.Security.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, refused(err, "SELECT ON system_views.settings")
		}
		return nil, err
	}

	authenticator := setting(settings, "authenticator.class_name", "authenticator")
	authorizer := setting(settings, "authorizer.class_name", "authorizer")
	roleManager := setting(settings, "role_manager.class_name", "role_manager")
	networkAuthorizer := setting(settings, "network_authorizer.class_name", "network_authorizer")
	clientEnc := setting(settings, "client_encryption_options.enabled", "client_encryption_options_enabled")
	internode := setting(settings, "server_encryption_options.internode_encryption", "server_encryption_options_internode_encryption")
	audit := setting(settings, "audit_logging_options.enabled", "audit_logging_options_enabled")

	res, err := CreateResource(r.MqlRuntime, "cassandra.security", map[string]*llx.RawData{
		"__id":                    llx.StringData(r.__id + "/security"),
		"authenticator":           llx.StringData(authenticator),
		"authorizer":              llx.StringData(authorizer),
		"roleManager":             llx.StringData(roleManager),
		"networkAuthorizer":       llx.StringData(networkAuthorizer),
		"authenticationEnabled":   llx.BoolData(authenticator != "" && !strings.HasSuffix(authenticator, "AllowAllAuthenticator")),
		"authorizationEnabled":    llx.BoolData(authorizer != "" && !strings.HasSuffix(authorizer, "AllowAllAuthorizer")),
		"clientEncryptionEnabled": llx.BoolData(strings.EqualFold(clientEnc, "true")),
		"internodeEncryption":     llx.StringData(internode),
		"auditLoggingEnabled":     llx.BoolData(strings.EqualFold(audit, "true")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCassandraSecurity), nil
}

func (r *mqlCassandraCluster) nodes() ([]any, error) {
	conn := cassandraConnection(r.MqlRuntime)
	session, err := conn.Session()
	if err != nil {
		return nil, err
	}
	serverID := r.__id
	list := []any{}

	// The connected node comes from system.local.
	var laddr, lhost, lver, ldc, lrack string
	err = session.Query(`SELECT broadcast_address, host_id, release_version, data_center, rack FROM system.local`).
		Scan(&laddr, &lhost, &lver, &ldc, &lrack)
	if err != nil {
		return nil, err
	}
	local, err := r.newNode(serverID, laddr, lhost, lver, ldc, lrack, true)
	if err != nil {
		return nil, err
	}
	list = append(list, local)

	// Other nodes come from system.peers_v2 (4.0+); fall back to the legacy
	// system.peers on clusters that do not have it (pre-4.0).
	peers, err := r.scanPeers(session, `SELECT peer, host_id, release_version, data_center, rack FROM system.peers_v2`)
	if err != nil {
		peers, err = r.scanPeers(session, `SELECT peer, host_id, release_version, data_center, rack FROM system.peers`)
		if err != nil {
			if connection.IsUnauthorized(err) {
				if !plugin.StructuredErrors() {
					return list, nil
				}
				return nil, refused(err, "SELECT ON system.peers")
			}
			return nil, err
		}
	}
	list = append(list, peers...)
	return list, nil
}

// scanPeers runs a peers query and builds a node resource per row.
func (r *mqlCassandraCluster) scanPeers(session *gocql.Session, query string) ([]any, error) {
	serverID := r.__id
	iter := session.Query(query).Iter()
	var addr, host, ver, dc, rack string
	list := []any{}
	for iter.Scan(&addr, &host, &ver, &dc, &rack) {
		node, err := r.newNode(serverID, addr, host, ver, dc, rack, false)
		if err != nil {
			_ = iter.Close()
			return nil, err
		}
		list = append(list, node)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return list, nil
}

func (r *mqlCassandraCluster) newNode(serverID, address, hostID, version, dc, rack string, isLocal bool) (*mqlCassandraNode, error) {
	res, err := CreateResource(r.MqlRuntime, "cassandra.node", map[string]*llx.RawData{
		"__id":           llx.StringData(serverID + "/node/" + hostID),
		"address":        llx.StringData(address),
		"hostId":         llx.StringData(hostID),
		"releaseVersion": llx.StringData(version),
		"datacenter":     llx.StringData(dc),
		"rack":           llx.StringData(rack),
		"isLocal":        llx.BoolData(isLocal),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCassandraNode), nil
}

func (r *mqlCassandraCluster) keyspaces() ([]any, error) {
	conn := cassandraConnection(r.MqlRuntime)
	session, err := conn.Session()
	if err != nil {
		return nil, err
	}

	type ksRow struct {
		name        string
		replication map[string]string
		durable     bool
	}
	var rows []ksRow
	iter := session.Query(`SELECT keyspace_name, replication, durable_writes FROM system_schema.keyspaces`).Iter()
	var name string
	var replication map[string]string
	var durable bool
	for iter.Scan(&name, &replication, &durable) {
		repl := make(map[string]string, len(replication))
		maps.Copy(repl, replication)
		rows = append(rows, ksRow{name: name, replication: repl, durable: durable})
	}
	if err := iter.Close(); err != nil {
		if connection.IsUnauthorized(err) {
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, refused(err, "SELECT ON system_schema.keyspaces")
		}
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	serverID := r.__id
	list := []any{}
	for _, row := range rows {
		strategy := row.replication["class"]
		if i := strings.LastIndex(strategy, "."); i >= 0 {
			strategy = strategy[i+1:]
		}
		factors := map[string]any{}
		for k, v := range row.replication {
			if k == "class" {
				continue
			}
			factors[k] = v
		}
		res, err := CreateResource(r.MqlRuntime, "cassandra.keyspace", map[string]*llx.RawData{
			"__id":                llx.StringData(serverID + "/keyspace/" + row.name),
			"name":                llx.StringData(row.name),
			"replicationStrategy": llx.StringData(strategy),
			"replicationFactors":  llx.MapData(factors, types.String),
			"durableWrites":       llx.BoolData(row.durable),
			"isSystem":            llx.BoolData(isSystemKeyspace(row.name)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// isSystemKeyspace reports whether a keyspace is one of Cassandra's built-ins.
func isSystemKeyspace(name string) bool {
	return name == "system" || strings.HasPrefix(name, "system_")
}
