// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// viewClusterMetadata is the privilege crdb_internal's node and store status
// tables need, which the admin role holds.
const viewClusterMetadata = "VIEWCLUSTERMETADATA"

func (r *mqlCockroachdbNode) id() (string, error) {
	return "cockroachdb.node/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlCockroachdbCluster) nodes() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT node_id, address, sql_address, build_tag, server_version, locality, is_live, started_at
		FROM crdb_internal.gossip_nodes ORDER BY node_id`)
	if err != nil {
		return nil, refused(err, viewClusterMetadata)
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var id int64
		var address, sqlAddress, buildTag, serverVersion, locality string
		var isLive bool
		var startedAt time.Time
		if err := rows.Scan(&id, &address, &sqlAddress, &buildTag, &serverVersion, &locality, &isLive, &startedAt); err != nil {
			return nil, err
		}
		startedAt = startedAt.UTC()
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.node", map[string]*llx.RawData{
			"id":            llx.IntData(id),
			"address":       llx.StringData(address),
			"sqlAddress":    llx.StringData(sqlAddress),
			"version":       llx.StringData(strings.TrimPrefix(buildTag, "v")),
			"serverVersion": llx.StringData(serverVersion),
			"locality":      llx.StringData(locality),
			"isLive":        llx.BoolData(isLive),
			"startedAt":     llx.TimeData(startedAt),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	if err := rows.Err(); err != nil {
		return nil, refused(err, viewClusterMetadata)
	}
	return list, nil
}

// nodeStatus is what crdb_internal.kv_node_status reports for one node.
type nodeStatus struct {
	args    []string
	metrics map[string]float64
}

// nodeStatuses reads every node's command line and metrics once.
func nodeStatuses(runtime *plugin.Runtime) (map[int64]nodeStatus, error) {
	v, err := crdbConnection(runtime).Memo("nodeStatus", func() (any, error) {
		rows, err := query(runtime, `SELECT node_id, args, metrics FROM crdb_internal.kv_node_status`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[int64]nodeStatus{}
		for rows.Next() {
			var id int64
			var args, metrics []byte
			if err := rows.Scan(&id, &args, &metrics); err != nil {
				return nil, err
			}
			var st nodeStatus
			if err := json.Unmarshal(args, &st.args); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(metrics, &st.metrics); err != nil {
				return nil, err
			}
			out[id] = st
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, refused(err, viewClusterMetadata)
	}
	return v.(map[int64]nodeStatus), nil
}

func (r *mqlCockroachdbNode) args() ([]any, error) {
	statuses, err := nodeStatuses(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return toAnySlice(statuses[r.Id.Data].args), nil
}

// certExpirationPrefix is the metric family that reports, per certificate
// type, when the certificate a node loaded expires, in seconds since the
// epoch; 0 when the node has no certificate of that type.
const certExpirationPrefix = "security.certificate.expiration."

// perUserCertTypes are certificate metrics CockroachDB labels by SQL user. The
// unlabeled metric sums every user's expiry, so it is not a time and is left
// out.
var perUserCertTypes = map[string]bool{
	"client": true,
}

// certificateExpirations returns the expiry of every certificate type a node
// loaded, from its metrics.
func certificateExpirations(metrics map[string]float64) map[string]time.Time {
	out := map[string]time.Time{}
	for name, v := range metrics {
		typ, ok := strings.CutPrefix(name, certExpirationPrefix)
		if !ok || v <= 0 || perUserCertTypes[typ] {
			continue
		}
		out[typ] = time.Unix(int64(v), 0).UTC()
	}
	return out
}

func (r *mqlCockroachdbNode) certificates() ([]any, error) {
	statuses, err := nodeStatuses(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	expirations := certificateExpirations(statuses[r.Id.Data].metrics)
	typesSorted := make([]string, 0, len(expirations))
	for typ := range expirations {
		typesSorted = append(typesSorted, typ)
	}
	sort.Strings(typesSorted)

	list := []any{}
	for _, typ := range typesSorted {
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.certificate", map[string]*llx.RawData{
			"__id":      llx.StringData(r.__id + "/certificate/" + typ),
			"type":      llx.StringData(typ),
			"expiresAt": llx.TimeData(expirations[typ]),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlCockroachdbNode) stores() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT store_id,
		COALESCE(properties->'file_store_properties'->>'path', ''),
		COALESCE((properties->>'encrypted')::BOOL, false),
		capacity, available, used
		FROM crdb_internal.kv_store_status WHERE node_id = $1 ORDER BY store_id`, r.Id.Data)
	if err != nil {
		return nil, refused(err, viewClusterMetadata)
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var id, capacity, available, used int64
		var path string
		var encrypted bool
		if err := rows.Scan(&id, &path, &encrypted, &capacity, &available, &used); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.store", map[string]*llx.RawData{
			"__id":      llx.StringData("cockroachdb.store/" + strconv.FormatInt(id, 10)),
			"id":        llx.IntData(id),
			"path":      llx.StringData(path),
			"encrypted": llx.BoolData(encrypted),
			"capacity":  llx.IntData(capacity),
			"available": llx.IntData(available),
			"used":      llx.IntData(used),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	if err := rows.Err(); err != nil {
		return nil, refused(err, viewClusterMetadata)
	}
	return list, nil
}
