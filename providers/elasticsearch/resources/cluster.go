// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/elasticsearch/connection"
	"go.mondoo.com/mql/types"
)

type esRootInfo struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number        string `json:"number"`
		Distribution  string `json:"distribution"`
		BuildFlavor   string `json:"build_flavor"`
		LuceneVersion string `json:"lucene_version"`
	} `json:"version"`
}

type esHealth struct {
	Status            string `json:"status"`
	NumberOfNodes     int64  `json:"number_of_nodes"`
	NumberOfDataNodes int64  `json:"number_of_data_nodes"`
}

// initElasticsearchCluster fetches the cluster info and health once and
// populates the cluster's scalar fields.
func initElasticsearchCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := esConnection(runtime)

	var root esRootInfo
	if err := conn.Get("/", &root); err != nil {
		return nil, nil, err
	}

	// Cluster health needs the monitor privilege. A refusal fails the health
	// fields (set below) rather than reporting misleading zeros, and leaves
	// the rest of the cluster readable; any other error fails.
	var health esHealth
	var healthErr error
	if err := conn.Get("/_cluster/health", &health); err != nil {
		if !connection.IsPermissionError(err) {
			return nil, nil, err
		}
		healthErr = err
	}

	clusterID := root.ClusterUUID
	if clusterID == "" {
		clusterID = conn.ServerID()
	}

	distribution := root.Version.Distribution
	if distribution == "" {
		distribution = "elasticsearch"
	}

	args["__id"] = llx.StringData(connection.NewElasticsearchClusterIdentifier(clusterID))
	args["name"] = llx.StringData(root.ClusterName)
	args["uuid"] = llx.StringData(root.ClusterUUID)
	args["version"] = llx.StringData(root.Version.Number)
	args["distribution"] = llx.StringData(distribution)
	args["buildFlavor"] = llx.StringData(root.Version.BuildFlavor)
	args["luceneVersion"] = llx.StringData(root.Version.LuceneVersion)

	res, err := CreateResource(runtime, "elasticsearch.cluster", args)
	if err != nil {
		return nil, nil, err
	}
	cluster := res.(*mqlElasticsearchCluster)
	switch {
	case healthErr != nil && plugin.StructuredErrors():
		// The credential cannot read health: each health field carries the
		// refusal, so a policy reading them fails instead of passing on null.
		denied := refusal(healthErr, "monitor")
		failed := plugin.StateIsSet | plugin.StateIsNull
		cluster.HealthStatus = plugin.TValue[string]{State: failed, Error: denied}
		cluster.NodeCount = plugin.TValue[int64]{State: failed, Error: denied}
		cluster.DataNodeCount = plugin.TValue[int64]{State: failed, Error: denied}
	case healthErr != nil:
		// v13: report null, not zero, so a policy like nodeCount == 0 does
		// not fire on a missing privilege.
		null := plugin.StateIsSet | plugin.StateIsNull
		cluster.HealthStatus = plugin.TValue[string]{State: null}
		cluster.NodeCount = plugin.TValue[int64]{State: null}
		cluster.DataNodeCount = plugin.TValue[int64]{State: null}
	default:
		set := plugin.StateIsSet
		cluster.HealthStatus = plugin.TValue[string]{Data: health.Status, State: set}
		cluster.NodeCount = plugin.TValue[int64]{Data: health.NumberOfNodes, State: set}
		cluster.DataNodeCount = plugin.TValue[int64]{Data: health.NumberOfDataNodes, State: set}
	}
	return nil, res, nil
}

// esUsage is the subset of GET /_xpack/usage used for the security posture.
type esUsage struct {
	Security struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
		SSL       struct {
			HTTP      struct{ Enabled bool } `json:"http"`
			Transport struct{ Enabled bool } `json:"transport"`
		} `json:"ssl"`
		Audit     struct{ Enabled bool } `json:"audit"`
		Anonymous struct{ Enabled bool } `json:"anonymous"`
	} `json:"security"`
}

func (r *mqlElasticsearchCluster) security() (*mqlElasticsearchSecurity, error) {
	conn := esConnection(r.MqlRuntime)
	var usage esUsage
	if err := conn.Get("/_xpack/usage", &usage); err != nil {
		if connection.IsPermissionError(err) && !plugin.StructuredErrors() {
			r.Security.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, refusal(err, "monitor")
	}
	s := usage.Security
	res, err := CreateResource(r.MqlRuntime, "elasticsearch.security", map[string]*llx.RawData{
		"__id":                   llx.StringData(r.__id + "/security"),
		"enabled":                llx.BoolData(s.Enabled),
		"available":              llx.BoolData(s.Available),
		"anonymousAccessEnabled": llx.BoolData(s.Anonymous.Enabled),
		"httpTlsEnabled":         llx.BoolData(s.SSL.HTTP.Enabled),
		"transportTlsEnabled":    llx.BoolData(s.SSL.Transport.Enabled),
		"auditLoggingEnabled":    llx.BoolData(s.Audit.Enabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlElasticsearchSecurity), nil
}

// isReserved reports whether a security object's metadata marks it as a
// built-in, reserved entity.
func isReserved(metadata map[string]any) bool {
	v, ok := metadata["_reserved"].(bool)
	return ok && v
}

func (r *mqlElasticsearchCluster) users() ([]any, error) {
	conn := esConnection(r.MqlRuntime)
	// The users endpoint returns an object keyed by username.
	var resp map[string]struct {
		Username string         `json:"username"`
		Roles    []string       `json:"roles"`
		FullName string         `json:"full_name"`
		Email    string         `json:"email"`
		Enabled  bool           `json:"enabled"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := conn.Get("/_security/user", &resp); err != nil {
		return refusedList(err, "read_security")
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		u := resp[name]
		res, err := CreateResource(r.MqlRuntime, "elasticsearch.user", map[string]*llx.RawData{
			"__id":       llx.StringData(r.__id + "/user/" + name),
			"name":       llx.StringData(u.Username),
			"roles":      llx.ArrayData(toStringSlice(u.Roles), types.String),
			"fullName":   llx.StringData(u.FullName),
			"email":      llx.StringData(u.Email),
			"enabled":    llx.BoolData(u.Enabled),
			"isReserved": llx.BoolData(isReserved(u.Metadata)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlElasticsearchCluster) roleMappings() ([]any, error) {
	conn := esConnection(r.MqlRuntime)
	var resp map[string]struct {
		Enabled bool     `json:"enabled"`
		Roles   []string `json:"roles"`
	}
	if err := conn.Get("/_security/role_mapping", &resp); err != nil {
		return refusedList(err, "read_security")
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		m := resp[name]
		res, err := CreateResource(r.MqlRuntime, "elasticsearch.roleMapping", map[string]*llx.RawData{
			"__id":    llx.StringData(r.__id + "/rolemapping/" + name),
			"name":    llx.StringData(name),
			"enabled": llx.BoolData(m.Enabled),
			"roles":   llx.ArrayData(toStringSlice(m.Roles), types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

type esAPIKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Username    string `json:"username"`
	Creation    int64  `json:"creation"`
	Expiration  int64  `json:"expiration"`
	Invalidated bool   `json:"invalidated"`
}

func (r *mqlElasticsearchCluster) apiKeys() ([]any, error) {
	conn := esConnection(r.MqlRuntime)
	var resp struct {
		APIKeys []esAPIKey `json:"api_keys"`
	}
	if err := conn.Get("/_security/api_key", &resp); err != nil {
		return refusedList(err, "read_security")
	}

	// Sort for deterministic output, matching users/roles/roleMappings.
	sort.Slice(resp.APIKeys, func(i, j int) bool {
		if resp.APIKeys[i].Name != resp.APIKeys[j].Name {
			return resp.APIKeys[i].Name < resp.APIKeys[j].Name
		}
		return resp.APIKeys[i].ID < resp.APIKeys[j].ID
	})

	list := []any{}
	for _, k := range resp.APIKeys {
		neverExpires := k.Expiration <= 0
		fields := map[string]*llx.RawData{
			"__id":         llx.StringData(r.__id + "/apikey/" + k.ID),
			"id":           llx.StringData(k.ID),
			"name":         llx.StringData(k.Name),
			"username":     llx.StringData(k.Username),
			"creation":     llx.TimeData(epochMillisToTime(k.Creation)),
			"neverExpires": llx.BoolData(neverExpires),
			"invalidated":  llx.BoolData(k.Invalidated),
		}
		if neverExpires {
			fields["expiration"] = llx.NilData
		} else {
			fields["expiration"] = llx.TimeData(epochMillisToTime(k.Expiration))
		}
		res, err := CreateResource(r.MqlRuntime, "elasticsearch.apiKey", fields)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
