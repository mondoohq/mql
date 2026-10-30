// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opensearch/connection"
	"go.mondoo.com/mql/types"
)

type osRootInfo struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number        string `json:"number"`
		Distribution  string `json:"distribution"`
		LuceneVersion string `json:"lucene_version"`
	} `json:"version"`
}

type osHealth struct {
	Status            string `json:"status"`
	NumberOfNodes     int64  `json:"number_of_nodes"`
	NumberOfDataNodes int64  `json:"number_of_data_nodes"`
}

// initOpensearchCluster fetches the cluster info and health once and populates
// the cluster's scalar fields. Health needs the cluster_monitor permission; a
// refusal fails the health fields rather than reporting misleading zeros, and
// leaves the rest of the cluster readable.
func initOpensearchCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := osConnection(runtime)

	var root osRootInfo
	if err := conn.Get("/", &root); err != nil {
		return nil, nil, err
	}

	var health osHealth
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
		distribution = "opensearch"
	}

	args["__id"] = llx.StringData(connection.NewOpensearchClusterIdentifier(clusterID))
	args["name"] = llx.StringData(root.ClusterName)
	args["uuid"] = llx.StringData(root.ClusterUUID)
	args["version"] = llx.StringData(root.Version.Number)
	args["distribution"] = llx.StringData(distribution)
	args["luceneVersion"] = llx.StringData(root.Version.LuceneVersion)

	res, err := CreateResource(runtime, "opensearch.cluster", args)
	if err != nil {
		return nil, nil, err
	}
	cluster := res.(*mqlOpensearchCluster)
	switch {
	case healthErr != nil && plugin.StructuredErrors():
		// The credential cannot read health: each health field carries the
		// refusal, so a policy reading them fails instead of passing on null.
		denied := refusal(healthErr, permClusterHealth)
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

// osSecurityConfig is the subset of the security config used for posture.
type osSecurityConfig struct {
	Config struct {
		Dynamic struct {
			HTTP struct {
				AnonymousAuthEnabled bool `json:"anonymous_auth_enabled"`
			} `json:"http"`
			DoNotFailOnForbidden bool                       `json:"do_not_fail_on_forbidden"`
			Authc                map[string]osAuthcRealmCfg `json:"authc"`
		} `json:"dynamic"`
	} `json:"config"`
}

type osAuthcRealmCfg struct {
	HTTPEnabled *bool `json:"http_enabled"`
	Enabled     *bool `json:"enabled"`
}

// realmServesREST reports whether an authc domain serves REST (HTTP) requests.
// OpenSearch defaults http_enabled and enabled to true when the key is absent,
// so a nil pointer means enabled; a domain serves REST only when it is both
// generally enabled and HTTP-enabled.
func realmServesREST(c osAuthcRealmCfg) bool {
	httpOn := c.HTTPEnabled == nil || *c.HTTPEnabled
	enabled := c.Enabled == nil || *c.Enabled
	return httpOn && enabled
}

func (r *mqlOpensearchCluster) security() (*mqlOpensearchSecurity, error) {
	conn := osConnection(r.MqlRuntime)

	var secConfig osSecurityConfig
	if err := conn.Get("/_plugins/_security/api/securityconfig", &secConfig); err != nil {
		if connection.IsPermissionError(err) && !plugin.StructuredErrors() {
			r.Security.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, refusal(err, permSecurityAPI)
	}
	dyn := secConfig.Config.Dynamic

	// Audit logging is a separate config document.
	auditEnabled := false
	var audit struct {
		Config struct {
			Enabled bool `json:"enabled"`
		} `json:"config"`
	}
	if err := conn.Get("/_plugins/_security/api/audit", &audit); err == nil {
		auditEnabled = audit.Config.Enabled
	} else if !connection.IsPermissionError(err) || plugin.StructuredErrors() {
		// A refused audit read is not "audit logging off".
		return nil, refusal(err, permSecurityAPI)
	}

	realms := []any{}
	names := make([]string, 0, len(dyn.Authc))
	for name := range dyn.Authc {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if realmServesREST(dyn.Authc[name]) {
			realms = append(realms, name)
		}
	}

	res, err := CreateResource(r.MqlRuntime, "opensearch.security", map[string]*llx.RawData{
		"__id":                   llx.StringData(r.__id + "/security"),
		"anonymousAccessEnabled": llx.BoolData(dyn.HTTP.AnonymousAuthEnabled),
		"auditLoggingEnabled":    llx.BoolData(auditEnabled),
		"doNotFailOnForbidden":   llx.BoolData(dyn.DoNotFailOnForbidden),
		"enabledAuthRealms":      llx.ArrayData(realms, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpensearchSecurity), nil
}

// osUser is one entry from the internal users API. The password hash is always
// masked to "" in GET responses, so it is not decoded or exposed.
type osUser struct {
	Reserved                bool     `json:"reserved"`
	Hidden                  bool     `json:"hidden"`
	Static                  bool     `json:"static"`
	BackendRoles            []string `json:"backend_roles"`
	OpendistroSecurityRoles []string `json:"opendistro_security_roles"`
	Description             string   `json:"description"`
}

func (r *mqlOpensearchCluster) users() ([]any, error) {
	conn := osConnection(r.MqlRuntime)
	var resp map[string]osUser
	if err := conn.Get("/_plugins/_security/api/internalusers", &resp); err != nil {
		return refusedList(err, permSecurityAPI)
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		u := resp[name]
		res, err := CreateResource(r.MqlRuntime, "opensearch.user", map[string]*llx.RawData{
			"__id":          llx.StringData(r.__id + "/user/" + name),
			"name":          llx.StringData(name),
			"isReserved":    llx.BoolData(u.Reserved),
			"isHidden":      llx.BoolData(u.Hidden),
			"isStatic":      llx.BoolData(u.Static),
			"backendRoles":  llx.ArrayData(toStringSlice(u.BackendRoles), types.String),
			"securityRoles": llx.ArrayData(toStringSlice(u.OpendistroSecurityRoles), types.String),
			"description":   llx.StringData(u.Description),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// osRoleMapping is one entry from the role mappings API.
type osRoleMapping struct {
	Reserved     bool     `json:"reserved"`
	Hidden       bool     `json:"hidden"`
	Users        []string `json:"users"`
	BackendRoles []string `json:"backend_roles"`
	Hosts        []string `json:"hosts"`
	Description  string   `json:"description"`
}

func (r *mqlOpensearchCluster) roleMappings() ([]any, error) {
	conn := osConnection(r.MqlRuntime)
	var resp map[string]osRoleMapping
	if err := conn.Get("/_plugins/_security/api/rolesmapping", &resp); err != nil {
		return refusedList(err, permSecurityAPI)
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		m := resp[name]
		res, err := CreateResource(r.MqlRuntime, "opensearch.roleMapping", map[string]*llx.RawData{
			"__id":         llx.StringData(r.__id + "/rolemapping/" + name),
			"name":         llx.StringData(name),
			"isReserved":   llx.BoolData(m.Reserved),
			"isHidden":     llx.BoolData(m.Hidden),
			"users":        llx.ArrayData(toStringSlice(m.Users), types.String),
			"backendRoles": llx.ArrayData(toStringSlice(m.BackendRoles), types.String),
			"hosts":        llx.ArrayData(toStringSlice(m.Hosts), types.String),
			"description":  llx.StringData(m.Description),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
