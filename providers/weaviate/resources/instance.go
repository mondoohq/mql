// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// initWeaviateInstance fetches the server's metadata, OIDC configuration, and
// access-control mode once and populates the instance's scalar fields.
func initWeaviateInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := weaviateConnection(runtime)
	client, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}
	ctx := weaviateContext()

	meta, err := client.Misc().MetaGetter().Do(ctx)
	if err != nil {
		return nil, nil, err
	}

	// OIDC is configured when the well-known endpoint returns a document; a
	// non-configured server answers 404, surfaced here as an error.
	oidcEnabled := false
	oidcIssuer := ""
	oidcClientID := ""
	if oidc, err := client.Misc().OpenIDConfigurationGetter().Do(ctx); err == nil && oidc != nil {
		oidcEnabled = true
		oidcIssuer = oidc.Href
		oidcClientID = oidc.ClientID
	}

	// RBAC is enabled when the roles endpoint exists. A 401/403 means it exists
	// but the credential cannot read it (still enabled); any other error (e.g.
	// 404 when RBAC is off) means it is not enabled.
	rbacEnabled := false
	if _, err := conn.Roles(); err == nil || isForbidden(err) {
		rbacEnabled = true
	}

	args["__id"] = llx.StringData(conn.ServerID())
	args["version"] = llx.StringData(meta.Version)
	args["hostname"] = llx.StringData(meta.Hostname)
	args["modules"] = llx.ArrayData(moduleNames(meta.Modules), types.String)
	args["anonymousAccessEnabled"] = llx.BoolData(conn.AnonymousAccessEnabled())
	args["oidcEnabled"] = llx.BoolData(oidcEnabled)
	args["oidcIssuer"] = llx.StringData(oidcIssuer)
	args["oidcClientId"] = llx.StringData(oidcClientID)
	args["rbacEnabled"] = llx.BoolData(rbacEnabled)
	return args, nil, nil
}

func (r *mqlWeaviateInstance) collections() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	schema, err := client.Schema().Getter().Do(weaviateContext())
	if err != nil {
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := r.__id
	list := []any{}
	for _, class := range schema.Classes {
		multiEnabled := false
		autoCreate := false
		autoActivate := false
		if mt := class.MultiTenancyConfig; mt != nil {
			multiEnabled = mt.Enabled
			autoCreate = mt.AutoTenantCreation
			autoActivate = mt.AutoTenantActivation
		}
		replFactor := int64(0)
		asyncRepl := false
		if rc := class.ReplicationConfig; rc != nil {
			replFactor = rc.Factor
			// Async replication is signaled by a present async config block.
			asyncRepl = rc.AsyncConfig != nil
		}

		res, err := CreateResource(r.MqlRuntime, "weaviate.collection", map[string]*llx.RawData{
			"__id":                    llx.StringData(collectionResourceID(serverID, class.Class)),
			"name":                    llx.StringData(class.Class),
			"description":             llx.StringData(class.Description),
			"vectorizer":              llx.StringData(class.Vectorizer),
			"modules":                 llx.ArrayData(moduleNames(class.ModuleConfig), types.String),
			"multiTenancyEnabled":     llx.BoolData(multiEnabled),
			"autoTenantCreation":      llx.BoolData(autoCreate),
			"autoTenantActivation":    llx.BoolData(autoActivate),
			"replicationFactor":       llx.IntData(replFactor),
			"asyncReplicationEnabled": llx.BoolData(asyncRepl),
			"vectorIndexType":         llx.StringData(class.VectorIndexType),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlWeaviateInstance) nodes() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := client.Cluster().NodesStatusGetter().WithOutput("verbose").Do(weaviateContext())
	if err != nil {
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := r.__id
	list := []any{}
	for _, n := range resp.Nodes {
		if n == nil {
			continue
		}
		status := ""
		if n.Status != nil {
			status = *n.Status
		}
		shardCount := int64(0)
		objectCount := int64(0)
		if n.Stats != nil {
			shardCount = n.Stats.ShardCount
			objectCount = n.Stats.ObjectCount
		}
		res, err := CreateResource(r.MqlRuntime, "weaviate.node", map[string]*llx.RawData{
			"__id":        llx.StringData(nodeResourceID(serverID, n.Name)),
			"name":        llx.StringData(n.Name),
			"status":      llx.StringData(status),
			"version":     llx.StringData(n.Version),
			"gitHash":     llx.StringData(n.GitHash),
			"shardCount":  llx.IntData(shardCount),
			"objectCount": llx.IntData(objectCount),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
