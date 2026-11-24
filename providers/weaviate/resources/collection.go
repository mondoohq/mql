// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"strings"

	"github.com/weaviate/weaviate/entities/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// Module name prefixes the server uses for the two kinds of module that send a
// collection's data to an external model at query time.
const (
	generativeModulePrefix = "generative-"
	rerankerModulePrefix   = "reranker-"
)

// endpointSettingKeys are the module settings that name the endpoint a module
// calls, in the order they are preferred when a module sets more than one. The
// key differs by module: most use baseURL, Google and Ollama use apiEndpoint,
// AWS and Databricks use endpoint, Hugging Face uses endpointURL, and the
// self-hosted inference modules use inferenceUrl. baseUrl is the older
// spelling some modules still accept. Only these keys are read, so API keys and
// headers a module configuration holds never leave it.
var endpointSettingKeys = []string{
	"baseURL",
	"baseUrl",
	"apiEndpoint",
	"endpointURL",
	"endpoint",
	"inferenceUrl",
}

// moduleWithPrefix returns the first configured module, in name order, whose
// name starts with prefix, or nil when none does.
func moduleWithPrefix(moduleConfig any, prefix string) *string {
	for _, name := range moduleNames(moduleConfig) {
		s := name.(string)
		if strings.HasPrefix(s, prefix) {
			return &s
		}
	}
	return nil
}

// moduleEndpoints maps each configured module that names an endpoint to that
// endpoint. Modules without one are left out.
func moduleEndpoints(moduleConfig any) map[string]any {
	out := map[string]any{}
	modules, ok := moduleConfig.(map[string]any)
	if !ok {
		return out
	}
	for name, settings := range modules {
		cfg, ok := settings.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range endpointSettingKeys {
			if v, ok := cfg[key].(string); ok && strings.TrimSpace(v) != "" {
				out[name] = redactEndpoint(v)
				break
			}
		}
	}
	return out
}

// redactEndpoint drops the user info, query string, and fragment from an
// endpoint URL, which is where a credential embedded in it would sit. A value
// that is not an absolute URL, such as a bare host name or an AWS endpoint
// name, is returned unchanged.
func redactEndpoint(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return v
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// vectorizerNone is what the server calls a vector that is not computed by a
// module.
const vectorizerNone = "none"

// namedVectorizers maps each named vector of a collection to its vectorizer
// module. A named vector's vectorizer setting is an object keyed by the module
// name.
func namedVectorizers(vectorConfig map[string]models.VectorConfig) map[string]any {
	out := make(map[string]any, len(vectorConfig))
	for name, cfg := range vectorConfig {
		module := vectorizerNone
		if names := moduleNames(cfg.Vectorizer); len(names) > 0 {
			module = names[0].(string)
		}
		out[name] = module
	}
	return out
}

// collectionTTL is a collection's object time-to-live configuration, with the
// values that are meaningless without a configuration left nil.
type collectionTTL struct {
	enabled    bool
	defaultTTL *int64
	deleteOn   *string
}

func objectTTL(cfg *models.ObjectTTLConfig) collectionTTL {
	if cfg == nil {
		return collectionTTL{}
	}
	ttl := collectionTTL{enabled: cfg.Enabled, defaultTTL: &cfg.DefaultTTL}
	if cfg.DeleteOn != "" {
		ttl.deleteOn = &cfg.DeleteOn
	}
	return ttl
}

// nonEmpty returns a pointer to s, or nil when s is empty. The server omits an
// unset string field, which decodes as the empty string.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// collectionArgs builds the fields of a collection resource from the class the
// schema reports.
func collectionArgs(serverID string, class *models.Class) map[string]*llx.RawData {
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
	var deletionStrategy *string
	if rc := class.ReplicationConfig; rc != nil {
		replFactor = rc.Factor
		// Async replication is signaled by a present async config block.
		asyncRepl = rc.AsyncConfig != nil
		deletionStrategy = nonEmpty(rc.DeletionStrategy)
	}
	ttl := objectTTL(class.ObjectTTLConfig)

	return map[string]*llx.RawData{
		"__id":                        llx.StringData(collectionResourceID(serverID, class.Class)),
		"name":                        llx.StringData(class.Class),
		"description":                 llx.StringData(class.Description),
		"vectorizer":                  llx.StringData(class.Vectorizer),
		"modules":                     llx.ArrayData(moduleNames(class.ModuleConfig), types.String),
		"multiTenancyEnabled":         llx.BoolData(multiEnabled),
		"autoTenantCreation":          llx.BoolData(autoCreate),
		"autoTenantActivation":        llx.BoolData(autoActivate),
		"replicationFactor":           llx.IntData(replFactor),
		"asyncReplicationEnabled":     llx.BoolData(asyncRepl),
		"vectorIndexType":             llx.StringData(class.VectorIndexType),
		"generativeModule":            llx.StringDataPtr(moduleWithPrefix(class.ModuleConfig, generativeModulePrefix)),
		"rerankerModule":              llx.StringDataPtr(moduleWithPrefix(class.ModuleConfig, rerankerModulePrefix)),
		"moduleEndpoints":             llx.MapData(moduleEndpoints(class.ModuleConfig), types.String),
		"vectorizers":                 llx.MapData(namedVectorizers(class.VectorConfig), types.String),
		"objectTtlEnabled":            llx.BoolData(ttl.enabled),
		"objectTtlDefault":            llx.IntDataPtr(ttl.defaultTTL),
		"objectTtlDeleteOn":           llx.StringDataPtr(ttl.deleteOn),
		"replicationDeletionStrategy": llx.StringDataPtr(deletionStrategy),
	}
}

func tenantResourceID(collectionID, name string) string {
	return collectionID + "/tenant/" + name
}

// tenants lists the tenants of a multi-tenant collection. A collection without
// multi-tenancy has none, and the server refuses the request for it, so no
// request is made.
func (r *mqlWeaviateCollection) tenants() ([]any, error) {
	if !r.MultiTenancyEnabled.Data {
		return []any{}, nil
	}
	client, err := weaviateConnection(r.MqlRuntime).Client()
	if err != nil {
		return nil, err
	}
	tenants, err := client.Schema().TenantsGetter().WithClassName(r.Name.Data).Do(weaviateContext())
	if err != nil {
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}
	list := make([]any, 0, len(tenants))
	for _, t := range tenants {
		res, err := CreateResource(r.MqlRuntime, "weaviate.collection.tenant", map[string]*llx.RawData{
			"__id":           llx.StringData(tenantResourceID(r.__id, t.Name)),
			"name":           llx.StringData(t.Name),
			"activityStatus": llx.StringData(t.ActivityStatus),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// collectionsByName indexes the collections an instance lists by name, so a
// reference by name resolves against the list already read rather than with a
// request of its own.
func collectionsByName(instance *mqlWeaviateInstance) (map[string]*mqlWeaviateCollection, error) {
	collections := instance.GetCollections()
	if collections.Error != nil {
		return nil, collections.Error
	}
	out := make(map[string]*mqlWeaviateCollection, len(collections.Data))
	for _, c := range collections.Data {
		if col, ok := c.(*mqlWeaviateCollection); ok {
			out[col.Name.Data] = col
		}
	}
	return out, nil
}
