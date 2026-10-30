// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// classifyDoError wraps a DigitalOcean API refusal in the matching llx error
// kind, so a caller can tell "the token may not read this" from other
// failures without matching on the message. Anything that is not a refusal is
// returned as is.
func classifyDoError(err error) error {
	var er *godo.ErrorResponse
	if !errors.As(err, &er) || er.Response == nil {
		return err
	}
	switch er.Response.StatusCode {
	case http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case http.StatusForbidden:
		return llx.Forbidden(err)
	case http.StatusTooManyRequests:
		return llx.TooManyRequests(err)
	}
	return err
}

// engineConfig is the decoded advanced configuration of one cluster. Exactly
// one of the engine pointers is set, matching the cluster's engine; all are
// nil for an engine without a configuration endpoint or when the API answered
// with no configuration.
type engineConfig struct {
	pg         *godo.PostgreSQLConfig
	mysql      *godo.MySQLConfig
	redis      *godo.RedisConfig
	valkey     *godo.ValkeyConfig
	mongo      *godo.MongoDBConfig
	opensearch *godo.OpensearchConfig
	kafka      *godo.KafkaConfig
}

// value returns the configuration struct that is set, or nil.
func (c *engineConfig) value() any {
	switch {
	case c == nil:
		return nil
	case c.pg != nil:
		return c.pg
	case c.mysql != nil:
		return c.mysql
	case c.redis != nil:
		return c.redis
	case c.valkey != nil:
		return c.valkey
	case c.mongo != nil:
		return c.mongo
	case c.opensearch != nil:
		return c.opensearch
	case c.kafka != nil:
		return c.kafka
	}
	return nil
}

// fetchEngineConfig reads the cluster's engine configuration once and shares
// it between engineConfig and the typed per-engine settings.
//
// A 404 means the cluster has no configuration to report (an engine or plan
// without the endpoint), which leaves every dependent field null. Any other
// failure is returned, so a refusal is never reported as an unset setting.
func (r *mqlDigitaloceanDatabase) fetchEngineConfig() (*engineConfig, error) {
	r.engineConfigOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		dbs := conn.Client().Databases
		ctx := context.Background()
		id := r.Id.Data
		cfg := &engineConfig{}
		var err error
		switch r.Engine.Data {
		case "pg":
			cfg.pg, _, err = dbs.GetPostgreSQLConfig(ctx, id)
		case "mysql":
			cfg.mysql, _, err = dbs.GetMySQLConfig(ctx, id)
		case "redis":
			cfg.redis, _, err = dbs.GetRedisConfig(ctx, id)
		case "valkey":
			cfg.valkey, _, err = dbs.GetValkeyConfig(ctx, id)
		case "mongodb":
			cfg.mongo, _, err = dbs.GetMongoDBConfig(ctx, id)
		case "opensearch":
			cfg.opensearch, _, err = dbs.GetOpensearchConfig(ctx, id)
		case "kafka":
			cfg.kafka, _, err = dbs.GetKafkaConfig(ctx, id)
		default:
			return
		}
		if err != nil {
			if isDoNotFound(err) {
				return
			}
			r.engineConfigErr = classifyDoError(err)
			return
		}
		r.engineConfigValue = cfg
	})
	return r.engineConfigValue, r.engineConfigErr
}

// isSecretShapedConfigKey reports whether a configuration setting's name
// marks a value that may be a credential. No engine configuration godo models
// today carries one, but engineConfig publishes the whole struct, so a setting
// added by a later SDK release would otherwise reach the dict unreviewed.
//
// Names are matched by segment rather than by substring, because real
// settings contain credential words without holding one:
// innodb_ft_min_token_size is a length and sql_require_primary_key a flag.
func isSecretShapedConfigKey(name string) bool {
	segs := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '.' || r == '-'
	})
	for i, seg := range segs {
		switch seg {
		case "password", "passwd", "secret", "credential", "credentials":
			return true
		}
		// A token or key is a credential only as the final segment, and a
		// key only when qualified as one (api_key, access_key, ...).
		if i != len(segs)-1 {
			continue
		}
		if seg == "token" {
			return true
		}
		if seg == "key" && i > 0 {
			switch segs[i-1] {
			case "api", "access", "private", "secret", "auth":
				return true
			}
		}
	}
	return false
}

// redactSecretShapedKeys removes secret-shaped settings from a decoded
// configuration, descending into nested blocks (PgBouncer, TimescaleDB).
func redactSecretShapedKeys(m map[string]any) {
	for k, v := range m {
		if isSecretShapedConfigKey(k) {
			delete(m, k)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			redactSecretShapedKeys(nested)
		}
	}
}

// engineConfigDict converts an engine configuration struct to a dict keyed by
// the API setting names, dropping any setting whose name looks like a
// credential. Settings the API did not report are absent (godo omits nil
// pointers), so every key present is a value that was read.
func engineConfigDict(cfg any) (map[string]any, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	redactSecretShapedKeys(out)
	return out, nil
}

func (r *mqlDigitaloceanDatabase) engineConfig() (any, error) {
	cfg, err := r.fetchEngineConfig()
	if err != nil {
		return nil, err
	}
	v := cfg.value()
	if v == nil {
		r.EngineConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return engineConfigDict(v)
}

// engineBool resolves a per-engine boolean setting, leaving the field null
// when the engine does not carry it or the API did not report it.
func (r *mqlDigitaloceanDatabase) engineBool(field *plugin.TValue[bool], pick func(*engineConfig) *bool) (bool, error) {
	cfg, err := r.fetchEngineConfig()
	if err != nil {
		return false, err
	}
	if cfg == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	v := pick(cfg)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// redisSSL returns the TLS requirement of a Redis or Valkey cluster.
func redisSSL(c *engineConfig) *bool {
	switch {
	case c.redis != nil:
		return c.redis.RedisSSL
	case c.valkey != nil:
		return c.valkey.ValkeySSL
	}
	return nil
}

// redisACLChannelsDefault returns the default channel permission of a Redis
// or Valkey cluster.
func redisACLChannelsDefault(c *engineConfig) *string {
	switch {
	case c.redis != nil:
		return c.redis.RedisACLChannelsDefault
	case c.valkey != nil:
		return c.valkey.ValkeyACLChannelsDefault
	}
	return nil
}

func (r *mqlDigitaloceanDatabase) sslRequired() (bool, error) {
	return r.engineBool(&r.SslRequired, redisSSL)
}

func (r *mqlDigitaloceanDatabase) aclChannelsDefault() (string, error) {
	cfg, err := r.fetchEngineConfig()
	if err != nil {
		return "", err
	}
	var v *string
	if cfg != nil {
		v = redisACLChannelsDefault(cfg)
	}
	if v == nil {
		r.AclChannelsDefault.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func (r *mqlDigitaloceanDatabase) securityAuditEnabled() (bool, error) {
	return r.engineBool(&r.SecurityAuditEnabled, func(c *engineConfig) *bool {
		if c.opensearch == nil {
			return nil
		}
		return c.opensearch.EnableSecurityAudit
	})
}

func (r *mqlDigitaloceanDatabase) destructiveActionsRequireName() (bool, error) {
	return r.engineBool(&r.DestructiveActionsRequireName, func(c *engineConfig) *bool {
		if c.opensearch == nil {
			return nil
		}
		return c.opensearch.ActionDestructiveRequiresName
	})
}

func (r *mqlDigitaloceanDatabase) reindexRemoteAllowlist() ([]any, error) {
	cfg, err := r.fetchEngineConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.opensearch == nil || cfg.opensearch.ReindexRemoteWhitelist == nil {
		r.ReindexRemoteAllowlist.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return toAnySlice(cfg.opensearch.ReindexRemoteWhitelist), nil
}

func (r *mqlDigitaloceanDatabase) autoCreateTopicsEnabled() (bool, error) {
	return r.engineBool(&r.AutoCreateTopicsEnabled, func(c *engineConfig) *bool {
		if c.kafka == nil {
			return nil
		}
		return c.kafka.AutoCreateTopicsEnable
	})
}

func (r *mqlDigitaloceanDatabase) slowQueryLogEnabled() (bool, error) {
	return r.engineBool(&r.SlowQueryLogEnabled, func(c *engineConfig) *bool {
		if c.mysql == nil {
			return nil
		}
		return c.mysql.SlowQueryLog
	})
}

func (r *mqlDigitaloceanDatabase) requirePrimaryKey() (bool, error) {
	return r.engineBool(&r.RequirePrimaryKey, func(c *engineConfig) *bool {
		if c.mysql == nil {
			return nil
		}
		return c.mysql.SQLRequirePrimaryKey
	})
}

// ----- Kafka topics -----

type mqlDigitaloceanDatabaseTopicInternal struct {
	// The topic listing carries only the name, state and replication factor.
	// Partitions and configuration come from the per-topic endpoint, read at
	// most once per topic and shared by every field that needs them.
	detailOnce  sync.Once
	detailValue *godo.DatabaseTopic
	detailErr   error
}

func (r *mqlDigitaloceanDatabaseTopic) id() (string, error) {
	return resourceID("digitalocean.database.topic", r.DatabaseId.Data, r.Name.Data)
}

func (r *mqlDigitaloceanDatabase) topics() ([]any, error) {
	if r.Engine.Data != "kafka" {
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	dbID := r.Id.Data

	topics, err := paginate(context.Background(), func(ctx context.Context, opt *godo.ListOptions) ([]godo.DatabaseTopic, *godo.Response, error) {
		return client.Databases.ListTopics(ctx, dbID, opt)
	})
	if err != nil {
		return nil, classifyDoError(err)
	}

	out := make([]any, 0, len(topics))
	for i := range topics {
		t := topics[i]
		res, err := CreateResource(r.MqlRuntime, "digitalocean.database.topic", map[string]*llx.RawData{
			"databaseId":        llx.StringData(dbID),
			"name":              llx.StringData(t.Name),
			"state":             llx.StringData(t.State),
			"replicationFactor": llx.IntDataPtr(uint32Ptr(t.ReplicationFactor)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// uint32Ptr widens an optional uint32 for llx, keeping absence as nil.
func uint32Ptr(v *uint32) *int64 {
	if v == nil {
		return nil
	}
	w := int64(*v)
	return &w
}

func (r *mqlDigitaloceanDatabaseTopic) database() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.Database)
}

// detail reads the topic's partitions and configuration once.
func (r *mqlDigitaloceanDatabaseTopic) detail() (*godo.DatabaseTopic, error) {
	r.detailOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		t, _, err := conn.Client().Databases.GetTopic(context.Background(), r.DatabaseId.Data, r.Name.Data)
		if err != nil {
			r.detailErr = classifyDoError(err)
			return
		}
		r.detailValue = t
	})
	return r.detailValue, r.detailErr
}

// topicConfig returns the topic's configuration, or nil when none was read.
func (r *mqlDigitaloceanDatabaseTopic) topicConfig() (*godo.TopicConfig, error) {
	t, err := r.detail()
	if err != nil || t == nil {
		return nil, err
	}
	return t.Config, nil
}

func (r *mqlDigitaloceanDatabaseTopic) partitionCount() (int64, error) {
	t, err := r.detail()
	if err != nil {
		return 0, err
	}
	if t == nil {
		r.PartitionCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(len(t.Partitions)), nil
}

// underReplicated counts the partitions whose in-sync replica count is below
// the topic's replication factor. Without a replication factor there is
// nothing to compare against, so the count is unknown.
func underReplicated(t *godo.DatabaseTopic) *int64 {
	if t == nil || t.ReplicationFactor == nil {
		return nil
	}
	var n int64
	for _, p := range t.Partitions {
		if p == nil {
			continue
		}
		if p.InSyncReplicas < *t.ReplicationFactor {
			n++
		}
	}
	return &n
}

func (r *mqlDigitaloceanDatabaseTopic) underReplicatedPartitions() (int64, error) {
	t, err := r.detail()
	if err != nil {
		return 0, err
	}
	n := underReplicated(t)
	if n == nil {
		r.UnderReplicatedPartitions.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *n, nil
}

func (r *mqlDigitaloceanDatabaseTopic) minInsyncReplicas() (int64, error) {
	cfg, err := r.topicConfig()
	if err != nil {
		return 0, err
	}
	if cfg == nil || cfg.MinInsyncReplicas == nil {
		r.MinInsyncReplicas.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*cfg.MinInsyncReplicas), nil
}

func (r *mqlDigitaloceanDatabaseTopic) retentionMs() (int64, error) {
	cfg, err := r.topicConfig()
	if err != nil {
		return 0, err
	}
	if cfg == nil || cfg.RetentionMS == nil {
		r.RetentionMs.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *cfg.RetentionMS, nil
}

func (r *mqlDigitaloceanDatabaseTopic) retentionBytes() (int64, error) {
	cfg, err := r.topicConfig()
	if err != nil {
		return 0, err
	}
	if cfg == nil || cfg.RetentionBytes == nil {
		r.RetentionBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *cfg.RetentionBytes, nil
}

func (r *mqlDigitaloceanDatabaseTopic) cleanupPolicy() (string, error) {
	cfg, err := r.topicConfig()
	if err != nil {
		return "", err
	}
	if cfg == nil || cfg.CleanupPolicy == "" {
		r.CleanupPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return cfg.CleanupPolicy, nil
}
