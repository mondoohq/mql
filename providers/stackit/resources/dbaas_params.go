// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Posture accessors over the Cloud-Foundry-broker DBaaS instances' free-form
// `parameters` blob (OpenSearch, MariaDB, Redis, RabbitMQ, LogMe). Each SDK's
// InstanceParameters model documents the keys the service accepts; the ones
// a policy reads are hoisted here as typed fields so a check compares a value
// rather than indexing a dict. The transport-crypto keys live in dbaas_tls.go.
//
// Keys shared by all five engines: sgw_acl, syslog, graphite,
// enable_monitoring, monitoring_instance_id, max_disk_threshold. The
// metrics_prefix key is deliberately not exposed: the SDK notes it commonly
// carries an API key for the Graphite receiver.

// paramInt reads an integer parameter. The blob arrives through a JSON
// round-trip, so numbers are float64; numeric strings are accepted too. The
// second result is false when the key is absent or not a whole number.
func paramInt(params *plugin.TValue[any], key string) (int64, bool, error) {
	if params.Error != nil {
		return 0, false, params.Error
	}
	v, ok := dictInt(paramValue(params.Data, key))
	return v, ok, nil
}

// paramBool reads a boolean parameter, accepting a JSON bool or the strings
// "true"/"false". The second result is false when the key is absent.
func paramBool(params *plugin.TValue[any], key string) (bool, bool, error) {
	if params.Error != nil {
		return false, false, params.Error
	}
	v := paramValue(params.Data, key)
	if v == nil {
		return false, false, nil
	}
	return dictBool(v), true, nil
}

// observabilityInstanceRef resolves a STACKIT Observability instance by UUID,
// marking the field null when the id is empty or the instance is not
// readable from this project.
func observabilityInstanceRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitObservabilityInstance]) (*mqlStackitObservabilityInstance, error) {
	if id == "" {
		return markNull[mqlStackitObservabilityInstance](field)
	}
	res, err := NewResource(runtime, "stackit.observability.instance", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if isNotFound(err) {
			return markNull[mqlStackitObservabilityInstance](field)
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return markNull[mqlStackitObservabilityInstance](field)
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	return res.(*mqlStackitObservabilityInstance), nil
}

// nullInt reports an absent integer parameter as null on the given field.
func nullInt(field *plugin.TValue[int64]) (int64, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

// nullBool reports an absent boolean parameter as null on the given field.
func nullBool(field *plugin.TValue[bool]) (bool, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

// ---- OpenSearch ----

func (r *mqlStackitOpenSearchInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.GetParameters(), "sgw_acl")
}

func (r *mqlStackitOpenSearchInstance) syslog() ([]any, error) {
	return tlsParamList(r.GetParameters(), "syslog")
}

func (r *mqlStackitOpenSearchInstance) graphite() (string, error) {
	return tlsParamString(r.GetParameters(), "graphite")
}

func (r *mqlStackitOpenSearchInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.GetParameters(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitOpenSearchInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.GetParameters(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitOpenSearchInstance) maxDiskThreshold() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "max_disk_threshold")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxDiskThreshold)
	}
	return v, nil
}

func (r *mqlStackitOpenSearchInstance) plugins() ([]any, error) {
	return tlsParamList(r.GetParameters(), "plugins")
}

// ---- MariaDB ----

func (r *mqlStackitMariaDbInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.GetParameters(), "sgw_acl")
}

func (r *mqlStackitMariaDbInstance) syslog() ([]any, error) {
	return tlsParamList(r.GetParameters(), "syslog")
}

func (r *mqlStackitMariaDbInstance) graphite() (string, error) {
	return tlsParamString(r.GetParameters(), "graphite")
}

func (r *mqlStackitMariaDbInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.GetParameters(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitMariaDbInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.GetParameters(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitMariaDbInstance) maxDiskThreshold() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "max_disk_threshold")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxDiskThreshold)
	}
	return v, nil
}

// ---- Redis ----

func (r *mqlStackitRedisInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.GetParameters(), "sgw_acl")
}

func (r *mqlStackitRedisInstance) syslog() ([]any, error) {
	return tlsParamList(r.GetParameters(), "syslog")
}

func (r *mqlStackitRedisInstance) graphite() (string, error) {
	return tlsParamString(r.GetParameters(), "graphite")
}

func (r *mqlStackitRedisInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.GetParameters(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitRedisInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.GetParameters(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitRedisInstance) maxDiskThreshold() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "max_disk_threshold")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxDiskThreshold)
	}
	return v, nil
}

func (r *mqlStackitRedisInstance) snapshot() (string, error) {
	return tlsParamString(r.GetParameters(), "snapshot")
}

func (r *mqlStackitRedisInstance) maxmemoryPolicy() (string, error) {
	return tlsParamString(r.GetParameters(), "maxmemory-policy")
}

func (r *mqlStackitRedisInstance) notifyKeyspaceEvents() (string, error) {
	return tlsParamString(r.GetParameters(), "notify-keyspace-events")
}

func (r *mqlStackitRedisInstance) maxClients() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "maxclients")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxClients)
	}
	return v, nil
}

// ---- RabbitMQ ----

func (r *mqlStackitRabbitMqInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.GetParameters(), "sgw_acl")
}

func (r *mqlStackitRabbitMqInstance) syslog() ([]any, error) {
	return tlsParamList(r.GetParameters(), "syslog")
}

func (r *mqlStackitRabbitMqInstance) graphite() (string, error) {
	return tlsParamString(r.GetParameters(), "graphite")
}

func (r *mqlStackitRabbitMqInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.GetParameters(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitRabbitMqInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.GetParameters(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitRabbitMqInstance) maxDiskThreshold() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "max_disk_threshold")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxDiskThreshold)
	}
	return v, nil
}

func (r *mqlStackitRabbitMqInstance) plugins() ([]any, error) {
	return tlsParamList(r.GetParameters(), "plugins")
}

// ---- LogMe ----

func (r *mqlStackitLogMeInstance) sgwAcl() ([]any, error) {
	return tlsParamList(r.GetParameters(), "sgw_acl")
}

func (r *mqlStackitLogMeInstance) syslog() ([]any, error) {
	return tlsParamList(r.GetParameters(), "syslog")
}

func (r *mqlStackitLogMeInstance) graphite() (string, error) {
	return tlsParamString(r.GetParameters(), "graphite")
}

func (r *mqlStackitLogMeInstance) monitoringEnabled() (bool, error) {
	v, ok, err := paramBool(r.GetParameters(), "enable_monitoring")
	if err != nil {
		return false, err
	}
	if !ok {
		return nullBool(&r.MonitoringEnabled)
	}
	return v, nil
}

func (r *mqlStackitLogMeInstance) monitoringInstance() (*mqlStackitObservabilityInstance, error) {
	id, err := tlsParamString(r.GetParameters(), "monitoring_instance_id")
	if err != nil {
		return nil, err
	}
	return observabilityInstanceRef(r.MqlRuntime, id, &r.MonitoringInstance)
}

func (r *mqlStackitLogMeInstance) maxDiskThreshold() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "max_disk_threshold")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.MaxDiskThreshold)
	}
	return v, nil
}

func (r *mqlStackitLogMeInstance) fluentdTcpPort() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "fluentd-tcp")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.FluentdTcpPort)
	}
	return v, nil
}

func (r *mqlStackitLogMeInstance) fluentdUdpPort() (int64, error) {
	v, ok, err := paramInt(r.GetParameters(), "fluentd-udp")
	if err != nil {
		return 0, err
	}
	if !ok {
		return nullInt(&r.FluentdUdpPort)
	}
	return v, nil
}

func (r *mqlStackitLogMeInstance) logRetention() (string, error) {
	return tlsParamString(r.GetParameters(), "ism_deletion_after")
}
