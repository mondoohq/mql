// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Transport-crypto accessors for the Cloud-Foundry-broker DBaaS instances
// (OpenSearch, Redis, RabbitMQ, LogMe). These services stash their TLS
// configuration in the free-form `parameters` blob under stable keys
// (`tls-protocols`, `tls-ciphers`, ...). We surface the TLS-relevant keys as
// typed fields so post-quantum-cryptography readiness checks can grade the
// negotiated protocol versions and cipher suites. The Flex engines (Postgres,
// MongoDB, SQLServer) and MariaDB expose no transport-crypto parameters and so
// have no such fields.

// paramValue reads a single key out of a DBaaS instance's parameters blob,
// returning nil when the blob is absent or not a map.
func paramValue(parameters any, key string) any {
	params, ok := parameters.(map[string]any)
	if !ok {
		return nil
	}
	return params[key]
}

// tlsParamList extracts a string-list TLS parameter (e.g. tls-protocols,
// tls-ciphers) and returns it as the []any list MQL expects. Both JSON arrays
// and single comma-separated strings are accepted (see dictStrSlice); a missing
// key yields an empty list.
func tlsParamList(params *plugin.TValue[any], key string) ([]any, error) {
	if params.Error != nil {
		return nil, params.Error
	}
	return strSlice(dictStrSlice(paramValue(params.Data, key))), nil
}

// tlsParamString extracts a scalar-string TLS parameter (e.g. tls-ciphersuites,
// fluentd-tls-min-version). A missing key yields "".
func tlsParamString(params *plugin.TValue[any], key string) (string, error) {
	if params.Error != nil {
		return "", params.Error
	}
	return dictStr(paramValue(params.Data, key)), nil
}

// ---- OpenSearch ----

func (r *mqlStackitOpenSearchInstance) tlsProtocols() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-protocols")
}

func (r *mqlStackitOpenSearchInstance) tlsCiphers() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-ciphers")
}

// ---- Redis ----

func (r *mqlStackitRedisInstance) tlsProtocols() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-protocols")
}

func (r *mqlStackitRedisInstance) tlsCiphers() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-ciphers")
}

func (r *mqlStackitRedisInstance) tlsCiphersuites() (string, error) {
	return tlsParamString(r.GetParameters(), "tls-ciphersuites")
}

// ---- RabbitMQ ----

func (r *mqlStackitRabbitMqInstance) tlsProtocols() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-protocols")
}

func (r *mqlStackitRabbitMqInstance) tlsCiphers() ([]any, error) {
	return tlsParamList(r.GetParameters(), "tls-ciphers")
}

// ---- LogMe ----
//
// LogMe fronts a Fluentd ingestion listener and an embedded OpenSearch API,
// each with its own TLS knobs, so the parameter keys are prefixed accordingly.

func (r *mqlStackitLogMeInstance) fluentdTlsMinVersion() (string, error) {
	return tlsParamString(r.GetParameters(), "fluentd-tls-min-version")
}

func (r *mqlStackitLogMeInstance) fluentdTlsMaxVersion() (string, error) {
	return tlsParamString(r.GetParameters(), "fluentd-tls-max-version")
}

func (r *mqlStackitLogMeInstance) fluentdTlsCiphers() (string, error) {
	return tlsParamString(r.GetParameters(), "fluentd-tls-ciphers")
}

func (r *mqlStackitLogMeInstance) opensearchTlsProtocols() ([]any, error) {
	return tlsParamList(r.GetParameters(), "opensearch-tls-protocols")
}

func (r *mqlStackitLogMeInstance) opensearchTlsCiphers() ([]any, error) {
	return tlsParamList(r.GetParameters(), "opensearch-tls-ciphers")
}
