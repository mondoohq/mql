// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package cassandraconf contains the parsers for Apache Cassandra's on-disk
// configuration: cassandra.yaml, cassandra-env.sh, and
// cassandra-rackdc.properties. They operate on already-read file content so
// they don't depend on a particular filesystem implementation, which lets
// them be unit-tested against inlined fixtures and re-used over different
// transports (local, SSH, container snapshot, ...).
//
// Option names follow Cassandra 4.1 and later, which renamed most of
// cassandra.yaml and moved durations and sizes to unit-suffixed values
// (read_request_timeout: 5000ms rather than read_request_timeout_in_ms:
// 5000). The pre-4.1 spellings are not read.
package cassandraconf

import (
	"go.mondoo.com/mql/providers/os/resources/yamlconf"
)

// Conf is the result of parsing a cassandra.yaml.
type Conf struct {
	// Params is the configuration tree, normalized so every value is
	// JSON-native. See yamlconf.Parse for why normalization is mandatory
	// rather than cosmetic.
	Params map[string]any
}

// ParseConf parses the content of a cassandra.yaml.
//
// An empty file is not an error: it parses to an empty tree and every
// accessor reports the default the server would have used.
func ParseConf(content string) (*Conf, error) {
	params, err := yamlconf.Parse(content, "cassandra.yaml")
	if err != nil {
		return nil, err
	}
	return &Conf{Params: params}, nil
}

// ---------------------------------------------------------------------------
// plugin blocks
// ---------------------------------------------------------------------------

// ClassName reads a plugin setting that names an implementation class,
// falling back to def when it is unset.
//
// Cassandra accepts two shapes for these settings. The historical one is a
// bare scalar (`authenticator: PasswordAuthenticator`); since 5.0 the same
// setting can be a mapping carrying `class_name` alongside `parameters`.
// Reading only the scalar form would report a cluster that uses the mapping
// form as running the permissive default.
func ClassName(params map[string]any, def string, path ...string) string {
	v, ok := yamlconf.Lookup(params, path...)
	if !ok || v == nil {
		return def
	}
	if m, ok := v.(map[string]any); ok {
		if s := yamlconf.String(m, "class_name"); s != "" {
			return s
		}
		return def
	}
	if s := yamlconf.ScalarString(v); s != "" {
		return s
	}
	return def
}

// pluginParam reads a single parameter out of a plugin block, which
// Cassandra writes as a list of mappings under `parameters`.
func pluginParam(block map[string]any, key string) string {
	for _, p := range yamlconf.Mappings(block, "parameters") {
		if s := yamlconf.String(p, key); s != "" {
			return s
		}
	}
	return ""
}

// Seeds reports the seed node addresses configured for the cluster.
//
// The seeds live two levels inside the seed_provider plugin block, as a
// comma-delimited string under `parameters`, so they are not reachable with
// a plain key-path lookup.
func Seeds(params map[string]any) []string {
	for _, provider := range yamlconf.Mappings(params, "seed_provider") {
		if raw := pluginParam(provider, "seeds"); raw != "" {
			return yamlconf.SplitList(raw)
		}
	}
	return nil
}

// SeedProviderClass reports the class implementing seed discovery.
func SeedProviderClass(params map[string]any) string {
	for _, provider := range yamlconf.Mappings(params, "seed_provider") {
		if s := yamlconf.String(provider, "class_name"); s != "" {
			return s
		}
	}
	return ""
}

// AuditLoggerClass reports the class the audit log is written through.
func AuditLoggerClass(params map[string]any) string {
	for _, logger := range yamlconf.Mappings(params, "audit_logging_options", "logger") {
		if s := yamlconf.String(logger, "class_name"); s != "" {
			return s
		}
	}
	return ""
}

// TDEKeyProviderClass reports the class supplying the at-rest encryption key.
func TDEKeyProviderClass(params map[string]any) string {
	for _, provider := range yamlconf.Mappings(params, "transparent_data_encryption_options", "key_provider") {
		if s := yamlconf.String(provider, "class_name"); s != "" {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// derived security posture
// ---------------------------------------------------------------------------

// Default classes Cassandra falls back to when the setting is absent. All
// three of the AllowAll variants are permissive, which is why the accessors
// must report them rather than an empty string: an absent authenticator is
// an open cluster, not an unknown one.
const (
	DefaultAuthenticator     = "AllowAllAuthenticator"
	DefaultAuthorizer        = "AllowAllAuthorizer"
	DefaultRoleManager       = "CassandraRoleManager"
	DefaultNetworkAuthorizer = "AllowAllNetworkAuthorizer"
)

// Authenticator reports the configured authenticator class.
func Authenticator(params map[string]any) string {
	return ClassName(params, DefaultAuthenticator, "authenticator")
}

// Authorizer reports the configured authorizer class.
func Authorizer(params map[string]any) string {
	return ClassName(params, DefaultAuthorizer, "authorizer")
}

// RoleManager reports the configured role manager class.
func RoleManager(params map[string]any) string {
	return ClassName(params, DefaultRoleManager, "role_manager")
}

// NetworkAuthorizer reports the configured network authorizer class.
func NetworkAuthorizer(params map[string]any) string {
	return ClassName(params, DefaultNetworkAuthorizer, "network_authorizer")
}

// AuthenticationEnabled reports whether clients must present credentials.
//
// Cassandra ships with AllowAllAuthenticator, which performs no
// authentication at all, so the check is against that class rather than
// against an enabled flag. The class name is matched on its trailing segment
// so a fully qualified spelling
// (org.apache.cassandra.auth.AllowAllAuthenticator) reads the same as the
// short one, which is how the shipped file writes it.
func AuthenticationEnabled(params map[string]any) bool {
	return shortClass(Authenticator(params)) != DefaultAuthenticator
}

// AuthorizationEnabled reports whether permissions are enforced.
//
// Cassandra ships with AllowAllAuthorizer, which grants every permission, so
// the check is against that class. Note that authorization is only
// meaningful alongside authentication: AllowAllAuthenticator with
// CassandraAuthorizer leaves every client authenticated as anonymous.
func AuthorizationEnabled(params map[string]any) bool {
	return shortClass(Authorizer(params)) != DefaultAuthorizer
}

// NetworkAuthorizationEnabled reports whether per-datacenter role
// restrictions are enforced.
func NetworkAuthorizationEnabled(params map[string]any) bool {
	return shortClass(NetworkAuthorizer(params)) != DefaultNetworkAuthorizer
}

// shortClass reduces a fully qualified Java class name to its trailing
// segment, leaving an already-short name untouched.
func shortClass(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return name
}

// ClientEncryptionOptional reports whether the native transport still
// accepts unencrypted connections while client encryption is on.
//
// The server's default is not a constant: `optional` defaults to true when
// client encryption is disabled and to false when it is enabled. Reporting a
// flat false would describe a transitional deployment, which does accept
// plaintext, as one that does not.
func ClientEncryptionOptional(params map[string]any) bool {
	enabled := yamlconf.Bool(params, false, "client_encryption_options", "enabled")
	return yamlconf.Bool(params, !enabled, "client_encryption_options", "optional")
}

// ServerEncryptionOptional reports whether the storage port still accepts
// unencrypted internode connections.
//
// As with the client side the default is conditional: `optional` defaults to
// true when internode_encryption is none, and to false otherwise.
func ServerEncryptionOptional(params map[string]any) bool {
	none := InternodeEncryption(params) == "none"
	return yamlconf.Bool(params, none, "server_encryption_options", "optional")
}

// InternodeEncryption reports which internode connections are encrypted:
// none, dc, rack, or all. It is none when unset.
func InternodeEncryption(params map[string]any) string {
	v := yamlconf.String(params, "server_encryption_options", "internode_encryption")
	if v == "" {
		return "none"
	}
	return v
}
