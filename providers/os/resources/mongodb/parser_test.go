// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/mongodb"
)

const fullConf = `
storage:
  dbPath: /var/lib/mongodb
  directoryPerDB: true
  engine: wiredTiger
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  verbosity: 2
  quiet: false
net:
  port: 27018
  bindIp: 127.0.0.1,10.0.0.5
  ipv6: false
  maxIncomingConnections: 200
  unixDomainSocket:
    enabled: true
    pathPrefix: /tmp
    filePermissions: 0700
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/ca.pem
    CRLFile: /etc/ssl/crl.pem
    clusterFile: /etc/ssl/cluster.pem
    allowInvalidCertificates: false
    allowInvalidHostnames: false
    disabledProtocols: TLS1_0,TLS1_1
    FIPSMode: true
security:
  authorization: enabled
  keyFile: /etc/mongo/keyfile
  clusterAuthMode: x509
  javascriptEnabled: false
  redactClientLogData: true
  enableEncryption: true
  encryptionCipherMode: AES256-GCM
setParameter:
  enableLocalhostAuthBypass: false
  authenticationMechanisms: SCRAM-SHA-256
  scramIterationCount: 20000
  auditAuthorizationSuccess: true
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.json
  filter: '{ atype: "authenticate" }'
processManagement:
  fork: true
  pidFilePath: /var/run/mongod.pid
replication:
  replSetName: rs0
  oplogSizeMB: 2048
sharding:
  clusterRole: shardsvr
operationProfiling:
  mode: slowOp
  slowOpThresholdMs: 50
`

func TestParseConf(t *testing.T) {
	c, err := mongodb.ParseConf(fullConf)
	require.NoError(t, err)

	assert.Equal(t, "/var/lib/mongodb", mongodb.String(c.Params, "storage", "dbPath"))
	assert.Equal(t, "wiredTiger", mongodb.String(c.Params, "storage", "engine"))
	assert.Equal(t, int64(27018), mongodb.Int(c.Params, 27017, "net", "port"))
	assert.Equal(t, int64(200), mongodb.Int(c.Params, 65536, "net", "maxIncomingConnections"))
	assert.Equal(t, []string{"127.0.0.1", "10.0.0.5"}, mongodb.List(c.Params, "net", "bindIp"))
	assert.Equal(t, "rs0", mongodb.String(c.Params, "replication", "replSetName"))
	assert.Equal(t, "shardsvr", mongodb.String(c.Params, "sharding", "clusterRole"))
	assert.Equal(t, "slowOp", mongodb.String(c.Params, "operationProfiling", "mode"))
	assert.Equal(t, int64(50), mongodb.Int(c.Params, 100, "operationProfiling", "slowOpThresholdMs"))
	assert.Equal(t, `{ atype: "authenticate" }`, mongodb.String(c.Params, "auditLog", "filter"))
}

// Every value the parser hands to llx has to be JSON-native. yaml.v3 decodes
// integers as `int`, which llx has no encoding for, so a missed conversion
// only surfaces as a query-time error rather than a parse failure.
func TestParseConfNormalizesToJSONNativeTypes(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  port: 27017
  tls:
    mode: requireTLS
    allowInvalidCertificates: false
    disabledProtocols:
      - TLS1_0
      - TLS1_1
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 1.5
`)
	require.NoError(t, err)

	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case nil, bool, string, int64, float64:
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for _, item := range x {
				walk(item)
			}
		default:
			t.Fatalf("value %#v of type %T is not JSON-native", v, v)
		}
	}
	walk(c.Params)

	// Spot-check that the numbers survived with the right types.
	port, ok := mongodb.Lookup(c.Params, "net", "port")
	require.True(t, ok)
	assert.Equal(t, int64(27017), port)

	cache, ok := mongodb.Lookup(c.Params, "storage", "wiredTiger", "engineConfig", "cacheSizeGB")
	require.True(t, ok)
	assert.Equal(t, 1.5, cache)
}

func TestParseConfEmpty(t *testing.T) {
	for _, content := range []string{"", "   \n\n", "# just a comment\n"} {
		c, err := mongodb.ParseConf(content)
		require.NoError(t, err)
		assert.Empty(t, c.Params)
		// A server running entirely on defaults still reports them.
		assert.Equal(t, int64(27017), mongodb.Int(c.Params, 27017, "net", "port"))
		assert.Equal(t, "disabled", mongodb.TLSMode(c.Params))
	}
}

func TestParseConfRejectsNonMapping(t *testing.T) {
	for _, content := range []string{"just a scalar", "- a\n- b\n"} {
		_, err := mongodb.ParseConf(content)
		assert.Error(t, err, "content %q should not parse as a config", content)
	}
}

func TestParseConfInvalidYAML(t *testing.T) {
	_, err := mongodb.ParseConf("net:\n  port: 27017\n bindIp: bad indent\n")
	assert.Error(t, err)
}

func TestLookup(t *testing.T) {
	c, err := mongodb.ParseConf("net:\n  tls:\n    mode: requireTLS\n  port: 27017\nsecurity: null\n")
	require.NoError(t, err)

	v, ok := mongodb.Lookup(c.Params, "net", "tls", "mode")
	assert.True(t, ok)
	assert.Equal(t, "requireTLS", v)

	// A key that is present but explicitly null reports found-with-nil, so
	// callers can tell it apart from an unset key.
	v, ok = mongodb.Lookup(c.Params, "security")
	assert.True(t, ok)
	assert.Nil(t, v)

	_, ok = mongodb.Lookup(c.Params, "net", "missing")
	assert.False(t, ok)

	// Walking through a scalar must not panic.
	_, ok = mongodb.Lookup(c.Params, "net", "port", "deeper")
	assert.False(t, ok)

	_, ok = mongodb.Lookup(c.Params)
	assert.False(t, ok)
}

// mongod defaults several security-relevant settings to true, so an absent
// key must not read as false.
func TestBoolDefaults(t *testing.T) {
	c, err := mongodb.ParseConf("net:\n  port: 27017\n")
	require.NoError(t, err)

	assert.True(t, mongodb.Bool(c.Params, true, "security", "javascriptEnabled"))
	assert.True(t, mongodb.Bool(c.Params, true, "setParameter", "enableLocalhostAuthBypass"))
	assert.False(t, mongodb.Bool(c.Params, false, "security", "redactClientLogData"))
}

func TestBoolCoercion(t *testing.T) {
	c, err := mongodb.ParseConf(`
setParameter:
  quotedTrue: "true"
  quotedFalse: "false"
  numeric: 1
  zero: 0
  garbage: sometimes
security:
  javascriptEnabled: false
`)
	require.NoError(t, err)

	assert.True(t, mongodb.Bool(c.Params, false, "setParameter", "quotedTrue"))
	assert.False(t, mongodb.Bool(c.Params, true, "setParameter", "quotedFalse"))
	assert.True(t, mongodb.Bool(c.Params, false, "setParameter", "numeric"))
	assert.False(t, mongodb.Bool(c.Params, true, "setParameter", "zero"))
	// An unparseable value falls back rather than guessing.
	assert.True(t, mongodb.Bool(c.Params, true, "setParameter", "garbage"))
	assert.False(t, mongodb.Bool(c.Params, true, "security", "javascriptEnabled"))
}

func TestIntAndString(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  port: 27017
  quoted: "27019"
  notANumber: abc
  fractional: 3.9
security:
  authorization: enabled
  flag: true
`)
	require.NoError(t, err)

	assert.Equal(t, int64(27017), mongodb.Int(c.Params, 1, "net", "port"))
	assert.Equal(t, int64(27019), mongodb.Int(c.Params, 1, "net", "quoted"))
	assert.Equal(t, int64(1), mongodb.Int(c.Params, 1, "net", "notANumber"))
	assert.Equal(t, int64(3), mongodb.Int(c.Params, 1, "net", "fractional"))
	assert.Equal(t, int64(27017), mongodb.Int(c.Params, 27017, "net", "unset"))

	assert.Equal(t, "enabled", mongodb.String(c.Params, "security", "authorization"))
	// Non-string scalars format back so a value still reads as written.
	assert.Equal(t, "27017", mongodb.String(c.Params, "net", "port"))
	assert.Equal(t, "true", mongodb.String(c.Params, "security", "flag"))
	assert.Equal(t, "", mongodb.String(c.Params, "security", "unset"))
}

// net.bindIp is documented as a comma-delimited string, but a YAML sequence
// is common in the wild and mongod reads it, so both have to work.
func TestListAcceptsBothSpellings(t *testing.T) {
	commaForm, err := mongodb.ParseConf("net:\n  bindIp: 127.0.0.1, 10.0.0.5 ,::1\n")
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1", "10.0.0.5", "::1"}, mongodb.List(commaForm.Params, "net", "bindIp"))

	seqForm, err := mongodb.ParseConf("net:\n  bindIp:\n    - 127.0.0.1\n    - 10.0.0.5\n")
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1", "10.0.0.5"}, mongodb.List(seqForm.Params, "net", "bindIp"))

	empty, err := mongodb.ParseConf("net:\n  port: 27017\n")
	require.NoError(t, err)
	assert.Nil(t, mongodb.List(empty.Params, "net", "bindIp"))
}

// mongod still accepts the pre-4.2 net.ssl tree, so reading only net.tls
// would report TLS as unconfigured on a host that has it configured.
func TestTLSLegacySSLTree(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  ssl:
    mode: requireSSL
    PEMKeyFile: /etc/ssl/mongodb.pem
    PEMKeyPassword: secret
    CAFile: /etc/ssl/ca.pem
    allowInvalidCertificates: true
    disabledProtocols: TLS1_0,TLS1_1
    FIPSMode: true
`)
	require.NoError(t, err)

	// The legacy mode values are exact aliases, so they report under the
	// modern name and an audit asserting requireTLS still passes.
	assert.Equal(t, "requireTLS", mongodb.TLSMode(c.Params))
	assert.Equal(t, "/etc/ssl/mongodb.pem", mongodb.TLSString(c.Params, "certificateKeyFile"))
	assert.Equal(t, "secret", mongodb.TLSString(c.Params, "certificateKeyFilePassword"))
	assert.Equal(t, "/etc/ssl/ca.pem", mongodb.TLSString(c.Params, "CAFile"))
	assert.True(t, mongodb.TLSBool(c.Params, false, "allowInvalidCertificates"))
	assert.True(t, mongodb.TLSBool(c.Params, false, "FIPSMode"))
	assert.Equal(t, []string{"TLS1_0", "TLS1_1"}, mongodb.TLSList(c.Params, "disabledProtocols"))
}

func TestTLSModern(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  tls:
    mode: preferTLS
    certificateKeyFile: /etc/ssl/modern.pem
    allowInvalidHostnames: true
`)
	require.NoError(t, err)

	assert.Equal(t, "preferTLS", mongodb.TLSMode(c.Params))
	assert.Equal(t, "/etc/ssl/modern.pem", mongodb.TLSString(c.Params, "certificateKeyFile"))
	assert.True(t, mongodb.TLSBool(c.Params, false, "allowInvalidHostnames"))
	assert.Equal(t, "", mongodb.TLSString(c.Params, "CAFile"))
}

// A host that sets both trees is misconfigured, but mongod reads net.tls, so
// that is what gets reported.
func TestTLSPrefersModernTree(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/new.pem
  ssl:
    mode: allowSSL
    PEMKeyFile: /etc/ssl/old.pem
`)
	require.NoError(t, err)

	assert.Equal(t, "requireTLS", mongodb.TLSMode(c.Params))
	assert.Equal(t, "/etc/ssl/new.pem", mongodb.TLSString(c.Params, "certificateKeyFile"))
}

// An explicit `false` under net.tls has to win over a `true` under net.ssl.
// Probing for the key rather than for a truthy value is what makes that work.
func TestTLSBoolRespectsExplicitFalse(t *testing.T) {
	c, err := mongodb.ParseConf(`
net:
  tls:
    allowInvalidCertificates: false
  ssl:
    allowInvalidCertificates: true
`)
	require.NoError(t, err)

	assert.False(t, mongodb.TLSBool(c.Params, false, "allowInvalidCertificates"))
}

func TestTLSModeDefaults(t *testing.T) {
	c, err := mongodb.ParseConf("net:\n  port: 27017\n")
	require.NoError(t, err)
	assert.Equal(t, "disabled", mongodb.TLSMode(c.Params))

	// An unrecognized value is reported as written rather than mapped.
	custom, err := mongodb.ParseConf("net:\n  tls:\n    mode: somethingElse\n")
	require.NoError(t, err)
	assert.Equal(t, "somethingElse", mongodb.TLSMode(custom.Params))
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "mongodb 7",
			output: "db version v7.0.14\nBuild Info: {\n    \"version\": \"7.0.14\"\n}\n",
			want:   "7.0.14",
		},
		{
			name:   "mongodb 4.4",
			output: "db version v4.4.29\ngit version: abc123\n",
			want:   "4.4.29",
		},
		{
			name:   "two-component version",
			output: "db version v8.0\n",
			want:   "8.0",
		},
		{
			name:   "no v prefix",
			output: "db version 6.0.16\n",
			want:   "6.0.16",
		},
		{
			name:   "unrelated output",
			output: "bash: mongod: command not found\n",
			want:   "",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mongodb.ParseVersion(tc.output))
		})
	}
}
