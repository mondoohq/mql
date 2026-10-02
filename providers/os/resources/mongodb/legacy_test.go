// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/mongodb"
)

// testdata/ubuntu1604-mongodb.conf is /etc/mongodb.conf exactly as the
// Ubuntu 16.04 mongodb-server 2.6.10 package installs it (18.04's 3.6.3
// package ships the same file with one comment changed). It used to fail
// every field with "must be a YAML mapping". Fails if ParseConf stops
// recognizing the legacy format.
func TestParseConfLegacyUbuntuPackageFile(t *testing.T) {
	content, err := os.ReadFile("testdata/ubuntu1604-mongodb.conf")
	require.NoError(t, err)

	c, err := mongodb.ParseConf(string(content))
	require.NoError(t, err)

	assert.Equal(t, []string{"127.0.0.1"}, mongodb.List(c.Params, "net", "bindIp"))
	assert.Equal(t, "/var/lib/mongodb", mongodb.String(c.Params, "storage", "dbPath"))
	assert.Equal(t, "/var/log/mongodb/mongodb.log", mongodb.String(c.Params, "systemLog", "path"))
	assert.Equal(t, "file", mongodb.String(c.Params, "systemLog", "destination"))
	assert.True(t, mongodb.Bool(c.Params, false, "systemLog", "logAppend"))
	assert.True(t, mongodb.Bool(c.Params, false, "storage", "journal", "enabled"))

	// Everything else in the file is commented out, so the defaults hold.
	_, set := mongodb.Lookup(c.Params, "net", "port")
	assert.False(t, set, "#port = 27017 is a comment")
	assert.Equal(t, "", mongodb.String(c.Params, "security", "authorization"))
	assert.Equal(t, "disabled", mongodb.TLSMode(c.Params))
}

// The sweep's flip: the archive-package file with auth and an all-interfaces
// bind_ip. `mongodb.conf.authorization == "enabled"` and
// `mongodb.conf.bindIp.none(_ == "0.0.0.0")` both errored instead of reading
// true and false.
func TestParseConfLegacyOptions(t *testing.T) {
	c, err := mongodb.ParseConf(`dbpath=/var/lib/mongodb
bind_ip = 0.0.0.0,::1   # every interface
auth = true
port = 27018
maxConns = 500
ipv6 = true
noscripting = true
nounixsocket = true
unixSocketPrefix = /run/mongodb
keyFile = /etc/mongodb-keyfile
replSet = rs0
oplogSize = 1024
profile = 1
slowms = 250
verbose = vv
fork = true
pidfilepath = /run/mongodb/mongod.pid
setParameter = enableLocalhostAuthBypass=false
setParameter = scramIterationCount=20000
nohttpinterface = true
`)
	require.NoError(t, err)
	p := c.Params

	assert.Equal(t, []string{"0.0.0.0", "::1"}, mongodb.List(p, "net", "bindIp"))
	assert.Equal(t, "enabled", mongodb.String(p, "security", "authorization"))
	assert.Equal(t, int64(27018), mongodb.Int(p, 27017, "net", "port"))
	assert.Equal(t, int64(500), mongodb.Int(p, 65536, "net", "maxIncomingConnections"))
	assert.True(t, mongodb.Bool(p, false, "net", "ipv6"))
	assert.False(t, mongodb.Bool(p, true, "security", "javascriptEnabled"))
	assert.False(t, mongodb.Bool(p, true, "net", "unixDomainSocket", "enabled"))
	assert.Equal(t, "/run/mongodb", mongodb.String(p, "net", "unixDomainSocket", "pathPrefix"))
	assert.Equal(t, "/etc/mongodb-keyfile", mongodb.String(p, "security", "keyFile"))
	assert.Equal(t, "rs0", mongodb.String(p, "replication", "replSetName"))
	assert.Equal(t, int64(1024), mongodb.Int(p, 0, "replication", "oplogSizeMB"))
	assert.Equal(t, "slowOp", mongodb.String(p, "operationProfiling", "mode"))
	assert.Equal(t, int64(250), mongodb.Int(p, 100, "operationProfiling", "slowOpThresholdMs"))
	assert.Equal(t, int64(2), mongodb.Int(p, 0, "systemLog", "verbosity"))
	assert.True(t, mongodb.Bool(p, false, "processManagement", "fork"))
	assert.Equal(t, "/run/mongodb/mongod.pid", mongodb.String(p, "processManagement", "pidFilePath"))
	assert.False(t, mongodb.Bool(p, true, "setParameter", "enableLocalhostAuthBypass"))
	assert.Equal(t, int64(20000), mongodb.Int(p, 15000, "setParameter", "scramIterationCount"))

	// An option with no YAML counterpart is kept under its legacy name.
	assert.Equal(t, true, p["nohttpinterface"])
}

func TestParseConfLegacySwitches(t *testing.T) {
	t.Run("noauth", func(t *testing.T) {
		c, err := mongodb.ParseConf("noauth = true\n")
		require.NoError(t, err)
		assert.Equal(t, "disabled", mongodb.String(c.Params, "security", "authorization"))
	})

	// mongod treats a switch set to false as absent.
	t.Run("auth = false leaves authorization unset", func(t *testing.T) {
		c, err := mongodb.ParseConf("auth = false\n")
		require.NoError(t, err)
		_, set := mongodb.Lookup(c.Params, "security", "authorization")
		assert.False(t, set)
	})

	t.Run("noscripting = false keeps the default", func(t *testing.T) {
		c, err := mongodb.ParseConf("noscripting = false\n")
		require.NoError(t, err)
		assert.True(t, mongodb.Bool(c.Params, true, "security", "javascriptEnabled"))
	})
}

// The legacy TLS options land in the net.ssl tree, which the tls fields
// already read as aliases. Fails if the ssl* names stop mapping there.
func TestParseConfLegacyTLS(t *testing.T) {
	c, err := mongodb.ParseConf(`sslMode = requireSSL
sslPEMKeyFile = /etc/ssl/mongodb.pem
sslCAFile = /etc/ssl/ca.pem
sslAllowInvalidHostnames = true
sslDisabledProtocols = TLS1_0,TLS1_1
`)
	require.NoError(t, err)
	assert.Equal(t, "requireTLS", mongodb.TLSMode(c.Params))
	assert.Equal(t, "/etc/ssl/mongodb.pem", mongodb.TLSString(c.Params, "certificateKeyFile"))
	assert.Equal(t, "/etc/ssl/ca.pem", mongodb.TLSString(c.Params, "CAFile"))
	assert.True(t, mongodb.TLSBool(c.Params, false, "allowInvalidHostnames"))
	assert.Equal(t, []string{"TLS1_0", "TLS1_1"}, mongodb.TLSList(c.Params, "disabledProtocols"))

	// 2.4's switch, which 2.6 replaced with sslMode=requireSSL.
	c, err = mongodb.ParseConf("sslOnNormalPorts = true\n")
	require.NoError(t, err)
	assert.Equal(t, "requireTLS", mongodb.TLSMode(c.Params))
}

// A line that is neither a comment nor an assignment is a syntax error for
// mongod, and stays one here rather than becoming an empty config.
func TestParseConfLegacyRejectsGarbage(t *testing.T) {
	_, err := mongodb.ParseConf("dbpath=/var/lib/mongodb\nthis is not an option\n")
	assert.Error(t, err)
}

// MongoDB 3.6 made localhost the default bind address. A 2.6 server with no
// bindIp listened on *:27099 in the sweep (`ss -ltn`), a 3.6 one on
// 127.0.0.1:27099. Fails if DefaultBindIp ignores the version.
func TestDefaultBindIp(t *testing.T) {
	for _, tc := range []struct {
		version string
		ipv6    bool
		want    []string
	}{
		{"2.6.10", false, []string{"0.0.0.0"}},
		{"2.6.10", true, []string{"0.0.0.0", "::"}},
		{"3.4.24", false, []string{"0.0.0.0"}},
		{"3.6.3", false, []string{"127.0.0.1"}},
		{"3.6", false, []string{"127.0.0.1"}},
		{"7.0.43", false, []string{"127.0.0.1"}},
		{"10.0.0", false, []string{"127.0.0.1"}},
		{"", false, nil},
		{"unknown", false, nil},
		{"3", false, nil},
	} {
		assert.Equal(t, tc.want, mongodb.DefaultBindIp(tc.version, tc.ipv6), "version %q ipv6 %v", tc.version, tc.ipv6)
	}
}
