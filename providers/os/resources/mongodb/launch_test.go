// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigFromArgs(t *testing.T) {
	// MongoDB's rpm unit with OPTIONS="-f /etc/mongod-alt.conf" from
	// /etc/sysconfig/mongod (SLES 15, /proc/<pid>/cmdline)
	assert.Equal(t, "/etc/mongod-alt.conf", ConfigFromArgs([]string{"-f", "/etc/mongod-alt.conf"}))
	// MongoDB's deb unit
	assert.Equal(t, "/etc/mongod.conf", ConfigFromArgs([]string{"--config", "/etc/mongod.conf"}))
	assert.Equal(t, "/etc/mongod.conf", ConfigFromArgs([]string{"--config=/etc/mongod.conf"}))
	assert.Equal(t, "/etc/mongod.conf", ConfigFromArgs([]string{"--fork", "-f/etc/mongod.conf"}))
	// systemd starts a service in / unless WorkingDirectory= says otherwise
	assert.Equal(t, "/etc/mongod.conf", ConfigFromArgs([]string{"-f", "etc/mongod.conf"}))

	// no file: mongod runs on its built-in defaults and command line options
	assert.Equal(t, "", ConfigFromArgs([]string{"--dbpath", "/data/db", "--fork"}))
	assert.Equal(t, "", ConfigFromArgs(nil))
	// a dangling -f, and an unset ${CONF} expanded to an empty argument
	assert.Equal(t, "", ConfigFromArgs([]string{"-f"}))
	assert.Equal(t, "", ConfigFromArgs([]string{"--config", ""}))
}

// RHEL 9, /etc/sysconfig/mongod with
// OPTIONS="-f /etc/mongod.conf --bind_ip_all --port 27018": the server listens
// on 0.0.0.0:27018 whatever the file says.
func TestArgOverrides(t *testing.T) {
	argv := []string{"-f", "/etc/mongod.conf", "--bind_ip_all", "--port", "27018", "--noauth",
		"--setParameter", "enableLocalhostAuthBypass=true", "--tlsMode=disabled", "--bind_ip", "0.0.0.0,::", "--unknown", "x"}
	params := map[string]any{
		"net":      map[string]any{"bindIp": "127.0.0.1,127.0.0.2", "port": int64(27017)},
		"security": map[string]any{"authorization": "enabled", "keyFile": "/etc/mongo.key"},
	}
	got := ApplyArgOverrides(params, ArgOverrides(argv))

	assert.Equal(t, true, Bool(got, false, "net", "bindIpAll"))
	assert.Equal(t, int64(27018), Int(got, 0, "net", "port"))
	assert.Equal(t, []string{"0.0.0.0", "::"}, List(got, "net", "bindIp"))
	assert.Equal(t, "disabled", String(got, "security", "authorization"))
	assert.Equal(t, "/etc/mongo.key", String(got, "security", "keyFile"), "settings the command line does not give stay")
	assert.Equal(t, "disabled", String(got, "net", "tls", "mode"))
	assert.Equal(t, true, Bool(got, false, "setParameter", "enableLocalhostAuthBypass"))
	assert.NotContains(t, got, "unknown")
}

func TestArgOverridesConfigOnly(t *testing.T) {
	assert.Empty(t, ArgOverrides([]string{"--config", "/etc/mongod.conf"}))
	assert.Empty(t, ArgOverrides([]string{"--port"}), "a value missing at the end is skipped")
}
