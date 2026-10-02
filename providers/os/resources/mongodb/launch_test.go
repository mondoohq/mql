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
