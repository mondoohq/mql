// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture is `jls -n --libxo json` on a FreeBSD 14.3 host with six jails:
// empty (ip4 and ip6 disabled), vnetjail (vnet), empty.child (created inside
// empty), web (one IPv4 address, raw sockets, securelevel 2, enforce_statfs 1,
// devfs ruleset 4), db (ip4 inherit, sysvipc and zfs mounts allowed,
// enforce_statfs 0, osrelease 13.5-RELEASE), and v6 (two IPv4 and one IPv6
// address).
func parseJlsFixture(t *testing.T) map[string]jailRecord {
	f, err := os.Open("testdata/freebsd14-jls.json")
	require.NoError(t, err)
	defer f.Close()

	records, err := parseJls(f)
	require.NoError(t, err)

	byName := map[string]jailRecord{}
	for _, r := range records {
		byName[r.name] = r
	}
	require.Len(t, byName, 6)
	return byName
}

func TestParseJlsRestrictedJail(t *testing.T) {
	web := parseJlsFixture(t)["web"]

	assert.Equal(t, int64(4), web.jid)
	assert.Equal(t, "web.example.internal", web.hostname)
	assert.Equal(t, "/", web.path)
	assert.Equal(t, "14.3-RELEASE-p16", web.osRelease)
	require.NotNil(t, web.securelevel)
	assert.Equal(t, int64(2), *web.securelevel)
	require.NotNil(t, web.enforceStatfs)
	assert.Equal(t, int64(1), *web.enforceStatfs)
	require.NotNil(t, web.devfsRuleset)
	assert.Equal(t, int64(4), *web.devfsRuleset)
	assert.True(t, web.persist)
	assert.Equal(t, int64(0), web.parentJid)

	// the kernel reports ip4=disable for a jail with its own addresses
	assert.Equal(t, "disable", web.parameters["ip4"])
	assert.Equal(t, "new", web.ip4)
	assert.Equal(t, []string{"127.0.1.1"}, web.ip4Addresses)
	assert.Equal(t, "disable", web.ip6)
	assert.Empty(t, web.ip6Addresses)

	assert.Equal(t, []string{"raw_sockets", "reserved_ports", "set_hostname", "suser", "unprivileged_proc_debug"}, web.allow)
	assert.Equal(t, "true", web.parameters["allow.raw_sockets"])
	assert.Equal(t, "false", web.parameters["allow.mount"])
	assert.Equal(t, "127.0.1.1", web.parameters["ip4.addr"])
}

func TestParseJlsPermissiveJail(t *testing.T) {
	db := parseJlsFixture(t)["db"]

	assert.Equal(t, "/jails", db.path)
	assert.Equal(t, "13.5-RELEASE", db.osRelease)
	require.NotNil(t, db.enforceStatfs)
	assert.Equal(t, int64(0), *db.enforceStatfs)
	require.NotNil(t, db.childrenMax)
	assert.Equal(t, int64(2), *db.childrenMax)
	require.NotNil(t, db.securelevel)
	assert.Equal(t, int64(-1), *db.securelevel)
	assert.Equal(t, "inherit", db.ip4)
	assert.Empty(t, db.ip4Addresses)
	assert.Contains(t, db.allow, "mount")
	assert.Contains(t, db.allow, "mount.zfs")
	assert.Contains(t, db.allow, "sysvipc")
	assert.NotContains(t, db.allow, "raw_sockets")
}

func TestParseJlsNetworking(t *testing.T) {
	jails := parseJlsFixture(t)

	require.NotNil(t, jails["vnetjail"].vnet)
	assert.True(t, *jails["vnetjail"].vnet)
	require.NotNil(t, jails["empty"].vnet)
	assert.False(t, *jails["empty"].vnet)

	v6 := jails["v6"]
	assert.Equal(t, "new", v6.ip4)
	assert.Equal(t, []string{"10.9.9.9", "10.9.9.10"}, v6.ip4Addresses)
	assert.Equal(t, "new", v6.ip6)
	assert.Equal(t, []string{"fd00::9"}, v6.ip6Addresses)
	assert.Equal(t, "10.9.9.9,10.9.9.10", v6.parameters["ip4.addr"])
}

func TestParseJlsChildJail(t *testing.T) {
	jails := parseJlsFixture(t)
	assert.Equal(t, int64(1), jails["empty.child"].parentJid)
	assert.Equal(t, int64(1), jails["empty"].jid)
}

func TestParseJlsAbsentValues(t *testing.T) {
	// a kernel without VIMAGE has no vnet parameter, and an unparseable
	// number reads as absent rather than 0
	records, err := parseJls(strings.NewReader(`{"__version": "2", "jail-information": {"jail": [
		{"jid":"7","name":"a","securelevel":"x","ip4":"inherit", "ip4.addr": []},
		{"name":"nojid"},
		{"jid":"8"}
	]}}`))
	require.NoError(t, err)
	require.Len(t, records, 1)

	a := records[0]
	assert.Nil(t, a.vnet)
	assert.Nil(t, a.securelevel)
	assert.Nil(t, a.enforceStatfs)
	assert.False(t, a.persist)
	assert.Equal(t, "inherit", a.ip4)
	assert.Equal(t, "", a.ip6)
	assert.Empty(t, a.allow)
	assert.NotNil(t, a.allow)
}

func TestParseJlsNoJails(t *testing.T) {
	records, err := parseJls(strings.NewReader(`{"__version": "2", "jail-information": {"jail": []}}`))
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestParseJlsMalformed(t *testing.T) {
	_, err := parseJls(strings.NewReader(`jls: unknown parameter`))
	assert.Error(t, err)
}
