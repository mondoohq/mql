// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// snmpV3Config follows the line shapes Arista's own tooling renders for EOS
// (the eos_cli_config_gen reference configurations published in the
// aristanetworks/avd repository), with addresses and secrets replaced.
//
// Every credential position holds a placeholder: what matters for the tests
// is that the parser reads the algorithm names and never carries the token
// that follows them.
const snmpV3Config = `!
snmp-server engineID local 424242424242424242
snmp-server contact netops
snmp-server location DC1-Row4
snmp-server chassis-id core-sw-01
snmp-server local-interface Loopback0
no snmp-server vrf default
snmp-server vrf MGMT local-interface Management1
snmp-server view VW-READ iso included
snmp-server view VW-EXCLUDED iso excluded
snmp-server group GRP-READ-ONLY v3 priv read VW-READ
snmp-server group GRP-READ-WRITE v3 auth read VW-READ write VW-WRITE
snmp-server group GRP-LEGACY v2c read VW-READ
snmp-server user USER-NO-AUTH GRP-READ-ONLY v3
snmp-server user USER-AUTH-ONLY GRP-READ-ONLY v3 auth md5 PLACEHOLDER-PASSPHRASE
snmp-server user USER-AUTH-PRIV GRP-READ-WRITE v3 auth sha PLACEHOLDER-PASSPHRASE priv aes PLACEHOLDER-PASSPHRASE
snmp-server user USER-LOCALIZED GRP-READ-ONLY v3 localized 424242424242424242 auth sha PLACEHOLDERKEY priv des PLACEHOLDERKEY
snmp-server user REMOTE-USER GRP-READ-ONLY remote 192.0.2.10 udp-port 666 v3
snmp-server host 192.0.2.20 vrf MGMT version 3 auth USER-AUTH-ONLY
snmp-server host 192.0.2.21 vrf MGMT version 2c PLACEHOLDER-COMMUNITY
snmp-server host 192.0.2.22 informs version 2c PLACEHOLDER-COMMUNITY
snmp-server host collector.example version 2c PLACEHOLDER-COMMUNITY udp-port 23
snmp-server host 192.0.2.23 version 1 PLACEHOLDER-COMMUNITY
snmp-server host 192.0.2.24 PLACEHOLDER-COMMUNITY
!
`

func TestParseSnmpConfig_Users(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)

	byName := map[string]SnmpUser{}
	for _, u := range cfg.Users {
		byName[u.Name] = u
	}
	assert.Len(t, cfg.Users, 5)

	// The whole point of the resource: a device with no communities at all
	// still reports principals, and a noAuthNoPriv one is visible as such.
	noAuth := byName["USER-NO-AUTH"]
	assert.Equal(t, "GRP-READ-ONLY", noAuth.Group)
	assert.Equal(t, "v3", noAuth.Version)
	assert.Equal(t, "", noAuth.AuthAlgorithm)
	assert.Equal(t, "", noAuth.PrivAlgorithm)
	assert.Equal(t, "noAuthNoPriv", noAuth.SecurityLevel())
	assert.False(t, noAuth.Localized)

	authOnly := byName["USER-AUTH-ONLY"]
	assert.Equal(t, "md5", authOnly.AuthAlgorithm)
	assert.Equal(t, "", authOnly.PrivAlgorithm)
	assert.Equal(t, "authNoPriv", authOnly.SecurityLevel())

	authPriv := byName["USER-AUTH-PRIV"]
	assert.Equal(t, "sha", authPriv.AuthAlgorithm)
	assert.Equal(t, "aes", authPriv.PrivAlgorithm)
	assert.Equal(t, "authPriv", authPriv.SecurityLevel())

	// A localized user carries its keys in hex after the same algorithm
	// tokens, so the clause must not shift what is read as an algorithm.
	loc := byName["USER-LOCALIZED"]
	assert.True(t, loc.Localized)
	assert.Equal(t, "sha", loc.AuthAlgorithm)
	assert.Equal(t, "des", loc.PrivAlgorithm)
	assert.Equal(t, "authPriv", loc.SecurityLevel())

	// A remote agent clause sits between the group and the version.
	remote := byName["REMOTE-USER"]
	assert.Equal(t, "192.0.2.10", remote.RemoteAddress)
	assert.Equal(t, 666, remote.RemotePort)
	assert.Equal(t, "v3", remote.Version)
	assert.Equal(t, "noAuthNoPriv", remote.SecurityLevel())
}

// The parser walks past every credential position. If a passphrase ever
// reached a field, this test names which one.
func TestParseSnmpConfig_NeverKeepsUserKeyMaterial(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)
	assert.NotEmpty(t, cfg.Users)

	for _, u := range cfg.Users {
		for field, v := range map[string]string{
			"Name":          u.Name,
			"Group":         u.Group,
			"Version":       u.Version,
			"AuthAlgorithm": u.AuthAlgorithm,
			"PrivAlgorithm": u.PrivAlgorithm,
			"RemoteAddress": u.RemoteAddress,
		} {
			assert.NotContains(t, v, "PLACEHOLDER",
				"user %q leaked key material through %s", u.Name, field)
		}
	}
}

func TestParseSnmpConfig_Groups(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)
	assert.Len(t, cfg.Groups, 3)

	byName := map[string]SnmpGroup{}
	for _, g := range cfg.Groups {
		byName[g.Name] = g
	}

	ro := byName["GRP-READ-ONLY"]
	assert.Equal(t, "v3", ro.Version)
	assert.Equal(t, "priv", ro.SecurityLevel)
	assert.Equal(t, "VW-READ", ro.ReadView)
	assert.Equal(t, "", ro.WriteView)

	rw := byName["GRP-READ-WRITE"]
	assert.Equal(t, "auth", rw.SecurityLevel)
	assert.Equal(t, "VW-READ", rw.ReadView)
	assert.Equal(t, "VW-WRITE", rw.WriteView)

	// v1 and v2c groups have no security level, and the read view must not
	// be mistaken for one.
	legacy := byName["GRP-LEGACY"]
	assert.Equal(t, "v2c", legacy.Version)
	assert.Equal(t, "", legacy.SecurityLevel)
	assert.Equal(t, "VW-READ", legacy.ReadView)
}

func TestParseSnmpConfig_GroupNotifyAndContext(t *testing.T) {
	cfg := ParseSnmpConfig("snmp-server group g2 v3 priv context ctx1 write view2 notify view1\n")
	assert.Len(t, cfg.Groups, 1)
	g := cfg.Groups[0]
	assert.Equal(t, "priv", g.SecurityLevel)
	assert.Equal(t, "ctx1", g.Context)
	assert.Equal(t, "view2", g.WriteView)
	assert.Equal(t, "view1", g.NotifyView)
	assert.Equal(t, "", g.ReadView)
}

func TestParseSnmpConfig_Views(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)
	assert.Len(t, cfg.Views, 2)
	assert.Equal(t, SnmpView{Name: "VW-READ", MibFamily: "iso", Included: true}, cfg.Views[0])
	assert.Equal(t, SnmpView{Name: "VW-EXCLUDED", MibFamily: "iso", Included: false}, cfg.Views[1])
}

func TestParseSnmpConfig_ViewAcceptsBothSpellings(t *testing.T) {
	// EOS accepts `include`/`exclude` and renders `included`/`excluded`.
	cfg := ParseSnmpConfig("snmp-server view sys-view system include\nsnmp-server view sys-view system.2 exclude\n")
	assert.Len(t, cfg.Views, 2)
	assert.True(t, cfg.Views[0].Included)
	assert.False(t, cfg.Views[1].Included)
	assert.Equal(t, "system.2", cfg.Views[1].MibFamily)
}

func TestParseSnmpConfig_Hosts(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)
	assert.Len(t, cfg.Hosts, 6)

	v3 := cfg.Hosts[0]
	assert.Equal(t, "192.0.2.20", v3.Host)
	assert.Equal(t, "MGMT", v3.Vrf)
	assert.Equal(t, "v3", v3.Version)
	assert.Equal(t, "auth", v3.SecurityLevel)
	assert.Equal(t, "traps", v3.NotificationType)
	assert.Equal(t, 162, v3.Port)
	// For v3 the trailing token is a security name, not a secret.
	assert.Equal(t, "USER-AUTH-ONLY", v3.Credential)

	v2c := cfg.Hosts[1]
	assert.Equal(t, "v2c", v2c.Version)
	assert.Equal(t, "", v2c.SecurityLevel)
	assert.Equal(t, "traps", v2c.NotificationType)

	informs := cfg.Hosts[2]
	assert.Equal(t, "informs", informs.NotificationType)
	assert.Equal(t, "", informs.Vrf)
	assert.Equal(t, "v2c", informs.Version)

	withPort := cfg.Hosts[3]
	assert.Equal(t, "collector.example", withPort.Host)
	assert.Equal(t, 23, withPort.Port)

	v1 := cfg.Hosts[4]
	assert.Equal(t, "v1", v1.Version)

	// No version clause at all: EOS defaults the destination to v2c on 162,
	// and reporting the effective value is what keeps it comparable with a
	// destination written out in full.
	bare := cfg.Hosts[5]
	assert.Equal(t, "192.0.2.24", bare.Host)
	assert.Equal(t, "v2c", bare.Version)
	assert.Equal(t, 162, bare.Port)
	assert.Equal(t, "traps", bare.NotificationType)
}

func TestParseSnmpConfig_HostInformsAfterVersion(t *testing.T) {
	// Arista's manual shows the notification kind before `version`, and EOS
	// also accepts it after. Both must land on the same reading.
	before := ParseSnmpConfig("snmp-server host 192.0.2.30 informs version 2c COMM\n")
	after := ParseSnmpConfig("snmp-server host 192.0.2.30 version 2c informs COMM\n")
	assert.Equal(t, "informs", before.Hosts[0].NotificationType)
	assert.Equal(t, "informs", after.Hosts[0].NotificationType)
	assert.Equal(t, "COMM", after.Hosts[0].Credential)
}

func TestParseSnmpConfig_GlobalIdentityAndVrfs(t *testing.T) {
	cfg := ParseSnmpConfig(snmpV3Config)

	assert.Equal(t, "netops", cfg.Contact)
	assert.Equal(t, "DC1-Row4", cfg.Location)
	assert.Equal(t, "core-sw-01", cfg.ChassisID)
	assert.Equal(t, "Loopback0", cfg.LocalInterface)

	// `no snmp-server vrf default` withdraws the instance SNMP would
	// otherwise be reachable in, and MGMT is added explicitly. Getting this
	// backwards would report the data plane as an SNMP surface when it is
	// not, or hide it when it is.
	assert.Equal(t, []string{"MGMT"}, cfg.Vrfs)
	assert.Equal(t, map[string]string{"MGMT": "Management1"}, cfg.VrfLocalInterfaces)
}

func TestParseSnmpConfig_DefaultVrfIsEnabledWhenUnstated(t *testing.T) {
	// The absent case: a configuration that never mentions VRFs still has
	// SNMP reachable in the default one.
	cfg := ParseSnmpConfig("snmp-server community public ro\n")
	assert.Equal(t, []string{"default"}, cfg.Vrfs)
}

func TestParseSnmpConfig_AdditionalVrfKeepsDefault(t *testing.T) {
	cfg := ParseSnmpConfig("snmp-server vrf MGMT local-interface Management1\n")
	assert.Equal(t, []string{"default", "MGMT"}, cfg.Vrfs)
}

func TestParseSnmpConfig_Empty(t *testing.T) {
	cfg := ParseSnmpConfig("")
	assert.Empty(t, cfg.Users)
	assert.Empty(t, cfg.Groups)
	assert.Empty(t, cfg.Views)
	assert.Empty(t, cfg.Hosts)
	assert.Equal(t, "", cfg.Contact)
	assert.Equal(t, "", cfg.LocalInterface)
}

func TestParseSnmpConfig_IgnoresIndentedLines(t *testing.T) {
	// An `snmp-server` line indented under another block is not device
	// configuration and must not be collected.
	cfg := ParseSnmpConfig("event-handler x\n   action bash echo snmp-server user fake grp v3\n")
	assert.Empty(t, cfg.Users)
}

// TestParseSnmpGroupsKeepsSecurityLevelsApart pins the identity dimensions a v3
// group repeats along. One name may be defined once per security level, and
// each definition carries its own views, so a key built from name and version
// alone collapses them onto the first. The group granting write at priv would
// then disappear behind a read-only one at noauth, which under-reports a
// privilege rather than failing.
func TestParseSnmpGroupsKeepsSecurityLevelsApart(t *testing.T) {
	cfg := ParseSnmpConfig(`
snmp-server group MONITORING v3 noauth read VW-READ
snmp-server group MONITORING v3 priv read VW-READ write VW-WRITE
`)

	if len(cfg.Groups) != 2 {
		t.Fatalf("parsed %d groups, want 2: %+v", len(cfg.Groups), cfg.Groups)
	}

	levels := map[string]SnmpGroup{}
	for _, g := range cfg.Groups {
		if g.Name != "MONITORING" || g.Version != "v3" {
			t.Fatalf("unexpected group %+v", g)
		}
		levels[g.SecurityLevel] = g
	}

	if len(levels) != 2 {
		t.Fatalf("groups do not differ by security level: %+v", cfg.Groups)
	}
	if got := levels["priv"].WriteView; got != "VW-WRITE" {
		t.Errorf("priv group WriteView = %q, want VW-WRITE", got)
	}
	if got := levels["noauth"].WriteView; got != "" {
		t.Errorf("noauth group WriteView = %q, want empty", got)
	}
}
