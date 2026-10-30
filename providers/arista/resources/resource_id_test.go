// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func idBool(v bool) plugin.TValue[bool] {
	return plugin.TValue[bool]{Data: v, State: plugin.StateIsSet}
}

func idInt(v int64) plugin.TValue[int64] {
	return plugin.TValue[int64]{Data: v, State: plugin.StateIsSet}
}

// distinct asserts that two records the device really can carry at once do not
// share a cache key. A shared key is silent: CreateResource returns the first
// instance for the second record, so the list has the right length and every
// row reads plausibly, while one record's values have been replaced by the
// other's.
func distinct(t *testing.T, what string, a, b func() (string, error)) {
	t.Helper()
	x, err := a()
	if err != nil {
		t.Fatalf("%s: first id: %v", what, err)
	}
	y, err := b()
	if err != nil {
		t.Fatalf("%s: second id: %v", what, err)
	}
	if x == y {
		t.Fatalf("%s: both records share the cache key %q, so one is dropped", what, x)
	}
}

// TestSnmpCommunityIDSeparatesAddressFamilies covers the dual-stack form:
// one community declared twice to bind an IPv4 access-list and an IPv6 one.
func TestSnmpCommunityIDSeparatesAddressFamilies(t *testing.T) {
	v4 := &mqlAristaEosSnmpCommunity{Name: str("ops"), Acl: str("IPV4-MGMT"), Ipv6: idBool(false)}
	v6 := &mqlAristaEosSnmpCommunity{Name: str("ops"), Acl: str("IPV6-MGMT"), Ipv6: idBool(true)}
	distinct(t, "snmpCommunity", v4.id, v6.id)

	again := &mqlAristaEosSnmpCommunity{Name: str("ops"), Acl: str("IPV4-MGMT"), Ipv6: idBool(false)}
	x, _ := v4.id()
	y, _ := again.id()
	if x != y {
		t.Fatalf("the same community produced two keys: %q and %q", x, y)
	}
}

// TestSnmpHostIDSeparatesSecurityLevels covers a v3 trap destination declared
// at two security levels to the same collector. The noauth one is the finding.
func TestSnmpHostIDSeparatesSecurityLevels(t *testing.T) {
	priv := &mqlAristaEosSnmpHost{
		Host: str("192.0.2.20"), Vrf: str(""), Version: str("v3"),
		NotificationType: str("traps"), Port: idInt(162), SecurityLevel: str("priv"),
	}
	noauth := &mqlAristaEosSnmpHost{
		Host: str("192.0.2.20"), Vrf: str(""), Version: str("v3"),
		NotificationType: str("traps"), Port: idInt(162), SecurityLevel: str("noauth"),
	}
	distinct(t, "snmpHost", priv.id, noauth.id)
}

// TestLoggingHostIDSeparatesTransports covers one collector reached over both
// TCP and plaintext UDP on the same port.
func TestLoggingHostIDSeparatesTransports(t *testing.T) {
	tcp := &mqlAristaEosLoggingHost{
		Host: str("10.0.0.2"), Vrf: str(""), Port: idInt(514), Protocol: str("tcp"),
	}
	udp := &mqlAristaEosLoggingHost{
		Host: str("10.0.0.2"), Vrf: str(""), Port: idInt(514), Protocol: str("udp"),
	}
	distinct(t, "loggingHost", tcp.id, udp.id)
}

// TestRadiusServerIDSeparatesAccountingPorts covers one RADIUS host defined
// twice with a shared authentication port and different accounting ports.
func TestRadiusServerIDSeparatesAccountingPorts(t *testing.T) {
	a := &mqlAristaEosAaaRadiusServer{
		Host: str("10.1.1.1"), Vrf: str(""), AuthPort: idInt(1812), AcctPort: idInt(1813),
	}
	b := &mqlAristaEosAaaRadiusServer{
		Host: str("10.1.1.1"), Vrf: str(""), AuthPort: idInt(1812), AcctPort: idInt(1646),
	}
	distinct(t, "radiusServer", a.id, b.id)
}
