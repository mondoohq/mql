// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The fixtures are the verbatim output of DNS_SERVER_SETTINGS and
// DNS_SERVER_ZONES captured from a Windows Server 2022 host with the DNS
// Server role installed, one DNSSEC-signed zone and one unsigned zone that
// allows unrestricted transfers and unauthenticated dynamic updates.
func loadDnsServerConfig(t *testing.T) *WindowsDnsServerConfig {
	t.Helper()
	f, err := os.Open("testdata/dnsserver-settings.json")
	require.NoError(t, err)
	defer f.Close()

	res, err := ParseWindowsDnsServerConfig(f)
	require.NoError(t, err)
	return res
}

func loadDnsServerZones(t *testing.T) map[string]WindowsDnsServerZone {
	t.Helper()
	f, err := os.Open("testdata/dnsserver-zones.json")
	require.NoError(t, err)
	defer f.Close()

	zones, err := ParseWindowsDnsServerZones(f)
	require.NoError(t, err)

	byName := make(map[string]WindowsDnsServerZone, len(zones))
	for _, z := range zones {
		byName[z.ZoneName] = z
	}
	return byName
}

// A script that no longer fits on the command line fails on the target with
// "The command line is too long", which reads like the DNS Server role is
// missing rather than like a bug. Catch it here instead.
func TestDnsServerScriptsFitCommandLine(t *testing.T) {
	scripts := map[string]string{
		"DNS_SERVER_SETTINGS": DNS_SERVER_SETTINGS,
		"DNS_SERVER_ZONES":    DNS_SERVER_ZONES,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			assert.LessOrEqual(t, len(script), PSMaxScriptLength,
				"script is too long to be encoded onto a Windows command line; split it rather than raising the cap")
			// The real constraint is the encoded length, so assert that too.
			assert.Less(t, len(powershell.Encode(script)), 8191)
		})
	}
}

func TestParseWindowsDnsServerSettings(t *testing.T) {
	s := loadDnsServerConfig(t).Settings

	assert.Equal(t, "dnslab", s.ComputerName)
	assert.Equal(t, int64(10), s.MajorVersion)
	assert.Equal(t, int64(20348), s.BuildNumber)
	assert.True(t, s.EnableDnsSec)

	// These two arrive as numbers rather than labels. A struct tag typo would
	// decode either to 0 and report the hardened value on a server that
	// discloses its build.
	assert.Equal(t, int64(0), s.EnableVersionQuery)
	assert.Equal(t, int64(2), s.NameCheckFlag)

	assert.Equal(t, int64(2500), s.SocketPoolSize)
	assert.Empty(t, s.SocketPoolExcludedPortRanges)
	// ListeningIPAddress arrives in the {"value":[...],"Count":n} shape, not as
	// a plain array. Decoding it to empty would report a server with no
	// listening addresses at all.
	assert.Equal(t, PSStringArray{"fe80::73f5:a0d4:e6d3:d2a9", "10.0.0.4"}, s.ListeningIPAddress)
	assert.Equal(t, "", s.ServerLevelPluginDll)
	assert.Equal(t, "https://data.iana.org/root-anchors/root-anchors.xml", s.RootTrustAnchorsURL)
}

func TestParseWindowsDnsServerRecursionCacheAndDiagnostics(t *testing.T) {
	cfg := loadDnsServerConfig(t)

	assert.True(t, cfg.Recursion.Enable)
	assert.True(t, cfg.Recursion.SecureResponse)
	assert.Equal(t, int64(8), cfg.Recursion.Timeout)

	assert.True(t, cfg.Cache.EnablePollutionProtection)
	assert.Equal(t, int64(100), cfg.Cache.LockingPercent)
	// TimeSpans arrive as objects, so the seconds have to be read out of them.
	require.NotNil(t, cfg.Cache.MaxTtl)
	assert.Equal(t, int64(86400), *cfg.Cache.MaxTtl.Seconds())
	require.NotNil(t, cfg.Cache.MaxNegativeTtl)
	assert.Equal(t, int64(900), *cfg.Cache.MaxNegativeTtl.Seconds())

	assert.Equal(t, int64(4), cfg.Diagnostics.EventLogLevel)
	assert.False(t, cfg.Diagnostics.UseSystemEventLog)
	assert.False(t, cfg.Diagnostics.Queries)
	assert.Empty(t, cfg.Diagnostics.FilterIPAddressList)
}

func TestParseWindowsDnsServerForwardersRootHintsAndRrl(t *testing.T) {
	cfg := loadDnsServerConfig(t)

	// No forwarders configured, but the configuration object still exists and
	// says the server falls back to the root hints. An empty forwarder list is
	// a real state, not a collection failure.
	require.NotNil(t, cfg.Forwarders)
	assert.Empty(t, cfg.Forwarders.IPAddress)
	assert.True(t, cfg.Forwarders.UseRootHint)

	require.Len(t, cfg.RootHints, 13)
	assert.Equal(t, "A.ROOT-SERVERS.NET.", cfg.RootHints[0].NameServer)
	assert.Equal(t, PSStringArray{"198.41.0.4", "2001:503:ba3e::2:30"}, cfg.RootHints[0].IPAddress)
	// E.ROOT-SERVERS.NET carries only a v4 glue record here, which exercises
	// the branch that falls back from IPv4Address to IPv6Address.
	assert.Equal(t, PSStringArray{"192.203.230.10"}, cfg.RootHints[4].IPAddress)

	require.NotNil(t, cfg.ResponseRateLimiting)
	assert.Equal(t, "Disable", cfg.ResponseRateLimiting.Mode)
	assert.Equal(t, int64(5), cfg.ResponseRateLimiting.ResponsesPerSec)
	assert.Equal(t, int64(1024), cfg.ResponseRateLimiting.MaximumResponsesPerWindow)
}

func TestParseWindowsDnsServerScavenging(t *testing.T) {
	s := loadDnsServerConfig(t).Scavenging

	assert.False(t, s.ScavengingState)
	require.NotNil(t, s.RefreshInterval)
	assert.Equal(t, int64(604800), *s.RefreshInterval.Seconds())
	// The server has never scavenged, so the timestamp is absent and must stay
	// null rather than becoming the zero time.
	assert.Equal(t, PSString(""), s.LastScavengeTime)
	assert.Nil(t, ParseDnsServerTime(s.LastScavengeTime))
}

func TestParseWindowsDnsServerZones(t *testing.T) {
	zones := loadDnsServerZones(t)
	require.Contains(t, zones, "lab.local")
	require.Contains(t, zones, "signed.local")

	// The permissive zone: transfers to anyone, unauthenticated dynamic
	// updates, unsigned.
	lab := zones["lab.local"]
	assert.Equal(t, "Primary", lab.ZoneType)
	assert.Equal(t, "TransferAnyServer", lab.SecureSecondaries)
	assert.Equal(t, "NonsecureAndSecure", lab.DynamicUpdate)
	assert.Equal(t, "NoNotify", lab.Notify)
	assert.False(t, lab.IsSigned)
	assert.False(t, lab.IsDsIntegrated)
	assert.Equal(t, "lab.local.dns", lab.ZoneFile)
	// An unsigned zone has no DNSSEC settings and no keys.
	assert.Nil(t, lab.Dnssec)
	assert.Empty(t, lab.SigningKeys)

	signed := zones["signed.local"]
	assert.Equal(t, "TransferToZoneNameServer", signed.SecureSecondaries)
	assert.Equal(t, "None", signed.DynamicUpdate)
	assert.True(t, signed.IsSigned)
	assert.False(t, signed.IsWinsEnabled)

	require.NotNil(t, signed.Dnssec)
	assert.Equal(t, "NSec3", signed.Dnssec.DenialOfExistence)
	assert.Equal(t, int64(50), signed.Dnssec.NSec3Iterations)
	assert.Equal(t, int64(8), signed.Dnssec.NSec3RandomSaltLength)
	assert.True(t, signed.Dnssec.EnableRfc5011KeyRollover)
	assert.False(t, signed.Dnssec.ParentHasSecureDelegation)
	assert.Equal(t, PSStringArray{"Sha1", "Sha256"}, signed.Dnssec.DSRecordGenerationAlgorithm)
	require.NotNil(t, signed.Dnssec.SignatureInceptionOffset)
	assert.Equal(t, int64(3600), *signed.Dnssec.SignatureInceptionOffset.Seconds())
}

func TestParseWindowsDnsServerSigningKeys(t *testing.T) {
	signed := loadDnsServerZones(t)["signed.local"]
	require.Len(t, signed.SigningKeys, 2)

	byType := map[string]WindowsDnsServerSigningKey{}
	for _, k := range signed.SigningKeys {
		byType[k.KeyType] = k
	}
	require.Contains(t, byType, "KeySigningKey")
	require.Contains(t, byType, "ZoneSigningKey")

	ksk := byType["KeySigningKey"]
	assert.Equal(t, "RsaSha256", ksk.CryptoAlgorithm)
	assert.Equal(t, int64(2048), ksk.KeyLength)
	assert.Equal(t, "Active", ksk.CurrentState)
	assert.True(t, ksk.IsRolloverEnabled)
	assert.False(t, ksk.StoreKeysInAD)
	// Validity periods are what a policy asserts a range on, so pin them.
	require.NotNil(t, ksk.DnsKeySignatureValidityPeriod)
	assert.Equal(t, int64(604800), *ksk.DnsKeySignatureValidityPeriod.Seconds())
	require.NotNil(t, ksk.ZoneSignatureValidityPeriod)
	assert.Equal(t, int64(864000), *ksk.ZoneSignatureValidityPeriod.Seconds())

	zsk := byType["ZoneSigningKey"]
	assert.Equal(t, int64(1024), zsk.KeyLength)
	assert.NotEqual(t, ksk.KeyId, zsk.KeyId)
}

// The zone list and the DNSSEC lists are collected separately and joined here,
// so the join is where a zone can end up carrying another zone's settings.
func TestJoinDnsServerZones(t *testing.T) {
	zones := []WindowsDnsServerZone{
		{ZoneName: "a.example", IsSigned: true},
		{ZoneName: "b.example", IsSigned: true},
		{ZoneName: "c.example"},
	}
	dnssec := []WindowsDnsServerZoneDnssec{
		{ZoneName: "b.example", DenialOfExistence: "NSec3"},
		// a.example is signed but its DNSSEC lookup failed, so it is absent.
	}
	keys := []WindowsDnsServerSigningKey{
		{ZoneName: "b.example", KeyType: "KeySigningKey", KeyId: "k1"},
		{ZoneName: "b.example", KeyType: "ZoneSigningKey", KeyId: "k2"},
		{ZoneName: "a.example", KeyType: "KeySigningKey", KeyId: "k3"},
	}

	got := JoinDnsServerZones(zones, dnssec, keys)
	require.Len(t, got, 3)

	byName := map[string]WindowsDnsServerZone{}
	for _, z := range got {
		byName[z.ZoneName] = z
	}

	// b.example gets its own settings and exactly its own two keys.
	require.NotNil(t, byName["b.example"].Dnssec)
	assert.Equal(t, "NSec3", byName["b.example"].Dnssec.DenialOfExistence)
	require.Len(t, byName["b.example"].SigningKeys, 2)

	// a.example is signed but has no readable settings. It must stay nil
	// rather than borrowing b.example's, and it keeps its own single key.
	assert.Nil(t, byName["a.example"].Dnssec)
	require.Len(t, byName["a.example"].SigningKeys, 1)
	assert.Equal(t, "k3", byName["a.example"].SigningKeys[0].KeyId)

	// The unsigned zone gets nothing.
	assert.Nil(t, byName["c.example"].Dnssec)
	assert.Empty(t, byName["c.example"].SigningKeys)
}

func TestDnsServerSigningKeyID(t *testing.T) {
	a := DnsServerSigningKeyID("signed.local", "997a9272-fb82-4f40-9675-c4e9012d5b7b")
	b := DnsServerSigningKeyID("signed.local", "3c1550ba-7963-48fe-b2a6-e891b00d2a38")
	c := DnsServerSigningKeyID("other.local", "997a9272-fb82-4f40-9675-c4e9012d5b7b")

	assert.NotEqual(t, a, b, "two keys in one zone must not collide")
	assert.NotEqual(t, a, c, "the same key id in two zones must not collide")
	assert.Contains(t, a, "signed.local")
}

// PowerShell serializes the same logical list in more than one shape within a
// single payload, so the decoder has to accept all of them.
func TestPSStringArrayUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  PSStringArray
	}{
		{name: "plain array", input: `["a","b"]`, want: PSStringArray{"a", "b"}},
		{name: "empty array", input: `[]`, want: PSStringArray{}},
		{name: "wrapped by Select-Object", input: `{"value":["a","b"],"Count":2}`, want: PSStringArray{"a", "b"}},
		{name: "wrapped and empty", input: `{"value":[],"Count":0}`, want: PSStringArray{}},
		{name: "null", input: `null`, want: nil},
		{name: "flattened single element", input: `"only"`, want: PSStringArray{"only"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got PSStringArray
			require.NoError(t, got.UnmarshalJSON([]byte(tc.input)))
			assert.Equal(t, tc.want, got)
		})
	}
}

// A calculated property whose expression produced nothing serializes as an
// empty object, which must read as an absent string rather than failing the
// decode of everything around it.
func TestPSStringUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  PSString
	}{
		{name: "string", input: `"2026-08-18T09:15:04Z"`, want: "2026-08-18T09:15:04Z"},
		{name: "empty string", input: `""`, want: ""},
		{name: "null", input: `null`, want: ""},
		{name: "empty object from an unset calculated property", input: `{}`, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got PSString
			require.NoError(t, got.UnmarshalJSON([]byte(tc.input)))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPSTimeSpanSeconds(t *testing.T) {
	var absent *PSTimeSpan
	assert.Nil(t, absent.Seconds(), "an absent duration stays null rather than becoming zero")

	zero := &PSTimeSpan{TotalSeconds: 0}
	require.NotNil(t, zero.Seconds())
	assert.Equal(t, int64(0), *zero.Seconds(), "an explicit zero is a real value")

	week := &PSTimeSpan{TotalSeconds: 604800}
	assert.Equal(t, int64(604800), *week.Seconds())

	// TotalSeconds is a float and can carry a fraction; truncate rather than
	// rounding up into a longer period than the server reports.
	frac := &PSTimeSpan{TotalSeconds: 3599.9}
	assert.Equal(t, int64(3599), *frac.Seconds())
}

func TestParseDnsServerTime(t *testing.T) {
	tests := []struct {
		name    string
		input   PSString
		wantNil bool
		want    string
	}{
		{name: "never happened", input: "", wantNil: true},
		{name: "unparseable", input: "not a timestamp", wantNil: true},
		{name: "rfc3339 with fraction", input: "2026-08-18T09:15:04.1234567Z", want: "2026-08-18T09:15:04Z"},
		{name: "rfc3339 with offset", input: "2026-08-18T11:15:04+02:00", want: "2026-08-18T09:15:04Z"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseDnsServerTime(tc.input)
			if tc.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.UTC().Format("2006-01-02T15:04:05Z"))
		})
	}
}

// A host where an optional cmdlet is missing returns those sections as null,
// which must decode to a nil pointer rather than a zero-valued struct that
// reports rate limiting as disabled when it was never read.
func TestParseWindowsDnsServerAbsentOptionalSections(t *testing.T) {
	res, err := ParseWindowsDnsServerConfig(strings.NewReader(`{
		"Settings":{"ComputerName":"ns1"},
		"Recursion":{"Enable":false},
		"Cache":{},
		"Diagnostics":{},
		"Scavenging":{},
		"ResponseRateLimiting":null,
		"Forwarders":null,
		"RootHints":[]
	}`))
	require.NoError(t, err)

	assert.Nil(t, res.ResponseRateLimiting)
	assert.Nil(t, res.Forwarders)
	assert.Empty(t, res.RootHints)
	assert.Equal(t, "ns1", res.Settings.ComputerName)
	// An absent TimeSpan is null, not zero.
	assert.Nil(t, res.Cache.MaxTtl.Seconds())
}

// A server with the role installed but no zones at all is a real state, and
// the one that catches a missing length guard in a policy.
func TestParseWindowsDnsServerNoZones(t *testing.T) {
	zones, err := ParseWindowsDnsServerZones(strings.NewReader(`{"Zones":[],"DnsSec":[],"SigningKeys":[]}`))
	require.NoError(t, err)
	assert.Empty(t, zones)
}
