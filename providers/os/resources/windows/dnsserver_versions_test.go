// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures behind this file are the verbatim stdout of DNS_SERVER_SETTINGS
// and DNS_SERVER_ZONES, captured over SSH from four Windows Server hosts with
// the DNS Server role installed: 2016 (build 14393), 2019 (17763), 2022 (20348)
// and 2025 (26100). Host names, the host's own addresses and the DNSSEC key
// identifiers are replaced with fixed placeholders; every configured value the
// server reported is untouched.
//
// Each host was put into the same state before capture, so the four payloads
// are comparable field by field:
//
//   - two forwarders, which is the case that decodes through the
//     {"value":[...],"Count":n} shape rather than a plain array,
//   - a debug-log address filter, a second list in that shape,
//   - one permissive unsigned zone (lab.test), which transfers to any server
//     and accepts unauthenticated dynamic updates,
//   - one DNSSEC-signed zone (signed.test) with a key signing key and a zone
//     signing key,
//   - and the three auto-created reverse zones a stock server carries.
type dnsServerRelease struct {
	name  string
	build int64
}

var dnsServerReleases = []dnsServerRelease{
	{name: "2016", build: 14393},
	{name: "2019", build: 17763},
	{name: "2022", build: 20348},
	{name: "2025", build: 26100},
}

func loadReleaseConfig(t *testing.T, release string) *WindowsDnsServerConfig {
	t.Helper()
	f, err := os.Open("testdata/dnsserver-settings-" + release + ".json")
	require.NoError(t, err)
	defer f.Close()

	res, err := ParseWindowsDnsServerConfig(f)
	require.NoError(t, err)
	return res
}

func loadReleaseZones(t *testing.T, release string) map[string]WindowsDnsServerZone {
	t.Helper()
	f, err := os.Open("testdata/dnsserver-zones-" + release + ".json")
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

// Every value asserted here was read off a live server. A property the DnsServer
// module stops reporting on a newer release comes back as JSON null and decodes
// to a Go zero value, which for most of these is the hardened reading: recursion
// off, pollution protection off, no forwarders, no listening addresses. Pinning
// the real values on each release is what separates "the server reports this" from
// "the server reported nothing and we called it false".
func TestParseWindowsDnsServerAcrossReleases(t *testing.T) {
	for _, release := range dnsServerReleases {
		t.Run(release.name, func(t *testing.T) {
			cfg := loadReleaseConfig(t, release.name)

			s := cfg.Settings
			assert.Equal(t, release.build, s.BuildNumber, "wrong capture for this release")
			assert.Equal(t, int64(10), s.MajorVersion)
			assert.True(t, s.EnableDnsSec)
			assert.True(t, s.EnableIPv6)
			assert.True(t, s.EnableOnlineSigning)
			assert.True(t, s.RoundRobin)
			assert.False(t, s.BindSecondaries)
			assert.False(t, s.StrictFileParsing)
			assert.False(t, s.DsAvailable, "a standalone server is not directory joined")
			assert.False(t, s.IsReadOnlyDC)
			assert.Equal(t, int64(2500), s.SocketPoolSize, "the source port randomization pool")
			assert.Equal(t, int64(0), s.EnableVersionQuery)
			assert.Equal(t, int64(2), s.NameCheckFlag)
			assert.Equal(t, int64(0), s.AddressAnswerLimit)
			assert.Equal(t, int64(30), s.XfrConnectTimeout)
			assert.Equal(t, "", s.ServerLevelPluginDll, "no plug-in DLL is loaded on a stock server")
			assert.Equal(t, "https://data.iana.org/root-anchors/root-anchors.xml", s.RootTrustAnchorsURL)
			assert.Empty(t, s.SocketPoolExcludedPortRanges)

			// The addresses arrive wrapped by Select-Object rather than as a
			// plain array. None of these servers was restricted to specific
			// addresses, and an unrestricted server still reports every address
			// it is bound to: the list is populated and equals AllIPAddress
			// rather than being empty.
			assert.Equal(t, PSStringArray{"fe80::73f5:a0d4:e6d3:d2a9", "10.0.0.4"}, s.ListeningIPAddress)
			assert.Equal(t, s.AllIPAddress, s.ListeningIPAddress)

			assert.True(t, cfg.Recursion.Enable)
			assert.True(t, cfg.Recursion.SecureResponse)
			assert.Equal(t, int64(8), cfg.Recursion.Timeout)
			assert.Equal(t, int64(3), cfg.Recursion.RetryInterval)
			assert.Equal(t, int64(4), cfg.Recursion.AdditionalTimeout)

			assert.True(t, cfg.Cache.EnablePollutionProtection)
			assert.True(t, cfg.Cache.StoreEmptyAuthenticationResponse)
			assert.False(t, cfg.Cache.IgnorePolicies)
			assert.Equal(t, int64(100), cfg.Cache.LockingPercent)
			assert.Equal(t, int64(0), cfg.Cache.MaxKBSize)
			require.NotNil(t, cfg.Cache.MaxTtl)
			assert.Equal(t, int64(86400), *cfg.Cache.MaxTtl.Seconds())
			require.NotNil(t, cfg.Cache.MaxNegativeTtl)
			assert.Equal(t, int64(900), *cfg.Cache.MaxNegativeTtl.Seconds())

			d := cfg.Diagnostics
			assert.Equal(t, int64(4), d.EventLogLevel)
			assert.False(t, d.UseSystemEventLog)
			assert.True(t, d.EnableLoggingToFile)
			assert.Equal(t, "", d.LogFilePath, "the default path is reported as absent")
			// MaxMBFileSize is a byte count despite its name: this is the
			// Windows default of 500 MB, written through to the LogFileMaxSize
			// registry value unchanged.
			assert.Equal(t, int64(500000000), d.MaxMBFileSize)
			assert.False(t, d.Queries)
			assert.False(t, d.Answers)
			assert.False(t, d.FullPackets)
			assert.Equal(t, PSStringArray{"192.0.2.10"}, d.FilterIPAddressList,
				"a one-element list flattens, and must not decode to empty")

			sc := cfg.Scavenging
			assert.False(t, sc.ScavengingState)
			require.NotNil(t, sc.RefreshInterval)
			assert.Equal(t, int64(604800), *sc.RefreshInterval.Seconds())
			require.NotNil(t, sc.NoRefreshInterval)
			assert.Equal(t, int64(604800), *sc.NoRefreshInterval.Seconds())
			// Never scavenged, so the timestamp stays null rather than
			// becoming the zero time.
			assert.Equal(t, PSString(""), sc.LastScavengeTime)
			assert.Nil(t, ParseDnsServerTime(sc.LastScavengeTime))

			// Response rate limiting arrived in Server 2016, so it is present
			// on every release in scope and must not be nil.
			require.NotNil(t, cfg.ResponseRateLimiting, "rate limiting is reported on this release")
			rrl := cfg.ResponseRateLimiting
			assert.Equal(t, "Disable", rrl.Mode)
			assert.Equal(t, int64(5), rrl.ResponsesPerSec)
			assert.Equal(t, int64(5), rrl.ErrorsPerSec)
			assert.Equal(t, int64(5), rrl.WindowInSec)
			assert.Equal(t, int64(24), rrl.IPv4PrefixLength)
			assert.Equal(t, int64(56), rrl.IPv6PrefixLength)
			assert.Equal(t, int64(3), rrl.LeakRate)
			assert.Equal(t, int64(2), rrl.TruncateRate)
			assert.Equal(t, int64(1024), rrl.MaximumResponsesPerWindow)

			// Two forwarders were configured. Decoding this to empty is the
			// failure that reports an open resolver as one that forwards.
			require.NotNil(t, cfg.Forwarders)
			assert.Equal(t, PSStringArray{"1.1.1.1", "9.9.9.9"}, cfg.Forwarders.IPAddress)
			assert.True(t, cfg.Forwarders.UseRootHint)
			assert.True(t, cfg.Forwarders.EnableReordering)
			assert.Equal(t, int64(3), cfg.Forwarders.Timeout)

			require.Len(t, cfg.RootHints, 13)
			assert.Equal(t, "A.ROOT-SERVERS.NET.", cfg.RootHints[0].NameServer)
			assert.Equal(t, PSStringArray{"198.41.0.4", "2001:503:ba3e::2:30"}, cfg.RootHints[0].IPAddress)
			// E.ROOT-SERVERS.NET carries only a v4 glue record, which is the
			// branch that falls back from IPv4Address to IPv6Address.
			assert.Equal(t, PSStringArray{"192.203.230.10"}, cfg.RootHints[4].IPAddress)
		})
	}
}

func TestParseWindowsDnsServerZonesAcrossReleases(t *testing.T) {
	for _, release := range dnsServerReleases {
		t.Run(release.name, func(t *testing.T) {
			zones := loadReleaseZones(t, release.name)
			require.Len(t, zones, 5)

			// An auto-created reverse zone reports no zone file at all, which
			// is a separate case from a directory-integrated zone reporting
			// none.
			reverse := zones["127.in-addr.arpa"]
			assert.True(t, reverse.IsAutoCreated)
			assert.True(t, reverse.IsReverseLookupZone)
			assert.Equal(t, "", reverse.ZoneFile)
			assert.Equal(t, "None", reverse.ReplicationScope)

			// The permissive zone: hands the full zone to anyone who asks, and
			// takes record changes from anyone who sends them.
			lab := zones["lab.test"]
			assert.Equal(t, "Primary", lab.ZoneType)
			assert.Equal(t, "TransferAnyServer", lab.SecureSecondaries)
			assert.Equal(t, "NonsecureAndSecure", lab.DynamicUpdate)
			assert.Equal(t, "NoNotify", lab.Notify)
			assert.False(t, lab.IsSigned)
			assert.False(t, lab.IsDsIntegrated)
			assert.False(t, lab.IsAutoCreated)
			assert.False(t, lab.IsWinsEnabled)
			assert.Equal(t, "lab.test.dns", lab.ZoneFile)
			assert.Empty(t, lab.SecondaryServers)
			// An unsigned zone carries no DNSSEC settings and no keys.
			assert.Nil(t, lab.Dnssec)
			assert.Empty(t, lab.SigningKeys)

			signed := zones["signed.test"]
			assert.True(t, signed.IsSigned)
			assert.Equal(t, "None", signed.DynamicUpdate)
			assert.Equal(t, "TransferToZoneNameServer", signed.SecureSecondaries)

			require.NotNil(t, signed.Dnssec, "a signed zone's settings must be attached to it")
			ds := signed.Dnssec
			assert.Equal(t, "NSec3", ds.DenialOfExistence)
			assert.Equal(t, int64(50), ds.NSec3Iterations)
			assert.Equal(t, int64(8), ds.NSec3RandomSaltLength)
			assert.False(t, ds.NSec3OptOut)
			assert.True(t, ds.EnableRfc5011KeyRollover)
			assert.False(t, ds.ParentHasSecureDelegation)
			assert.True(t, ds.IsKeyMasterServer)
			assert.Equal(t, PSStringArray{"Sha1", "Sha256"}, ds.DSRecordGenerationAlgorithm)
			assert.Equal(t, PSStringArray{"None"}, ds.DistributeTrustAnchor)
			require.NotNil(t, ds.SignatureInceptionOffset)
			assert.Equal(t, int64(3600), *ds.SignatureInceptionOffset.Seconds())
			require.NotNil(t, ds.SecureDelegationPollingPeriod)
			assert.Equal(t, int64(43200), *ds.SecureDelegationPollingPeriod.Seconds())
			require.NotNil(t, ds.DSRecordSetTtl)
			assert.Equal(t, int64(3600), *ds.DSRecordSetTtl.Seconds())
			require.NotNil(t, ds.DnsKeyRecordSetTtl)
			assert.Equal(t, int64(3600), *ds.DnsKeyRecordSetTtl.Seconds())
			// PropagationTime is genuinely zero on a single-server zone, which
			// is a reported value and not an absent one.
			require.NotNil(t, ds.PropagationTime)
			assert.Equal(t, int64(0), *ds.PropagationTime.Seconds())

			byType := map[string]WindowsDnsServerSigningKey{}
			for _, k := range signed.SigningKeys {
				byType[k.KeyType] = k
			}
			require.Len(t, signed.SigningKeys, 2)
			require.Contains(t, byType, "KeySigningKey")
			require.Contains(t, byType, "ZoneSigningKey")

			ksk := byType["KeySigningKey"]
			assert.Equal(t, "signed.test", ksk.ZoneName, "a key without its zone name joins to no zone")
			assert.Equal(t, "RsaSha256", ksk.CryptoAlgorithm)
			assert.Equal(t, int64(2048), ksk.KeyLength)
			assert.Equal(t, "Active", ksk.CurrentState)
			assert.Equal(t, "Microsoft Software Key Storage Provider", ksk.KeyStorageProvider)
			assert.False(t, ksk.StoreKeysInAD)
			assert.True(t, ksk.IsRolloverEnabled)
			require.NotNil(t, ksk.RolloverPeriod)
			assert.Equal(t, int64(65232000), *ksk.RolloverPeriod.Seconds())
			require.NotNil(t, ksk.DnsKeySignatureValidityPeriod)
			assert.Equal(t, int64(604800), *ksk.DnsKeySignatureValidityPeriod.Seconds())
			require.NotNil(t, ksk.ZoneSignatureValidityPeriod)
			assert.Equal(t, int64(864000), *ksk.ZoneSignatureValidityPeriod.Seconds())

			zsk := byType["ZoneSigningKey"]
			assert.Equal(t, int64(1024), zsk.KeyLength)
			require.NotNil(t, zsk.RolloverPeriod)
			assert.Equal(t, int64(7776000), *zsk.RolloverPeriod.Seconds())
			assert.NotEqual(t, ksk.KeyId, zsk.KeyId, "the two keys of one zone must be distinguishable")
		})
	}
}

// The four hosts were configured identically, so any difference between the
// decoded payloads is the DnsServer module reporting something differently on
// one release rather than the servers disagreeing. Nothing in the modeled set
// differs today, build number aside. A future release that renames, retypes or
// drops one of these properties fails here, where the cause is legible, instead
// of surfacing as a field that quietly reads false on that release alone.
func TestWindowsDnsServerDoesNotDriftAcrossReleases(t *testing.T) {
	base := dnsServerReleases[0]

	normalize := func(cfg *WindowsDnsServerConfig) string {
		t.Helper()
		// The build number is the one value that is meant to differ.
		cfg.Settings.BuildNumber = 0
		out, err := json.Marshal(cfg)
		require.NoError(t, err)
		return string(out)
	}

	want := normalize(loadReleaseConfig(t, base.name))
	for _, release := range dnsServerReleases[1:] {
		t.Run(release.name, func(t *testing.T) {
			assert.Equal(t, want, normalize(loadReleaseConfig(t, release.name)),
				"the server configuration decodes differently on %s than on %s", release.name, base.name)
		})
	}
}
