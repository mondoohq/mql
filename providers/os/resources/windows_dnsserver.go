// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
)

// mqlWindowsDnsServerInternal caches the two collection calls behind every
// field. Without it a policy that reads the settings, the recursion state and
// the cache would pay three PowerShell processes on the remote host instead of
// sharing one, and the zone accessors would re-run the per-zone DNSSEC lookups
// for every field read.
type mqlWindowsDnsServerInternal struct {
	configLock    sync.Mutex
	configFetched bool
	configData    *windows.WindowsDnsServerConfig

	zonesLock    sync.Mutex
	zonesFetched bool
	zonesData    []windows.WindowsDnsServerZone
}

func (w *mqlWindowsDnsServer) id() (string, error) {
	return "windows.dnsServer", nil
}

// runDnsCollection runs one of the collection scripts and returns its stdout.
// It deliberately errors when the DnsServer module is missing rather than
// reporting empty values: a host without the DNS Server role is not a host
// whose DNS configuration is compliant, and an empty zone list would let
// `zones.all(...)` pass on a machine that is not a name server at all.
func (w *mqlWindowsDnsServer) runDnsCollection(script string) (io.Reader, error) {
	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("windows.dnsServer is not supported on this connection")
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("windows.dnsServer requires a connection that can run commands")
	}

	executedCmd, err := conn.RunCommand(powershell.Encode(script))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to read the DNS server configuration, the DNS Server role may not be installed: " + string(stderr))
	}
	return executedCmd.Stdout, nil
}

func (w *mqlWindowsDnsServer) config() (*windows.WindowsDnsServerConfig, error) {
	// The guard is read under the lock, never before it. A fast path that
	// tests the flag first is a data race: the goroutine that publishes the
	// result writes the flag and the pointer with no happens-before edge to
	// the reader, so a racing accessor can see the flag set and the data still
	// nil. The lock is uncontended in the common case and the work it guards
	// is a remote command, so there is nothing to win by skipping it.
	w.configLock.Lock()
	defer w.configLock.Unlock()
	if w.configFetched {
		return w.configData, nil
	}

	stdout, err := w.runDnsCollection(windows.DNS_SERVER_SETTINGS)
	if err != nil {
		return nil, err
	}
	data, err := windows.ParseWindowsDnsServerConfig(stdout)
	if err != nil {
		return nil, err
	}

	w.configData = data
	w.configFetched = true
	return w.configData, nil
}

func (w *mqlWindowsDnsServer) zoneData() ([]windows.WindowsDnsServerZone, error) {
	w.zonesLock.Lock()
	defer w.zonesLock.Unlock()
	if w.zonesFetched {
		return w.zonesData, nil
	}

	stdout, err := w.runDnsCollection(windows.DNS_SERVER_ZONES)
	if err != nil {
		return nil, err
	}
	zones, err := windows.ParseWindowsDnsServerZones(stdout)
	if err != nil {
		return nil, err
	}

	w.zonesData = zones
	w.zonesFetched = true
	return w.zonesData, nil
}

// Each singleton sub-resource below is reachable by a dotted path that is also
// its own registered resource name: the field `settings` on `windows.dnsServer`
// and the resource `windows.dnsServer.settings` occupy the same path. The
// compiler resolves the longest matching resource name before it considers a
// field (compileResource extends the identifier while Schema.Lookup keeps
// matching), so `windows.dnsServer.settings` instantiates the sub-resource
// directly and the parent's settings() accessor never runs. Its fields are
// plain schema fields that only the parent populates, so every one stays unset
// and reports "provider returned no data and no error", then converts as a
// primitive carrying no type information.
//
// Delegating to the parent's accessor fills the resource in. The block form
// `windows.dnsServer { settings { ... } }` binds the field instead of resolving
// a resource name and was never affected, which is why the list fields
// (`zones`, `rootHints`) also work: their element resources are singular
// (`windows.dnsServer.zone`), so the plural field path matches no resource.
//
// When the resource is created normally by the parent, it carries an __id and
// each of these is a no-op.
func initWindowsDnsServerChild[T plugin.Resource](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	get func(*mqlWindowsDnsServer) *plugin.TValue[T],
) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "windows.dnsServer", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := get(parent.(*mqlWindowsDnsServer))
	if v.Error != nil {
		return nil, nil, v.Error
	}
	return args, v.Data, nil
}

func initWindowsDnsServerSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetSettings)
}

func initWindowsDnsServerRecursion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetRecursion)
}

func initWindowsDnsServerCache(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetCache)
}

func initWindowsDnsServerDiagnostics(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetDiagnostics)
}

func initWindowsDnsServerScavenging(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetScavenging)
}

func initWindowsDnsServerResponseRateLimiting(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetResponseRateLimiting)
}

func initWindowsDnsServerForwarderConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsDnsServerChild(runtime, args, (*mqlWindowsDnsServer).GetForwarderConfiguration)
}

// windows.dnsServer.zone.dnssec collides the same way, but it cannot be filled
// in from the root: the DNSSEC settings belong to one zone and there is no
// single zone to delegate to. Returning an error keeps the dotted form from
// reporting a whole set of nulls, which would let a check that reads "not
// signed" pass on a server whose zones are signed. The signing state is
// available per zone through windows.dnsServer.zones.
func initWindowsDnsServerZoneDnssec(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	return nil, nil, errors.New("windows.dnsServer.zone.dnssec belongs to a zone and cannot be queried on its own, iterate windows.dnsServer.zones and read its dnssec field instead")
}

func (w *mqlWindowsDnsServer) settings() (*mqlWindowsDnsServerSettings, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	s := cfg.Settings

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.settings", map[string]*llx.RawData{
		"__id":                     llx.StringData("windows.dnsServer.settings"),
		"computerName":             llx.StringData(s.ComputerName),
		"majorVersion":             llx.IntData(s.MajorVersion),
		"minorVersion":             llx.IntData(s.MinorVersion),
		"buildNumber":              llx.IntData(s.BuildNumber),
		"enableDnsSec":             llx.BoolData(s.EnableDnsSec),
		"enableVersionQuery":       llx.IntData(s.EnableVersionQuery),
		"enableIPv6":               llx.BoolData(s.EnableIPv6),
		"listeningIpAddresses":     llx.ArrayData(strSliceToAny(s.ListeningIPAddress), types.String),
		"allIpAddresses":           llx.ArrayData(strSliceToAny(s.AllIPAddress), types.String),
		"socketPoolSize":           llx.IntData(s.SocketPoolSize),
		"excludedPortRanges":       llx.ArrayData(strSliceToAny(s.SocketPoolExcludedPortRanges), types.String),
		"roundRobin":               llx.BoolData(s.RoundRobin),
		"bindSecondaries":          llx.BoolData(s.BindSecondaries),
		"strictFileParsing":        llx.BoolData(s.StrictFileParsing),
		"nameCheckFlag":            llx.IntData(s.NameCheckFlag),
		"enableOnlineSigning":      llx.BoolData(s.EnableOnlineSigning),
		"addressAnswerLimit":       llx.IntData(s.AddressAnswerLimit),
		"xfrConnectTimeoutSeconds": llx.IntData(s.XfrConnectTimeout),
		"dsAvailable":              llx.BoolData(s.DsAvailable),
		"isReadOnlyDC":             llx.BoolData(s.IsReadOnlyDC),
		"serverLevelPluginDll":     llx.StringData(s.ServerLevelPluginDll),
		"rootTrustAnchorsUrl":      llx.StringData(s.RootTrustAnchorsURL),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerSettings), nil
}

func (w *mqlWindowsDnsServer) recursion() (*mqlWindowsDnsServerRecursion, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	r := cfg.Recursion

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.recursion", map[string]*llx.RawData{
		"__id":                     llx.StringData("windows.dnsServer.recursion"),
		"enabled":                  llx.BoolData(r.Enable),
		"secureResponse":           llx.BoolData(r.SecureResponse),
		"timeoutSeconds":           llx.IntData(r.Timeout),
		"retryIntervalSeconds":     llx.IntData(r.RetryInterval),
		"additionalTimeoutSeconds": llx.IntData(r.AdditionalTimeout),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerRecursion), nil
}

func (w *mqlWindowsDnsServer) cache() (*mqlWindowsDnsServerCache, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	c := cfg.Cache

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.cache", map[string]*llx.RawData{
		"__id":                             llx.StringData("windows.dnsServer.cache"),
		"enablePollutionProtection":        llx.BoolData(c.EnablePollutionProtection),
		"lockingPercent":                   llx.IntData(c.LockingPercent),
		"maxKbSize":                        llx.IntData(c.MaxKBSize),
		"maxTtlSeconds":                    llx.IntDataPtr(c.MaxTtl.Seconds()),
		"maxNegativeTtlSeconds":            llx.IntDataPtr(c.MaxNegativeTtl.Seconds()),
		"storeEmptyAuthenticationResponse": llx.BoolData(c.StoreEmptyAuthenticationResponse),
		"ignorePolicies":                   llx.BoolData(c.IgnorePolicies),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerCache), nil
}

func (w *mqlWindowsDnsServer) diagnostics() (*mqlWindowsDnsServerDiagnostics, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	d := cfg.Diagnostics

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.diagnostics", map[string]*llx.RawData{
		"__id":                llx.StringData("windows.dnsServer.diagnostics"),
		"eventLogLevel":       llx.IntData(d.EventLogLevel),
		"useSystemEventLog":   llx.BoolData(d.UseSystemEventLog),
		"enableLoggingToFile": llx.BoolData(d.EnableLoggingToFile),
		"logFilePath":         llx.StringData(d.LogFilePath),
		"maxFileSizeBytes":    llx.IntData(d.MaxMBFileSize),
		// Deprecated: same value, kept so existing checks do not break.
		"maxFileSizeMb":               llx.IntData(d.MaxMBFileSize),
		"enableLogFileRollover":       llx.BoolData(d.EnableLogFileRollover),
		"saveLogsToPersistentStorage": llx.BoolData(d.SaveLogsToPersistentStorage),
		"logQueries":                  llx.BoolData(d.Queries),
		"logAnswers":                  llx.BoolData(d.Answers),
		"logNotifications":            llx.BoolData(d.Notifications),
		"logUpdates":                  llx.BoolData(d.Update),
		"logQuestionTransactions":     llx.BoolData(d.QuestionTransactions),
		"logUnmatchedResponses":       llx.BoolData(d.UnmatchedResponse),
		"logSendPackets":              llx.BoolData(d.SendPackets),
		"logReceivePackets":           llx.BoolData(d.ReceivePackets),
		"logTcpPackets":               llx.BoolData(d.TcpPackets),
		"logUdpPackets":               llx.BoolData(d.UdpPackets),
		"logFullPackets":              llx.BoolData(d.FullPackets),
		"writeThrough":                llx.BoolData(d.WriteThrough),
		"filterIpAddresses":           llx.ArrayData(strSliceToAny(d.FilterIPAddressList), types.String),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerDiagnostics), nil
}

func (w *mqlWindowsDnsServer) scavenging() (*mqlWindowsDnsServerScavenging, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}
	s := cfg.Scavenging

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.scavenging", map[string]*llx.RawData{
		"__id":                      llx.StringData("windows.dnsServer.scavenging"),
		"enabled":                   llx.BoolData(s.ScavengingState),
		"scavengingIntervalSeconds": llx.IntDataPtr(s.ScavengingInterval.Seconds()),
		"refreshIntervalSeconds":    llx.IntDataPtr(s.RefreshInterval.Seconds()),
		"noRefreshIntervalSeconds":  llx.IntDataPtr(s.NoRefreshInterval.Seconds()),
		// A server that has never scavenged reports no timestamp at all, which
		// stays null rather than becoming the zero time.
		"lastScavengeTime": llx.TimeDataPtr(windows.ParseDnsServerTime(s.LastScavengeTime)),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerScavenging), nil
}

func (w *mqlWindowsDnsServer) responseRateLimiting() (*mqlWindowsDnsServerResponseRateLimiting, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}

	// Older DNS server builds have no response rate limiting cmdlet at all.
	// The field is null there, which is a different fact from rate limiting
	// being switched off, and a policy can tell the two apart.
	if cfg.ResponseRateLimiting == nil {
		w.ResponseRateLimiting.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r := cfg.ResponseRateLimiting

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.responseRateLimiting", map[string]*llx.RawData{
		"__id":                      llx.StringData("windows.dnsServer.responseRateLimiting"),
		"mode":                      llx.StringData(r.Mode),
		"responsesPerSecond":        llx.IntData(r.ResponsesPerSec),
		"errorsPerSecond":           llx.IntData(r.ErrorsPerSec),
		"windowSeconds":             llx.IntData(r.WindowInSec),
		"ipv4PrefixLength":          llx.IntData(r.IPv4PrefixLength),
		"ipv6PrefixLength":          llx.IntData(r.IPv6PrefixLength),
		"leakRate":                  llx.IntData(r.LeakRate),
		"truncateRate":              llx.IntData(r.TruncateRate),
		"maximumResponsesPerWindow": llx.IntData(r.MaximumResponsesPerWindow),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerResponseRateLimiting), nil
}

func (w *mqlWindowsDnsServer) forwarderConfiguration() (*mqlWindowsDnsServerForwarderConfiguration, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}

	if cfg.Forwarders == nil {
		w.ForwarderConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f := cfg.Forwarders

	o, err := CreateResource(w.MqlRuntime, "windows.dnsServer.forwarderConfiguration", map[string]*llx.RawData{
		"__id": llx.StringData("windows.dnsServer.forwarderConfiguration"),
		// An empty list means no forwarders are configured, which is a real
		// state and not a collection failure.
		"ipAddresses":      llx.ArrayData(strSliceToAny(f.IPAddress), types.String),
		"useRootHint":      llx.BoolData(f.UseRootHint),
		"timeoutSeconds":   llx.IntData(f.Timeout),
		"enableReordering": llx.BoolData(f.EnableReordering),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlWindowsDnsServerForwarderConfiguration), nil
}

func (w *mqlWindowsDnsServer) rootHints() ([]any, error) {
	cfg, err := w.config()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(cfg.RootHints))
	for _, h := range cfg.RootHints {
		r, err := CreateResource(w.MqlRuntime, "windows.dnsServer.rootHint", map[string]*llx.RawData{
			"__id":        llx.StringData(windows.DnsServerRootHintID(h.NameServer)),
			"nameServer":  llx.StringData(h.NameServer),
			"ipAddresses": llx.ArrayData(strSliceToAny(h.IPAddress), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (w *mqlWindowsDnsServer) zones() ([]any, error) {
	zones, err := w.zoneData()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(zones))
	for i := range zones {
		z := zones[i]

		args := map[string]*llx.RawData{
			"__id":                   llx.StringData(windows.DnsServerZoneID(z.ZoneName)),
			"name":                   llx.StringData(z.ZoneName),
			"zoneType":               llx.StringData(z.ZoneType),
			"dynamicUpdate":          llx.StringData(z.DynamicUpdate),
			"secureSecondaries":      llx.StringData(z.SecureSecondaries),
			"secondaryServers":       llx.ArrayData(strSliceToAny(z.SecondaryServers), types.String),
			"notify":                 llx.StringData(z.Notify),
			"notifyServers":          llx.ArrayData(strSliceToAny(z.NotifyServers), types.String),
			"isSigned":               llx.BoolData(z.IsSigned),
			"isDsIntegrated":         llx.BoolData(z.IsDsIntegrated),
			"isAutoCreated":          llx.BoolData(z.IsAutoCreated),
			"isReverseLookupZone":    llx.BoolData(z.IsReverseLookupZone),
			"isPaused":               llx.BoolData(z.IsPaused),
			"isShutdown":             llx.BoolData(z.IsShutdown),
			"isReadOnly":             llx.BoolData(z.IsReadOnly),
			"isWinsEnabled":          llx.BoolData(z.IsWinsEnabled),
			"zoneFile":               llx.StringData(z.ZoneFile),
			"replicationScope":       llx.StringData(z.ReplicationScope),
			"directoryPartitionName": llx.StringData(z.DirectoryPartitionName),
		}

		dnssec, err := w.zoneDnssec(z)
		if err != nil {
			return nil, err
		}
		if dnssec == nil {
			// An unsigned zone has no DNSSEC settings, and neither does a
			// signed zone whose settings could not be read. Reporting a
			// zero-valued object here would let an assertion about the signing
			// parameters pass on a zone whose parameters were never read.
			args["dnssec"] = llx.NilData
		} else {
			args["dnssec"] = llx.ResourceData(dnssec, "windows.dnsServer.zone.dnssec")
		}

		keys, err := w.zoneSigningKeys(z)
		if err != nil {
			return nil, err
		}
		args["signingKeys"] = llx.ArrayData(keys, types.Resource("windows.dnsServer.zone.signingKey"))

		r, err := CreateResource(w.MqlRuntime, "windows.dnsServer.zone", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (w *mqlWindowsDnsServer) zoneDnssec(z windows.WindowsDnsServerZone) (plugin.Resource, error) {
	if z.Dnssec == nil {
		return nil, nil
	}
	d := z.Dnssec

	return CreateResource(w.MqlRuntime, "windows.dnsServer.zone.dnssec", map[string]*llx.RawData{
		"__id":                                 llx.StringData(windows.DnsServerZoneID(z.ZoneName) + "/dnssec"),
		"denialOfExistence":                    llx.StringData(d.DenialOfExistence),
		"nsec3HashAlgorithm":                   llx.StringData(d.NSec3HashAlgorithm),
		"nsec3Iterations":                      llx.IntData(d.NSec3Iterations),
		"nsec3OptOut":                          llx.BoolData(d.NSec3OptOut),
		"nsec3RandomSaltLength":                llx.IntData(d.NSec3RandomSaltLength),
		"distributeTrustAnchor":                llx.ArrayData(strSliceToAny(d.DistributeTrustAnchor), types.String),
		"enableRfc5011KeyRollover":             llx.BoolData(d.EnableRfc5011KeyRollover),
		"dsRecordGenerationAlgorithm":          llx.ArrayData(strSliceToAny(d.DSRecordGenerationAlgorithm), types.String),
		"dsRecordSetTtlSeconds":                llx.IntDataPtr(d.DSRecordSetTtl.Seconds()),
		"dnsKeyRecordSetTtlSeconds":            llx.IntDataPtr(d.DnsKeyRecordSetTtl.Seconds()),
		"signatureInceptionOffsetSeconds":      llx.IntDataPtr(d.SignatureInceptionOffset.Seconds()),
		"secureDelegationPollingPeriodSeconds": llx.IntDataPtr(d.SecureDelegationPollingPeriod.Seconds()),
		"parentHasSecureDelegation":            llx.BoolData(d.ParentHasSecureDelegation),
		"propagationTimeSeconds":               llx.IntDataPtr(d.PropagationTime.Seconds()),
		"isKeyMasterServer":                    llx.BoolData(d.IsKeyMasterServer),
		"keyMasterServer":                      llx.StringData(d.KeyMasterServer),
	})
}

func (w *mqlWindowsDnsServer) zoneSigningKeys(z windows.WindowsDnsServerZone) ([]any, error) {
	res := make([]any, 0, len(z.SigningKeys))
	for _, k := range z.SigningKeys {
		r, err := CreateResource(w.MqlRuntime, "windows.dnsServer.zone.signingKey", map[string]*llx.RawData{
			// The zone is part of the id because two zones can hold keys that
			// are otherwise identical, and the key id is part of it because a
			// zone holds a key signing key and a zone signing key at once.
			"__id":                                 llx.StringData(windows.DnsServerSigningKeyID(z.ZoneName, k.KeyId)),
			"keyId":                                llx.StringData(k.KeyId),
			"zoneName":                             llx.StringData(z.ZoneName),
			"keyType":                              llx.StringData(k.KeyType),
			"cryptoAlgorithm":                      llx.StringData(k.CryptoAlgorithm),
			"keyLength":                            llx.IntData(k.KeyLength),
			"currentState":                         llx.StringData(k.CurrentState),
			"keyStorageProvider":                   llx.StringData(k.KeyStorageProvider),
			"storeKeysInAD":                        llx.BoolData(k.StoreKeysInAD),
			"isRolloverEnabled":                    llx.BoolData(k.IsRolloverEnabled),
			"rolloverPeriodSeconds":                llx.IntDataPtr(k.RolloverPeriod.Seconds()),
			"dnsKeySignatureValidityPeriodSeconds": llx.IntDataPtr(k.DnsKeySignatureValidityPeriod.Seconds()),
			"dsSignatureValidityPeriodSeconds":     llx.IntDataPtr(k.DSSignatureValidityPeriod.Seconds()),
			"zoneSignatureValidityPeriodSeconds":   llx.IntDataPtr(k.ZoneSignatureValidityPeriod.Seconds()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
