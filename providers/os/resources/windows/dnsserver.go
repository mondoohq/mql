// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// The Windows DNS Server configuration is collected in two batched calls
// rather than one call per field. A remote host pays a process per command, so
// a policy that reads a dozen settings would otherwise pay a dozen processes.
//
// It is two calls and not one because a PowerShell command is passed to the
// target base64 encoded as UTF-16, which triples its length, and the command
// line is capped at 8191 characters. That caps a script at roughly 3000
// characters, and a single script covering every cmdlet here does not fit. The
// split is by cost as well as by size: a policy that only inspects zones does
// not fetch the server settings, and vice versa. TestDnsServerScriptsFitCommandLine
// fails the build if either script grows past the cap.
const (
	// DNS_SERVER_SETTINGS collects the server-wide configuration.
	DNS_SERVER_SETTINGS = `$ErrorActionPreference='Stop'
Import-Module DnsServer -ErrorAction Stop
function A($v){ if($null -eq $v){,@()}else{,@($v|ForEach-Object{[string]$_})} }
$rrl=$null;try{$rrl=Get-DnsServerResponseRateLimiting|Select-Object Mode,ResponsesPerSec,ErrorsPerSec,WindowInSec,IPv4PrefixLength,IPv6PrefixLength,LeakRate,TruncateRate,MaximumResponsesPerWindow}catch{}
$fwd=$null;try{$fwd=Get-DnsServerForwarder|Select-Object UseRootHint,Timeout,EnableReordering,@{n='IPAddress';e={A $_.IPAddress}}}catch{}
$rh=@();try{$rh=@(Get-DnsServerRootHint|ForEach-Object{[ordered]@{NameServer=[string]$_.NameServer.RecordData.NameServer;IPAddress=A @($_.IPAddress|ForEach-Object{if($_.RecordData.IPv4Address){$_.RecordData.IPv4Address}else{$_.RecordData.IPv6Address}})}})}catch{}
[ordered]@{
Settings=Get-DnsServerSetting -All|Select-Object ComputerName,MajorVersion,MinorVersion,BuildNumber,EnableDnsSec,EnableVersionQuery,EnableIPv6,SocketPoolSize,RoundRobin,BindSecondaries,StrictFileParsing,NameCheckFlag,EnableOnlineSigning,AddressAnswerLimit,XfrConnectTimeout,DsAvailable,IsReadOnlyDC,ServerLevelPluginDll,RootTrustAnchorsURL,@{n='ListeningIPAddress';e={A $_.ListeningIPAddress}},@{n='AllIPAddress';e={A $_.AllIPAddress}},@{n='SocketPoolExcludedPortRanges';e={A $_.SocketPoolExcludedPortRanges}}
Recursion=Get-DnsServerRecursion|Select-Object Enable,SecureResponse,Timeout,RetryInterval,AdditionalTimeout
Cache=Get-DnsServerCache|Select-Object EnablePollutionProtection,LockingPercent,MaxKBSize,MaxTtl,MaxNegativeTtl,StoreEmptyAuthenticationResponse,IgnorePolicies
Diagnostics=Get-DnsServerDiagnostics|Select-Object EventLogLevel,UseSystemEventLog,EnableLoggingToFile,LogFilePath,MaxMBFileSize,EnableLogFileRollover,SaveLogsToPersistentStorage,Queries,Answers,Notifications,Update,QuestionTransactions,UnmatchedResponse,SendPackets,ReceivePackets,TcpPackets,UdpPackets,FullPackets,WriteThrough,@{n='FilterIPAddressList';e={A $_.FilterIPAddressList}}
Scavenging=Get-DnsServerScavenging|Select-Object ScavengingState,ScavengingInterval,RefreshInterval,NoRefreshInterval,@{n='LastScavengeTime';e={if($_.LastScavengeTime){$_.LastScavengeTime.ToUniversalTime().ToString('o')}else{''}}}
ResponseRateLimiting=$rrl
Forwarders=$fwd
RootHints=@($rh)
}|ConvertTo-Json -Depth 6 -Compress`

	// DNS_SERVER_ZONES collects every zone, plus the DNSSEC settings and
	// signing keys of the signed ones. The DNSSEC lookups run inside this one
	// process, so a server with fifty signed zones still costs a single remote
	// command. Each per-zone lookup is guarded, so a zone whose settings cannot
	// be read is simply absent from the DnsSec and SigningKeys lists instead of
	// failing the whole collection.
	DNS_SERVER_ZONES = `$ErrorActionPreference='Stop'
Import-Module DnsServer -ErrorAction Stop
function A($v){ if($null -eq $v){,@()}else{,@($v|ForEach-Object{[string]$_})} }
$zz=@(Get-DnsServerZone)
$sg=@($zz|Where-Object IsSigned)
$dsec=@(foreach($x in $sg){try{Get-DnsServerDnsSecZoneSetting -ZoneName $x.ZoneName|Select-Object ZoneName,DenialOfExistence,NSec3HashAlgorithm,NSec3Iterations,NSec3OptOut,NSec3RandomSaltLength,EnableRfc5011KeyRollover,DSRecordSetTtl,DnsKeyRecordSetTtl,SignatureInceptionOffset,SecureDelegationPollingPeriod,ParentHasSecureDelegation,PropagationTime,IsKeyMasterServer,KeyMasterServer,@{n='DistributeTrustAnchor';e={A $_.DistributeTrustAnchor}},@{n='DSRecordGenerationAlgorithm';e={A $_.DSRecordGenerationAlgorithm}}}catch{}})
$keys=@(foreach($x in $sg){try{Get-DnsServerSigningKey -ZoneName $x.ZoneName|Select-Object ZoneName,KeyType,CryptoAlgorithm,KeyLength,CurrentState,KeyStorageProvider,StoreKeysInAD,IsRolloverEnabled,RolloverPeriod,DnsKeySignatureValidityPeriod,DSSignatureValidityPeriod,ZoneSignatureValidityPeriod,@{n='KeyId';e={[string]$_.KeyId}}}catch{}})
[ordered]@{
Zones=@($zz|Select-Object ZoneName,ZoneType,DynamicUpdate,SecureSecondaries,Notify,IsSigned,IsDsIntegrated,IsAutoCreated,IsReverseLookupZone,IsPaused,IsShutdown,IsReadOnly,IsWinsEnabled,ZoneFile,ReplicationScope,DirectoryPartitionName,@{n='SecondaryServers';e={A $_.SecondaryServers}},@{n='NotifyServers';e={A $_.NotifyServers}})
DnsSec=@($dsec)
SigningKeys=@($keys)
}|ConvertTo-Json -Depth 6 -Compress`
)

// PSMaxScriptLength is the largest PowerShell script that still fits on the
// command line once Encode has widened it to UTF-16 and base64 encoded it.
// A longer script fails on the target with "The command line is too long",
// which surfaces as if the DNS Server role were missing.
const PSMaxScriptLength = 3000

// PSStringArray decodes a list of strings out of any of the shapes PowerShell
// produces for one. The same payload carries more than one: a list built
// inside an ordered hashtable serializes as a plain JSON array, while the same
// list produced by a Select-Object calculated property serializes as
// {"value":[...],"Count":n}. A plain []string tag silently decodes the second
// shape to empty, which reports "no forwarders" and "no listening addresses"
// on a server that has both.
type PSStringArray []string

func (a *PSStringArray) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*a = nil
		return nil
	}

	switch data[0] {
	case '[':
		var list []string
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		*a = list
		return nil
	case '{':
		var wrapped struct {
			Value []string `json:"value"`
		}
		if err := json.Unmarshal(data, &wrapped); err != nil {
			return err
		}
		*a = wrapped.Value
		return nil
	case '"':
		// A single element can arrive unwrapped when PowerShell flattens the
		// one-element array away.
		var single string
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*a = []string{single}
		return nil
	}
	return json.Unmarshal(data, (*[]string)(a))
}

// PSTimeSpan decodes a .NET TimeSpan. ConvertTo-Json renders one as an object
// of Ticks/Days/Hours/TotalSeconds rather than a number, so the value a caller
// wants has to be read out of it.
type PSTimeSpan struct {
	TotalSeconds float64 `json:"TotalSeconds"`
}

// Seconds returns the duration in whole seconds, or nil for an absent value so
// it stays null rather than being reported as zero.
func (t *PSTimeSpan) Seconds() *int64 {
	if t == nil {
		return nil
	}
	v := int64(t.TotalSeconds)
	return &v
}

// WindowsDnsServerConfig is the server-wide configuration.
type WindowsDnsServerConfig struct {
	Settings             WindowsDnsServerSettings    `json:"Settings"`
	Recursion            WindowsDnsServerRecursion   `json:"Recursion"`
	Cache                WindowsDnsServerCache       `json:"Cache"`
	Diagnostics          WindowsDnsServerDiagnostics `json:"Diagnostics"`
	Scavenging           WindowsDnsServerScavenging  `json:"Scavenging"`
	ResponseRateLimiting *WindowsDnsServerRrl        `json:"ResponseRateLimiting"`
	Forwarders           *WindowsDnsServerForwarders `json:"Forwarders"`
	RootHints            []WindowsDnsServerRootHint  `json:"RootHints"`
}

type WindowsDnsServerSettings struct {
	ComputerName string `json:"ComputerName"`
	MajorVersion int64  `json:"MajorVersion"`
	MinorVersion int64  `json:"MinorVersion"`
	BuildNumber  int64  `json:"BuildNumber"`
	EnableDnsSec bool   `json:"EnableDnsSec"`
	// EnableVersionQuery and NameCheckFlag are numeric rather than labels.
	// Unlike ZoneType or DynamicUpdate, these CIM properties carry no string
	// representation, so they are reported as the underlying number.
	EnableVersionQuery           int64         `json:"EnableVersionQuery"`
	NameCheckFlag                int64         `json:"NameCheckFlag"`
	EnableIPv6                   bool          `json:"EnableIPv6"`
	ListeningIPAddress           PSStringArray `json:"ListeningIPAddress"`
	AllIPAddress                 PSStringArray `json:"AllIPAddress"`
	SocketPoolSize               int64         `json:"SocketPoolSize"`
	SocketPoolExcludedPortRanges PSStringArray `json:"SocketPoolExcludedPortRanges"`
	RoundRobin                   bool          `json:"RoundRobin"`
	BindSecondaries              bool          `json:"BindSecondaries"`
	StrictFileParsing            bool          `json:"StrictFileParsing"`
	EnableOnlineSigning          bool          `json:"EnableOnlineSigning"`
	AddressAnswerLimit           int64         `json:"AddressAnswerLimit"`
	XfrConnectTimeout            int64         `json:"XfrConnectTimeout"`
	DsAvailable                  bool          `json:"DsAvailable"`
	IsReadOnlyDC                 bool          `json:"IsReadOnlyDC"`
	ServerLevelPluginDll         string        `json:"ServerLevelPluginDll"`
	RootTrustAnchorsURL          string        `json:"RootTrustAnchorsURL"`
}

type WindowsDnsServerRecursion struct {
	Enable            bool  `json:"Enable"`
	SecureResponse    bool  `json:"SecureResponse"`
	Timeout           int64 `json:"Timeout"`
	RetryInterval     int64 `json:"RetryInterval"`
	AdditionalTimeout int64 `json:"AdditionalTimeout"`
}

type WindowsDnsServerCache struct {
	EnablePollutionProtection        bool        `json:"EnablePollutionProtection"`
	LockingPercent                   int64       `json:"LockingPercent"`
	MaxKBSize                        int64       `json:"MaxKBSize"`
	MaxTtl                           *PSTimeSpan `json:"MaxTtl"`
	MaxNegativeTtl                   *PSTimeSpan `json:"MaxNegativeTtl"`
	StoreEmptyAuthenticationResponse bool        `json:"StoreEmptyAuthenticationResponse"`
	IgnorePolicies                   bool        `json:"IgnorePolicies"`
}

type WindowsDnsServerDiagnostics struct {
	EventLogLevel               int64         `json:"EventLogLevel"`
	UseSystemEventLog           bool          `json:"UseSystemEventLog"`
	EnableLoggingToFile         bool          `json:"EnableLoggingToFile"`
	LogFilePath                 string        `json:"LogFilePath"`
	MaxMBFileSize               int64         `json:"MaxMBFileSize"`
	EnableLogFileRollover       bool          `json:"EnableLogFileRollover"`
	SaveLogsToPersistentStorage bool          `json:"SaveLogsToPersistentStorage"`
	Queries                     bool          `json:"Queries"`
	Answers                     bool          `json:"Answers"`
	Notifications               bool          `json:"Notifications"`
	Update                      bool          `json:"Update"`
	QuestionTransactions        bool          `json:"QuestionTransactions"`
	UnmatchedResponse           bool          `json:"UnmatchedResponse"`
	SendPackets                 bool          `json:"SendPackets"`
	ReceivePackets              bool          `json:"ReceivePackets"`
	TcpPackets                  bool          `json:"TcpPackets"`
	UdpPackets                  bool          `json:"UdpPackets"`
	FullPackets                 bool          `json:"FullPackets"`
	WriteThrough                bool          `json:"WriteThrough"`
	FilterIPAddressList         PSStringArray `json:"FilterIPAddressList"`
}

type WindowsDnsServerScavenging struct {
	ScavengingState    bool        `json:"ScavengingState"`
	ScavengingInterval *PSTimeSpan `json:"ScavengingInterval"`
	RefreshInterval    *PSTimeSpan `json:"RefreshInterval"`
	NoRefreshInterval  *PSTimeSpan `json:"NoRefreshInterval"`
	LastScavengeTime   PSString    `json:"LastScavengeTime"`
}

type WindowsDnsServerRrl struct {
	Mode                      string `json:"Mode"`
	ResponsesPerSec           int64  `json:"ResponsesPerSec"`
	ErrorsPerSec              int64  `json:"ErrorsPerSec"`
	WindowInSec               int64  `json:"WindowInSec"`
	IPv4PrefixLength          int64  `json:"IPv4PrefixLength"`
	IPv6PrefixLength          int64  `json:"IPv6PrefixLength"`
	LeakRate                  int64  `json:"LeakRate"`
	TruncateRate              int64  `json:"TruncateRate"`
	MaximumResponsesPerWindow int64  `json:"MaximumResponsesPerWindow"`
}

type WindowsDnsServerForwarders struct {
	IPAddress        PSStringArray `json:"IPAddress"`
	UseRootHint      bool          `json:"UseRootHint"`
	Timeout          int64         `json:"Timeout"`
	EnableReordering bool          `json:"EnableReordering"`
}

type WindowsDnsServerRootHint struct {
	NameServer string        `json:"NameServer"`
	IPAddress  PSStringArray `json:"IPAddress"`
}

// windowsDnsServerZonePayload is the raw second call: the zones, and the
// DNSSEC settings and signing keys of the signed ones as flat lists keyed by
// zone name. JoinDnsServerZones stitches them together.
type windowsDnsServerZonePayload struct {
	Zones       []WindowsDnsServerZone       `json:"Zones"`
	DnsSec      []WindowsDnsServerZoneDnssec `json:"DnsSec"`
	SigningKeys []WindowsDnsServerSigningKey `json:"SigningKeys"`
}

type WindowsDnsServerZone struct {
	ZoneName               string        `json:"ZoneName"`
	ZoneType               string        `json:"ZoneType"`
	DynamicUpdate          string        `json:"DynamicUpdate"`
	SecureSecondaries      string        `json:"SecureSecondaries"`
	SecondaryServers       PSStringArray `json:"SecondaryServers"`
	Notify                 string        `json:"Notify"`
	NotifyServers          PSStringArray `json:"NotifyServers"`
	IsSigned               bool          `json:"IsSigned"`
	IsDsIntegrated         bool          `json:"IsDsIntegrated"`
	IsAutoCreated          bool          `json:"IsAutoCreated"`
	IsReverseLookupZone    bool          `json:"IsReverseLookupZone"`
	IsPaused               bool          `json:"IsPaused"`
	IsShutdown             bool          `json:"IsShutdown"`
	IsReadOnly             bool          `json:"IsReadOnly"`
	IsWinsEnabled          bool          `json:"IsWinsEnabled"`
	ZoneFile               string        `json:"ZoneFile"`
	ReplicationScope       string        `json:"ReplicationScope"`
	DirectoryPartitionName string        `json:"DirectoryPartitionName"`

	// Filled in by JoinDnsServerZones, not by the JSON.
	Dnssec      *WindowsDnsServerZoneDnssec  `json:"-"`
	SigningKeys []WindowsDnsServerSigningKey `json:"-"`
}

type WindowsDnsServerZoneDnssec struct {
	ZoneName                      string        `json:"ZoneName"`
	DenialOfExistence             string        `json:"DenialOfExistence"`
	NSec3HashAlgorithm            string        `json:"NSec3HashAlgorithm"`
	NSec3Iterations               int64         `json:"NSec3Iterations"`
	NSec3OptOut                   bool          `json:"NSec3OptOut"`
	NSec3RandomSaltLength         int64         `json:"NSec3RandomSaltLength"`
	DistributeTrustAnchor         PSStringArray `json:"DistributeTrustAnchor"`
	EnableRfc5011KeyRollover      bool          `json:"EnableRfc5011KeyRollover"`
	DSRecordGenerationAlgorithm   PSStringArray `json:"DSRecordGenerationAlgorithm"`
	DSRecordSetTtl                *PSTimeSpan   `json:"DSRecordSetTtl"`
	DnsKeyRecordSetTtl            *PSTimeSpan   `json:"DnsKeyRecordSetTtl"`
	SignatureInceptionOffset      *PSTimeSpan   `json:"SignatureInceptionOffset"`
	SecureDelegationPollingPeriod *PSTimeSpan   `json:"SecureDelegationPollingPeriod"`
	ParentHasSecureDelegation     bool          `json:"ParentHasSecureDelegation"`
	PropagationTime               *PSTimeSpan   `json:"PropagationTime"`
	IsKeyMasterServer             bool          `json:"IsKeyMasterServer"`
	KeyMasterServer               string        `json:"KeyMasterServer"`
}

// WindowsDnsServerSigningKey deliberately omits ActiveKey, StandbyKey and
// NextKey. Those are DNSSEC key tags computed from the key material, and they
// change every time the zone is re-signed, so a check written against one
// cannot stay true. Everything modeled here is a configured property.
type WindowsDnsServerSigningKey struct {
	ZoneName                      string      `json:"ZoneName"`
	KeyId                         string      `json:"KeyId"`
	KeyType                       string      `json:"KeyType"`
	CryptoAlgorithm               string      `json:"CryptoAlgorithm"`
	KeyLength                     int64       `json:"KeyLength"`
	CurrentState                  string      `json:"CurrentState"`
	KeyStorageProvider            string      `json:"KeyStorageProvider"`
	StoreKeysInAD                 bool        `json:"StoreKeysInAD"`
	IsRolloverEnabled             bool        `json:"IsRolloverEnabled"`
	RolloverPeriod                *PSTimeSpan `json:"RolloverPeriod"`
	DnsKeySignatureValidityPeriod *PSTimeSpan `json:"DnsKeySignatureValidityPeriod"`
	DSSignatureValidityPeriod     *PSTimeSpan `json:"DSSignatureValidityPeriod"`
	ZoneSignatureValidityPeriod   *PSTimeSpan `json:"ZoneSignatureValidityPeriod"`
}

// ParseWindowsDnsServerConfig decodes the server-wide configuration.
func ParseWindowsDnsServerConfig(input io.Reader) (*WindowsDnsServerConfig, error) {
	var res WindowsDnsServerConfig
	if err := json.NewDecoder(input).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ParseWindowsDnsServerZones decodes the zone payload and attaches each
// zone's DNSSEC settings and signing keys.
func ParseWindowsDnsServerZones(input io.Reader) ([]WindowsDnsServerZone, error) {
	var payload windowsDnsServerZonePayload
	if err := json.NewDecoder(input).Decode(&payload); err != nil {
		return nil, err
	}
	return JoinDnsServerZones(payload.Zones, payload.DnsSec, payload.SigningKeys), nil
}

// JoinDnsServerZones attaches the DNSSEC settings and signing keys to the zone
// they belong to. The two lists are collected separately because they need one
// cmdlet call per signed zone, and joining them here keeps that off the wire.
//
// A signed zone whose DNSSEC lookup failed keeps a nil Dnssec, which is the
// same shape an unsigned zone has. That is deliberate: reporting a zero-valued
// settings object would let an assertion about the signing parameters pass on
// a zone whose parameters were never read.
func JoinDnsServerZones(zones []WindowsDnsServerZone, dnssec []WindowsDnsServerZoneDnssec, keys []WindowsDnsServerSigningKey) []WindowsDnsServerZone {
	byZone := make(map[string]*WindowsDnsServerZoneDnssec, len(dnssec))
	for i := range dnssec {
		byZone[dnssec[i].ZoneName] = &dnssec[i]
	}

	keysByZone := make(map[string][]WindowsDnsServerSigningKey, len(keys))
	for _, k := range keys {
		keysByZone[k.ZoneName] = append(keysByZone[k.ZoneName], k)
	}

	res := make([]WindowsDnsServerZone, 0, len(zones))
	for _, z := range zones {
		z.Dnssec = byZone[z.ZoneName]
		z.SigningKeys = keysByZone[z.ZoneName]
		res = append(res, z)
	}
	return res
}

// DnsServerZoneID builds the resource id of a zone. A zone name is unique on
// a server, so it is the only dimension the id needs.
func DnsServerZoneID(zoneName string) string {
	return "windows.dnsServer.zone/" + zoneName
}

// DnsServerSigningKeyID builds the resource id of a DNSSEC signing key. A key
// repeats along two dimensions, the zone and the key itself, so both are in
// the id: a zone holds a key signing key and a zone signing key at once, and
// two zones can hold keys that differ in nothing a user would notice.
func DnsServerSigningKeyID(zoneName, keyID string) string {
	return "windows.dnsServer.zone.signingKey/" + zoneName + "/" + keyID
}

// DnsServerRootHintID builds the resource id of a root hint, keyed by the name
// server it points at.
func DnsServerRootHintID(nameServer string) string {
	return "windows.dnsServer.rootHint/" + nameServer
}

// ParseDnsServerTime converts an RFC 3339 timestamp emitted by the collection
// script into a time. An empty string means the event has never happened (the
// server has never scavenged, for example) and yields nil, so the field stays
// null rather than reporting the zero time as a real date.
func ParseDnsServerTime(v PSString) *time.Time {
	if v == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, string(v))
	if err != nil {
		return nil
	}
	return &t
}
