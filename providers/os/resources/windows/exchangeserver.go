// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// The Exchange Server configuration is read through the Exchange Management
// Shell snap-in. Loading the snap-in takes seconds, so the cmdlets are batched
// into a few scripts instead of one process per field. It is three scripts and
// not one because a script is passed to the target base64 encoded as UTF-16,
// which caps it at PSMaxScriptLength characters; TestExchangeScriptsFitCommandLine
// fails the build if any of them grows past it. The split is also by cost: a
// policy that reads only the organization settings does not enumerate every
// connector and database of the organization.
//
// Every value is passed through P, which keeps booleans, integers and nulls
// as they are, turns a collection into a list of strings, and turns
// everything else into its string form. Exchange's own types (sizes, time
// spans, values that may be Unlimited, flag enums, AD object ids) serialize as
// nested objects whose shape differs between Exchange builds, while their
// string forms are stable, so the Go side parses those strings.
//
// Each cmdlet runs in its own try block. A cmdlet that fails, or does not
// exist on this server role (Get-MailboxDatabase on an Edge Transport server,
// the anti-spam cmdlets where the agents are not installed), records its error
// under Errors and leaves the other sections intact.
const exchangePrelude = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$WarningPreference='SilentlyContinue'
$ok=$false;foreach($s in 'Microsoft.Exchange.Management.PowerShell.SnapIn','Microsoft.Exchange.Management.PowerShell.E2010'){try{if(!(Get-PSSnapin $s -EA SilentlyContinue)){Add-PSSnapin $s -EA Stop};$ok=$true;break}catch{}}
if(!$ok){[Console]::Error.WriteLine('the Exchange Management Shell snap-in cannot be loaded on this host');exit 3}
function P($o,$n){$h=[ordered]@{};foreach($k in $n){$v=$o.$k;if($null -eq $v -or $v -is [bool] -or $v -is [int] -or $v -is [long]){$h[$k]=$v}elseif($v -is [Collections.IEnumerable] -and $v -isnot [string]){$h[$k]=@($v|%{[string]$_})}else{$h[$k]=[string]$v}};$h}
$r=[ordered]@{};$e=[ordered]@{}
function C($n,$s,$p){try{$r[$n]=@(& $s|%{P $_ $p})}catch{$e[$n]=[string]$_}}
`

const exchangeEpilogue = `
[ordered]@{Data=$r;Errors=$e}|ConvertTo-Json -Depth 5 -Compress`

const (
	// EXCHANGE_ORGANIZATION collects the organization-wide settings and the
	// anti-spam agent configuration.
	EXCHANGE_ORGANIZATION = exchangePrelude +
		`C 'OrganizationConfig' {Get-OrganizationConfig} 'Name','CustomerFeedbackEnabled','OAuth2ClientProfileEnabled','MapiHttpEnabled'
C 'TransportConfig' {Get-TransportConfig} 'MaxReceiveSize','MaxSendSize','MaxRecipientEnvelopeLimit'
C 'AdminAuditLogConfig' {Get-AdminAuditLogConfig} 'AdminAuditLogEnabled','AdminAuditLogCmdlets','AdminAuditLogParameters','AdminAuditLogExcludedCmdlets','AdminAuditLogAgeLimit','LogLevel'
C 'ContentFilterConfig' {Get-ContentFilterConfig} 'Enabled','SCLQuarantineEnabled','SCLQuarantineThreshold','SCLRejectEnabled','SCLDeleteEnabled','QuarantineMailbox'
C 'SenderFilterConfig' {Get-SenderFilterConfig} 'Enabled','Action','BlankSenderBlockingEnabled','BlockedSenders','BlockedDomains'
C 'SenderIdConfig' {Get-SenderIdConfig} 'Enabled','SpoofedDomainAction','TempErrorAction'
C 'SenderReputationConfig' {Get-SenderReputationConfig} 'Enabled','SenderBlockingEnabled','OpenProxyDetectionEnabled','SrlBlockThreshold','SenderBlockingPeriod'
C 'RecipientFilterConfig' {Get-RecipientFilterConfig} 'Enabled','RecipientValidationEnabled','BlockListEnabled','BlockedRecipients'` +
		exchangeEpilogue

	// EXCHANGE_CLIENTS collects the policies that govern clients and external
	// domains, and the transport agents of this server.
	// Get-OwaVirtualDirectory runs with -ADPropertiesOnly: without it the cmdlet
	// reads the IIS metabase of every server in the organization, which fails
	// the whole section when one of them is unreachable, and the settings read
	// here are all stored in Active Directory.
	EXCHANGE_CLIENTS = exchangePrelude +
		`C 'MobileDeviceMailboxPolicies' {Get-MobileDeviceMailboxPolicy} 'Identity','Name','IsDefault','PasswordEnabled','AllowSimplePassword','AlphanumericPasswordRequired','MinPasswordLength','MinPasswordComplexCharacters','PasswordHistory','PasswordExpiration','MaxPasswordFailedAttempts','MaxInactivityTimeLock','DevicePolicyRefreshInterval','RequireDeviceEncryption','RequireStorageCardEncryption','AllowNonProvisionableDevices'
C 'RemoteDomains' {Get-RemoteDomain} 'Identity','Name','DomainName','AllowedOOFType','AutoForwardEnabled','AutoReplyEnabled','NDREnabled','DeliveryReportEnabled'
C 'OwaVirtualDirectories' {Get-OwaVirtualDirectory -ADPropertiesOnly} 'Identity','Server','SMimeEnabled','BasicAuthentication','FormsAuthentication'
C 'TransportAgents' {Get-TransportAgent} 'Identity','Enabled','Priority'` +
		exchangeEpilogue

	// EXCHANGE_TRANSPORT collects the connectors, the per-server transport and
	// client access settings, and the mailbox databases.
	EXCHANGE_TRANSPORT = exchangePrelude +
		`C 'SendConnectors' {Get-SendConnector} 'Identity','Name','Enabled','DNSRoutingEnabled','DomainSecureEnabled','IgnoreSTARTTLS','RequireTLS','TlsAuthLevel','MaxMessageSize','ProtocolLoggingLevel','ConnectionInactivityTimeOut','AddressSpaces','SmartHosts'
C 'ReceiveConnectors' {Get-ReceiveConnector} 'Identity','Name','Server','Enabled','AuthMechanism','PermissionGroups','Banner','ConnectionTimeout','MaxMessageSize','ProtocolLoggingLevel','TransportRole','Bindings','RemoteIPRanges','RequireTLS'
C 'TransportServices' {Get-TransportService} 'Identity','Name','MessageTrackingLogEnabled','ConnectivityLogEnabled','PickupDirectoryPath','ReplayDirectoryPath'
C 'RpcClientAccess' {Get-RpcClientAccess} 'Identity','Server','EncryptionRequired','BlockedClientVersions'
C 'MailboxDatabases' {Get-MailboxDatabase} 'Identity','Name','Server','RetainDeletedItemsUntilBackup','DeletedItemRetention','MailboxRetention','IssueWarningQuota','ProhibitSendQuota','ProhibitSendReceiveQuota','CircularLoggingEnabled'` +
		exchangeEpilogue
)

// ExchangeCollection is the output of one collection script: the records of
// each cmdlet that ran, and the error of each one that failed.
type ExchangeCollection struct {
	Data   map[string][]ExchangeRecord `json:"Data"`
	Errors map[string]string           `json:"Errors"`
}

// ParseExchangeCollection decodes the output of a collection script.
func ParseExchangeCollection(r io.Reader) (*ExchangeCollection, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("the Exchange Management Shell returned no output")
	}

	// PowerShell flattens a section with one record to a bare object and an
	// empty one to null, depending on how the array reached the hashtable.
	// Decode each section on its own so both shapes read as lists.
	var raw struct {
		Data   map[string]json.RawMessage `json:"Data"`
		Errors map[string]string          `json:"Errors"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cannot parse the Exchange Management Shell output: %w", err)
	}

	res := &ExchangeCollection{
		Data:   make(map[string][]ExchangeRecord, len(raw.Data)),
		Errors: raw.Errors,
	}
	if res.Errors == nil {
		res.Errors = map[string]string{}
	}
	for name, section := range raw.Data {
		records, err := decodeExchangeRecords(section)
		if err != nil {
			return nil, fmt.Errorf("cannot parse the %s section of the Exchange Management Shell output: %w", name, err)
		}
		res.Data[name] = records
	}
	return res, nil
}

func decodeExchangeRecords(section json.RawMessage) ([]ExchangeRecord, error) {
	section = bytes.TrimSpace(section)
	if len(section) == 0 || bytes.Equal(section, []byte("null")) {
		return []ExchangeRecord{}, nil
	}
	if section[0] == '{' {
		var one ExchangeRecord
		if err := json.Unmarshal(section, &one); err != nil {
			return nil, err
		}
		// Windows PowerShell 5.1 can serialize an array that went through the
		// extended type system as {"value":[...],"Count":n}. Read as a record,
		// that would report every setting as null.
		if inner, ok := one["value"]; ok && len(one) == 2 {
			if _, ok := one["Count"]; ok {
				return decodeExchangeRecords(inner)
			}
		}
		return []ExchangeRecord{one}, nil
	}
	var list []ExchangeRecord
	if err := json.Unmarshal(section, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Section returns the records of one cmdlet. It errors when the cmdlet failed
// on the server, so a field built on it reports why rather than an empty
// list, which would let `list.all(...)` pass on a server that was never read.
func (c *ExchangeCollection) Section(name string) ([]ExchangeRecord, error) {
	if msg, ok := c.Errors[name]; ok {
		return nil, fmt.Errorf("the Exchange Management Shell failed to read %s: %s", name, strings.TrimSpace(msg))
	}
	records, ok := c.Data[name]
	if !ok {
		return nil, fmt.Errorf("the Exchange Management Shell returned no %s section", name)
	}
	return records, nil
}

// Single returns the one record of an organization-wide cmdlet such as
// Get-TransportConfig.
func (c *ExchangeCollection) Single(name string) (ExchangeRecord, error) {
	records, err := c.Section(name)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("the Exchange Management Shell returned no %s", name)
	}
	return records[0], nil
}

// ExchangeRecord is one object a cmdlet returned, keyed by property name.
type ExchangeRecord map[string]json.RawMessage

func (r ExchangeRecord) raw(key string) (json.RawMessage, bool) {
	v, ok := r[key]
	if !ok {
		return nil, false
	}
	v = bytes.TrimSpace(v)
	if len(v) == 0 || bytes.Equal(v, []byte("null")) {
		return nil, false
	}
	return v, true
}

func (r ExchangeRecord) str(key string) (string, bool, error) {
	v, ok := r.raw(key)
	if !ok {
		return "", false, nil
	}
	if v[0] != '"' {
		// A number or a boolean that reached the record unconverted.
		return string(v), true, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false, fmt.Errorf("%s: %w", key, err)
	}
	return s, true, nil
}

// String returns a property as a string. An absent or empty value is nil, so
// an unset banner or quarantine mailbox reads as null.
func (r ExchangeRecord) String(key string) (*string, error) {
	s, ok, err := r.str(key)
	if err != nil || !ok || strings.TrimSpace(s) == "" {
		return nil, err
	}
	return &s, nil
}

// Bool returns a property as a boolean. It accepts a JSON boolean and the
// strings True and False.
func (r ExchangeRecord) Bool(key string) (*bool, error) {
	v, ok := r.raw(key)
	if !ok {
		return nil, nil
	}
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return &b, nil
	}
	s, _, err := r.str(key)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		b = true
	case "false":
		b = false
	default:
		return nil, fmt.Errorf("%s: %q is not a boolean", key, s)
	}
	return &b, nil
}

// Int returns a property as an integer. It accepts a JSON number and a
// numeric string. An Unlimited value is nil.
func (r ExchangeRecord) Int(key string) (*int64, error) {
	s, ok, err := r.str(key)
	if err != nil || !ok {
		return nil, err
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Unlimited") {
		return nil, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: %q is not an integer", key, s)
	}
	return &n, nil
}

var exchangeBytesRe = regexp.MustCompile(`\(([^()]*?)\s*bytes\)`)

// Bytes returns a ByteQuantifiedSize as a number of bytes. Exchange prints a
// size as "25 MB (26,214,400 bytes)"; the digit grouping follows the server's
// culture ("26.214.400" on a German server), so every non-digit inside the
// parentheses is dropped. An Unlimited size is nil.
func (r ExchangeRecord) Bytes(key string) (*int64, error) {
	s, ok, err := r.str(key)
	if err != nil || !ok {
		return nil, err
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Unlimited") {
		return nil, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return &n, nil
	}
	m := exchangeBytesRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("%s: %q is not a size", key, s)
	}
	digits := strings.Map(func(c rune) rune {
		if c >= '0' && c <= '9' {
			return c
		}
		return -1
	}, m[1])
	if digits == "" {
		return nil, fmt.Errorf("%s: %q is not a size", key, s)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: %q is not a size", key, s)
	}
	return &n, nil
}

var exchangeTimeSpanRe = regexp.MustCompile(`^(-)?(?:(\d+)\.)?(\d+):(\d+):(\d+)(?:\.(\d+))?$`)

// Seconds returns a TimeSpan or EnhancedTimeSpan as whole seconds. The string
// form is .NET's constant format, [-][d.]hh:mm:ss[.fffffff], which is the same
// on every culture. An Unlimited value is nil.
func (r ExchangeRecord) Seconds(key string) (*int64, error) {
	s, ok, err := r.str(key)
	if err != nil || !ok {
		return nil, err
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Unlimited") {
		return nil, nil
	}
	n, err := ParseExchangeTimeSpan(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return &n, nil
}

// ParseExchangeTimeSpan parses a .NET TimeSpan in its constant format into
// whole seconds; a fraction of a second is dropped.
func ParseExchangeTimeSpan(s string) (int64, error) {
	m := exchangeTimeSpanRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("%q is not a time span", s)
	}
	var days int64
	if m[2] != "" {
		days, _ = strconv.ParseInt(m[2], 10, 64)
	}
	hours, _ := strconv.ParseInt(m[3], 10, 64)
	minutes, _ := strconv.ParseInt(m[4], 10, 64)
	seconds, _ := strconv.ParseInt(m[5], 10, 64)
	if hours > 23 || minutes > 59 || seconds > 59 {
		return 0, fmt.Errorf("%q is not a time span", s)
	}
	total := days*86400 + hours*3600 + minutes*60 + seconds
	if m[1] == "-" {
		total = -total
	}
	return total, nil
}

// Strings returns a multi-valued property as a list. A single string is a
// one-element list, an absent value an empty one.
func (r ExchangeRecord) Strings(key string) ([]string, error) {
	v, ok := r.raw(key)
	if !ok {
		return []string{}, nil
	}
	var list PSStringArray
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	res := make([]string, 0, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			res = append(res, s)
		}
	}
	return res, nil
}

// Flags returns a flags enum as the list of its set flags. A flags enum
// prints as "Tls, BasicAuth, BasicAuthRequireTLS", and None as "None", which
// is an empty list.
func (r ExchangeRecord) Flags(key string) ([]string, error) {
	s, ok, err := r.str(key)
	if err != nil || !ok {
		return []string{}, err
	}
	res := []string{}
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "None" {
			continue
		}
		res = append(res, part)
	}
	return res, nil
}

// ExchangeRecordReader reads typed values out of a record and keeps the first
// error, so a resource can read a dozen properties and check once.
type ExchangeRecordReader struct {
	Record ExchangeRecord
	Err    error
}

func (x *ExchangeRecordReader) keep(err error) {
	if err != nil && x.Err == nil {
		x.Err = err
	}
}

func (x *ExchangeRecordReader) String(key string) *string {
	v, err := x.Record.String(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Bool(key string) *bool {
	v, err := x.Record.Bool(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Int(key string) *int64 {
	v, err := x.Record.Int(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Bytes(key string) *int64 {
	v, err := x.Record.Bytes(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Seconds(key string) *int64 {
	v, err := x.Record.Seconds(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Strings(key string) []string {
	v, err := x.Record.Strings(key)
	x.keep(err)
	return v
}

func (x *ExchangeRecordReader) Flags(key string) []string {
	v, err := x.Record.Flags(key)
	x.keep(err)
	return v
}
