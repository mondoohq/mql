// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// LogonSessionsScript enumerates the active logon sessions and the account
// each one authenticated as.
//
// Two classes are needed. Win32_LogonSession carries the session itself but
// names no account; Win32_LoggedOnUser is the association that ties a session
// to one. The association is read first into a lookup so the sessions are
// walked once rather than queried per session.
//
// A session can be associated with more than one account record. The first
// wins: the duplicates describe the same principal reached by different
// paths, so picking between them would report a difference that does not
// exist.
//
// The SID is translated rather than read, because neither class carries one.
// Translation reaches the domain controller for a domain account and fails
// when it is unreachable, so it is guarded and the SID is simply absent in
// that case rather than failing the whole collection.
//
// Win32_LoggedOnUser names the machine as the domain of every account the
// system creates (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, IUSR, DWM-1,
// UMFD-0, an IIS application pool), and machine\SYSTEM does not translate.
// For an account under the machine's name that did not translate, the SID is
// read from the Win32_SystemAccount instance the association points at, which
// carries it and does not depend on the display language. The virtual
// accounts are not system accounts in WMI, so they are translated under the
// authorities that own them. The domain is then read back from the SID, so
// SYSTEM reports NT AUTHORITY rather than the machine name. The fallback only
// runs for the machine's own name: a domain account that did not translate
// keeps an absent SID rather than being matched by name to another account.
//
// ConvertTo-Json is forced to a list with @(): PowerShell serializes a single
// object as an object rather than a one-element array, which would otherwise
// need two parse paths.
const LogonSessionsScript = `
$ErrorActionPreference = 'SilentlyContinue'
$accounts = @{}
Get-CimInstance -ClassName Win32_LoggedOnUser | ForEach-Object {
  $id = $_.Dependent.LogonId
  if ($id -and -not $accounts.ContainsKey($id)) {
    $accounts[$id] = $_.Antecedent
  }
}
function Get-AccountSid($domain, $name) {
  try {
    (New-Object System.Security.Principal.NTAccount($domain, $name)).Translate([System.Security.Principal.SecurityIdentifier])
  } catch { $null }
}
$authorities = @('Window Manager', 'Font Driver Host', 'IIS APPPOOL', 'NT SERVICE')
@(Get-CimInstance -ClassName Win32_LogonSession | ForEach-Object {
  $a = $accounts[$_.LogonId]
  $sid = $null
  $domain = $a.Domain
  if ($a -and $a.Name) {
    $s = Get-AccountSid $a.Domain $a.Name
    if (-not $s -and $a.Domain -eq $env:COMPUTERNAME) {
      $c = Get-CimInstance -InputObject $a
      if ($c.SID) {
        try { $s = New-Object System.Security.Principal.SecurityIdentifier($c.SID) } catch {}
      }
      foreach ($d in $authorities) {
        if ($s) { break }
        $s = Get-AccountSid $d $a.Name
      }
      if ($s) {
        try { $domain = $s.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[0] } catch {}
      }
    }
    if ($s) { $sid = $s.Value }
  }
  $start = $null
  if ($_.StartTime) { $start = $_.StartTime.ToUniversalTime().ToString('o') }
  [PSCustomObject]@{
    LogonId = $_.LogonId
    LogonType = [int]$_.LogonType
    AuthenticationPackage = $_.AuthenticationPackage
    StartTime = $start
    AccountName = $a.Name
    AccountDomain = $domain
    Sid = $sid
  }
}) | ConvertTo-Json -Compress -Depth 3
`

// LogonSession is one active logon session as the LSA reports it.
type LogonSession struct {
	// LogonId is the LUID the LSA assigned, as WMI reports it: the decimal
	// low part, e.g. "999" for the session created at boot. Unique for the
	// life of the boot and reused after a restart.
	LogonId string `json:"LogonId"`
	// LogonType is the documented Win32 logon type. See LogonTypeName.
	LogonType int64 `json:"LogonType"`
	// AuthenticationPackage is "Kerberos", "NTLM", "Negotiate" and so on.
	AuthenticationPackage string `json:"AuthenticationPackage"`
	// StartTime is nil when the LSA reported no start time, which is normal
	// for some of the sessions created at boot. It must stay nil rather than
	// becoming the zero time, which would report a session as having started
	// in year 1.
	StartTime     *time.Time `json:"-"`
	AccountName   string     `json:"AccountName"`
	AccountDomain string     `json:"AccountDomain"`
	// Sid is empty when the account could not be translated, which happens for
	// a domain account while the domain is unreachable.
	Sid string `json:"Sid"`
}

// logonTypeNames maps the documented Win32 logon types to their names.
//
// The set is closed: these are the names the Win32_LogonSession documentation
// gives, and a type outside it has no name rather than a guessed one, so a
// caller can tell an unknown type from a known one.
//
// 0 is absent deliberately: the documentation describes it as used only by
// the System account and gives it no name. 1 is an internal value the LSA
// never reports on a session.
var logonTypeNames = map[int64]string{
	2:  "Interactive",
	3:  "Network",
	4:  "Batch",
	5:  "Service",
	6:  "Proxy",
	7:  "Unlock",
	8:  "NetworkCleartext",
	9:  "NewCredentials",
	10: "RemoteInteractive",
	11: "CachedInteractive",
	12: "CachedRemoteInteractive",
	13: "CachedUnlock",
}

// LogonTypeName renders a logon type as its documented name, empty for a type
// outside the documented set.
func LogonTypeName(logonType int64) string {
	return logonTypeNames[logonType]
}

// ParseLogonSessions reads the script's output.
//
// An empty document is not an error: a target that reported no sessions
// legitimately has none to report.
func ParseLogonSessions(r io.Reader) ([]LogonSession, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return []LogonSession{}, nil
	}

	// StartTime is decoded separately so that an absent value stays nil. A
	// time.Time field would decode a missing timestamp to the zero time, which
	// reports every such session as having started in year 1.
	var raw []struct {
		LogonSession
		StartTime *string `json:"StartTime"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, errors.New("failed to parse logon sessions: " + err.Error())
	}

	out := make([]LogonSession, 0, len(raw))
	for _, r := range raw {
		s := r.LogonSession
		if r.StartTime != nil && strings.TrimSpace(*r.StartTime) != "" {
			if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*r.StartTime)); err == nil {
				s.StartTime = &t
			}
		}
		out = append(out, s)
	}
	return out, nil
}
