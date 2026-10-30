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
@(Get-CimInstance -ClassName Win32_LogonSession | ForEach-Object {
  $a = $accounts[$_.LogonId]
  $sid = $null
  if ($a -and $a.Name) {
    try {
      $nt = New-Object System.Security.Principal.NTAccount($a.Domain, $a.Name)
      $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {}
  }
  $start = $null
  if ($_.StartTime) { $start = $_.StartTime.ToUniversalTime().ToString('o') }
  [PSCustomObject]@{
    LogonId = $_.LogonId
    LogonType = [int]$_.LogonType
    AuthenticationPackage = $_.AuthenticationPackage
    StartTime = $start
    AccountName = $a.Name
    AccountDomain = $a.Domain
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
// The set is closed: these are the values SECURITY_LOGON_TYPE defines, and a
// type outside it is reported as an empty name rather than guessed at, so a
// caller can tell an unknown type from a known one.
//
// 1 is absent deliberately. It exists in the enumeration as an internal value
// the LSA never reports on a session.
var logonTypeNames = map[int64]string{
	2:  "Interactive",
	3:  "Network",
	4:  "Batch",
	5:  "Service",
	7:  "Unlock",
	8:  "NetworkCleartext",
	9:  "NewCredentials",
	10: "RemoteInteractive",
	11: "CachedInteractive",
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
