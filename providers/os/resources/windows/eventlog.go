// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// errEmptyEventLogChannel is returned when the command produced no object at
// all. Reporting a zero value instead would say the channel is disabled and
// holds no events, which is the reading that makes an audit pass on a channel
// nobody managed to look at.
var errEmptyEventLogChannel = errors.New("no Event Log channel information was returned")

// EventLogChannelScript builds the PowerShell that reads the live state of one
// Event Log channel.
//
// Get-WinEvent -ListLog is used rather than the registry because it reaches
// every channel by the same name a user writes. The classic logs are
// configured under Services\EventLog, but a modern provider channel such as
// Microsoft-Windows-PowerShell/Operational is not there at all, and reading
// only that key reports a modern channel as absent rather than as
// unconfigured.
//
// The stored LogFilePath carries %SystemRoot% unexpanded, which cannot be
// handed to file or windows.acl as it stands. The expansion is deliberately
// not done here with [System.Environment]::ExpandEnvironmentVariables: a
// static method call is refused in ConstrainedLanguage mode, which WDAC and
// AppLocker put a host into, and the refusal fails the whole payload rather
// than just that one value. The system root is carried out as data instead and
// the substitution happens in Go, where it is also testable.
//
// A name that matches no channel makes the command fail, which is the right
// answer: "there is no such channel" must not read as "the channel is
// disabled".
func EventLogChannelScript(name string) string {
	return `$ErrorActionPreference='Stop'
$l=Get-WinEvent -ListLog ` + powershell.SingleQuote(name) + ` -ErrorAction Stop
[ordered]@{
LogName=[string]$l.LogName
IsEnabled=[bool]$l.IsEnabled
MaximumSizeInBytes=$(if($null -eq $l.MaximumSizeInBytes){0}else{[int64]$l.MaximumSizeInBytes})
IsClassicLog=[bool]$l.IsClassicLog
LogFilePath=[string]$l.LogFilePath
SystemRoot=[string]$env:SystemRoot
RecordCount=$(if($null -eq $l.RecordCount){0}else{[int64]$l.RecordCount})
LogMode=[string]$l.LogMode
}|ConvertTo-Json -Depth 3 -Compress`
}

// expandWindowsPath resolves the environment variables an Event Log channel
// path is stored with, against the system root the target reported.
//
// Only the two that Windows actually stores a channel path with are handled,
// and the match is case insensitive because the registry value and the
// documentation disagree on the casing. A path referencing anything else is
// returned as it stands rather than half expanded, so a caller can still see
// what the channel is configured with.
func expandWindowsPath(path, systemRoot string) string {
	if systemRoot == "" {
		return path
	}
	systemRoot = strings.TrimRight(systemRoot, `\`)
	for _, v := range []string{"%SystemRoot%", "%windir%"} {
		for {
			i := strings.Index(strings.ToLower(path), strings.ToLower(v))
			if i < 0 {
				break
			}
			path = path[:i] + systemRoot + path[i+len(v):]
		}
	}
	return path
}

// EventLogChannel is the live state of one Event Log channel.
type EventLogChannel struct {
	LogName      string `json:"LogName"`
	IsEnabled    bool   `json:"IsEnabled"`
	IsClassicLog bool   `json:"IsClassicLog"`
	// MaximumSizeInBytes is the effective maximum size, which includes the
	// value a channel's manifest declares. The registry holds overrides only,
	// so a channel left at its manifest default has no registry value at all
	// and this is the only source that reports its real size.
	MaximumSizeInBytes int64 `json:"MaximumSizeInBytes"`
	// LogFilePath is the path of the backing .evtx file as stored, which
	// carries %SystemRoot% unexpanded. Read it through ExpandedLogFilePath.
	LogFilePath string `json:"LogFilePath"`
	// SystemRoot is the target's Windows directory, carried out as data so
	// the path can be expanded without a static method call the target may
	// refuse.
	SystemRoot string `json:"SystemRoot"`
	// RecordCount is 0 both on a channel that was cleared and on one that
	// never collected anything, which is why it is only meaningful read
	// together with IsEnabled.
	RecordCount int64 `json:"RecordCount"`
	// LogMode is the effective retention behavior Windows resolved for the
	// channel: Circular, AutoBackup or Retain. It is the only source that
	// covers a modern provider channel left at its manifest default, where
	// neither the classic Services\EventLog key nor an override exists.
	LogMode string `json:"LogMode"`
}

// ExpandedLogFilePath is the full path of the backing .evtx file, with the
// environment variables it is stored with resolved against the target's own
// system root.
func (c *EventLogChannel) ExpandedLogFilePath() string {
	return expandWindowsPath(c.LogFilePath, c.SystemRoot)
}

// ParseEventLogChannel decodes the JSON emitted by EventLogChannelScript.
func ParseEventLogChannel(r io.Reader) (*EventLogChannel, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errEmptyEventLogChannel
	}

	var res EventLogChannel
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
