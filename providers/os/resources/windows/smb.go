// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import "io"

// $ErrorActionPreference is Stop on each of these deliberately.
//
// The SMB cmdlets report a failure as a non-terminating error: they write to
// stderr, write nothing to stdout, and leave the exit status at 0. The
// provider only treats a non-zero exit as a failure, so without the guard a
// cmdlet that could not read anything is indistinguishable from a host that
// genuinely has no shares, no sessions or no connections, and the resource
// reports an empty list either way.
//
// An empty list is the worst possible answer to be wrong with, because every
// assertion made about a collection is satisfied by it: none() and all() both
// pass vacuously, so "no share is exposed to Everyone" passes on a host whose
// share list nobody managed to read.
//
// With the guard the two cases separate cleanly. A cmdlet failure becomes a
// terminating error and PowerShell exits non-zero, which the provider turns
// into an error carrying stderr; a host that genuinely has none still exits 0
// with empty output and still reports an empty list.
const (
	// ShareType is an enum; "$($_.ShareType)" forces its label (e.g.
	// FileSystemDirectory) rather than its numeric value.
	SMB_SHARES = `$ErrorActionPreference='Stop'
Get-SmbShare | Select-Object Name,Path,Description,ScopeName,@{Name='ShareType';Expression={"$($_.ShareType)"}} | ConvertTo-Json`
	SMB_SESSIONS = `$ErrorActionPreference='Stop'
Get-SmbSession | Select-Object SessionId,ClientComputerName,ClientUserName,Dialect,NumOpens | ConvertTo-Json`
	SMB_CONNECTIONS = `$ErrorActionPreference='Stop'
Get-SmbConnection | Select-Object ServerName,ShareName,UserName,Dialect | ConvertTo-Json`
)

type WindowsSmbShare struct {
	Name        string `json:"Name"`
	Path        string `json:"Path"`
	Description string `json:"Description"`
	ScopeName   string `json:"ScopeName"`
	ShareType   string `json:"ShareType"`
}

type WindowsSmbSession struct {
	// SessionId uniquely identifies a session; a single client+user pair can
	// hold multiple concurrent sessions, so it is required to key them apart.
	SessionId          uint64 `json:"SessionId"`
	ClientComputerName string `json:"ClientComputerName"`
	ClientUserName     string `json:"ClientUserName"`
	Dialect            string `json:"Dialect"`
	NumOpens           int64  `json:"NumOpens"`
}

type WindowsSmbConnection struct {
	ServerName string `json:"ServerName"`
	ShareName  string `json:"ShareName"`
	UserName   string `json:"UserName"`
	Dialect    string `json:"Dialect"`
}

func ParseWindowsSmbShares(input io.Reader) ([]WindowsSmbShare, error) {
	return streamDecodeJSONArray[WindowsSmbShare](input)
}

func ParseWindowsSmbSessions(input io.Reader) ([]WindowsSmbSession, error) {
	return streamDecodeJSONArray[WindowsSmbSession](input)
}

func ParseWindowsSmbConnections(input io.Reader) ([]WindowsSmbConnection, error) {
	return streamDecodeJSONArray[WindowsSmbConnection](input)
}
