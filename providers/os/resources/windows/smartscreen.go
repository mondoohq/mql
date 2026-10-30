// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Microsoft Defender SmartScreen is configured entirely through policy registry
// values; there is no dedicated cmdlet. We read the well-known policy values for
// the three SmartScreen surfaces (Windows/File Explorer, Microsoft Edge, and
// Microsoft Store apps) in a single PowerShell call and emit a normalized JSON
// object. Missing values serialize as null, which we treat as "not configured".
//
// References:
// https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/

// Get-RegVal returns null only when the key or the value does not exist. Any
// other failure (an access-denied key, a broken provider) stops the script
// with a non-zero exit status, so a read that failed is never reported as
// "not configured".
const smartScreenScript = `
$ErrorActionPreference = 'Stop'
function Get-RegVal($path, $name) {
  try { $k = Get-Item -LiteralPath $path } catch [System.Management.Automation.ItemNotFoundException] { return $null }
  return $k.GetValue($name, $null)
}
$o = [pscustomobject]@{
  EnableSmartScreen                   = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
  ShellSmartScreenLevel               = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
  EdgeSmartScreenEnabled              = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
  EdgeSmartScreenPuaEnabled           = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled'
  EdgePreventOverride                 = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PreventSmartScreenPromptOverride'
  EdgePreventOverrideForFiles         = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'PreventSmartScreenPromptOverrideForFiles'
  StoreAppsEnableWebContentEvaluation = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation'
}
$o | ConvertTo-Json -Compress
`

// SmartScreenSettings holds the raw policy values that drive SmartScreen. Every
// value is a pointer so a missing (null) value is distinguishable from an
// explicit 0 or an empty string.
type SmartScreenSettings struct {
	EnableSmartScreen                   *int64
	ShellSmartScreenLevel               *string
	EdgeSmartScreenEnabled              *int64
	EdgeSmartScreenPuaEnabled           *int64
	EdgePreventOverride                 *int64
	EdgePreventOverrideForFiles         *int64
	StoreAppsEnableWebContentEvaluation *int64
}

// enabledFlag decodes a 0/1 policy DWORD: nil when the value is absent (not
// configured, Windows applies its own default), true for 1, false for any
// other value. Folding "absent" into false made a host without SmartScreen
// policy indistinguishable from one where policy turns SmartScreen off.
func enabledFlag(v *int64) *bool {
	if v == nil {
		return nil
	}
	res := *v == 1
	return &res
}

// ExplorerEnabled reports whether SmartScreen is enabled for Windows/File Explorer.
func (s *SmartScreenSettings) ExplorerEnabled() *bool { return enabledFlag(s.EnableSmartScreen) }

// EdgeEnabled reports whether SmartScreen is enabled for Microsoft Edge.
func (s *SmartScreenSettings) EdgeEnabled() *bool { return enabledFlag(s.EdgeSmartScreenEnabled) }

// EdgePuaEnabled reports whether Edge SmartScreen blocks potentially unwanted apps.
func (s *SmartScreenSettings) EdgePuaEnabled() *bool {
	return enabledFlag(s.EdgeSmartScreenPuaEnabled)
}

// EdgePreventOverrideEnabled reports whether users are prevented from bypassing
// Edge SmartScreen warnings about sites.
func (s *SmartScreenSettings) EdgePreventOverrideEnabled() *bool {
	return enabledFlag(s.EdgePreventOverride)
}

// EdgePreventOverrideForFilesEnabled reports whether users are prevented from
// bypassing Edge SmartScreen warnings about downloads.
func (s *SmartScreenSettings) EdgePreventOverrideForFilesEnabled() *bool {
	return enabledFlag(s.EdgePreventOverrideForFiles)
}

// StoreAppsEnabled reports whether SmartScreen web-content evaluation is enabled
// for Microsoft Store apps.
func (s *SmartScreenSettings) StoreAppsEnabled() *bool {
	return enabledFlag(s.StoreAppsEnableWebContentEvaluation)
}

// GetSmartScreenSettings reads the SmartScreen policy values from the target.
func GetSmartScreenSettings(p shared.Connection) (*SmartScreenSettings, error) {
	c, err := p.RunCommand(powershell.Encode(smartScreenScript))
	if err != nil {
		return nil, err
	}
	stdout, err := io.ReadAll(c.Stdout)
	if err != nil {
		return nil, err
	}
	stderr, _ := io.ReadAll(c.Stderr)
	return smartScreenResult(stdout, c.ExitStatus, stderr)
}

// smartScreenResult turns a raw command result into settings. A non-zero exit
// status is an error, never an empty reading that would turn every field null.
func smartScreenResult(stdout []byte, exitStatus int, stderr []byte) (*SmartScreenSettings, error) {
	if exitStatus != 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = fmt.Sprintf("command exited with status %d", exitStatus)
		}
		return nil, fmt.Errorf("failed to read SmartScreen policy: %s", msg)
	}
	return ParseSmartScreenSettings(stdout)
}

func ParseSmartScreenSettings(data []byte) (*SmartScreenSettings, error) {
	var s SmartScreenSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
