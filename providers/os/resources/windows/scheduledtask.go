// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"io"
	"strings"
)

// SCHEDULED_TASKS projects every registered Task Scheduler task into a stable
// JSON shape. Enum-typed properties (State, LogonType, RunLevel,
// MultipleInstances, Compatibility) are stringified via "$(...)" so they
// serialize as their names rather than raw integers, and the polymorphic
// trigger objects are flattened into a single union shape keyed by their CIM
// class name: Select-Object yields null for a property the concrete trigger
// class does not carry.
//
// The script has to stay under powershell.MaxScriptLength. It is passed to the
// target base64-encoded as UTF-16, so it arrives roughly three times its source
// length against a fixed command-line cap, and a script that overruns the cap
// fails in a way that reads like the Task Scheduler being unavailable rather
// than like a script that is too long. TestScheduledTasksScriptFitsCommandLine
// guards the budget; if a property has to be added and the script no longer
// fits, split it into two round trips rather than raising the cap.
//
// Property lists are spelled out and cmdlets are named in full deliberately.
// Aliases (%, ?, gci) can be absent or redefined under Constrained Language
// Mode and JEA, which is exactly where this resource is used.
const SCHEDULED_TASKS = `
$ErrorActionPreference = 'Stop'
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $p = $t.Principal
  $s = $t.Settings
  [PSCustomObject]@{
    Name = $t.TaskName
    Path = $t.TaskPath
    URI = $t.URI
    State = "$($t.State)"
    Description = $t.Description
    Author = $t.Author
    Documentation = $t.Documentation
    SecurityDescriptor = $t.SecurityDescriptor
    Source = $t.Source
    Date = $t.Date
    Principal = if ($p) {
      $p | Select-Object UserId, GroupId, DisplayName,
        @{ Name = 'LogonType'; Expression = { "$($_.LogonType)" } },
        @{ Name = 'RunLevel'; Expression = { "$($_.RunLevel)" } }
    } else { $null }
    Actions = @($t.Actions | Select-Object Execute, Arguments, WorkingDirectory)
    Triggers = @($t.Triggers | Select-Object @{ Name = 'Type'; Expression = { $_.CimClass.CimClassName } },
      Enabled, StartBoundary, EndBoundary, ExecutionTimeLimit,
      @{ Name = 'RepetitionInterval'; Expression = { $_.Repetition.Interval } },
      @{ Name = 'RepetitionDuration'; Expression = { $_.Repetition.Duration } },
      @{ Name = 'RepetitionStopAtDurationEnd'; Expression = { $_.Repetition.StopAtDurationEnd } },
      Delay, RandomDelay, DaysInterval, WeeksInterval, DaysOfWeek, UserId)
    Settings = if ($s) {
      $s | Select-Object Enabled, Hidden, AllowDemandStart, AllowHardTerminate,
        StartWhenAvailable, RunOnlyIfNetworkAvailable, RunOnlyIfIdle, WakeToRun,
        DisallowStartIfOnBatteries, StopIfGoingOnBatteries, DisallowStartOnRemoteAppSession,
        RestartCount, RestartInterval, ExecutionTimeLimit,
        @{ Name = 'MultipleInstances'; Expression = { "$($_.MultipleInstances)" } },
        Priority, DeleteExpiredTaskAfter,
        @{ Name = 'Compatibility'; Expression = { "$($_.Compatibility)" } },
        @{ Name = 'IdleDuration'; Expression = { $_.IdleSettings.IdleDuration } },
        @{ Name = 'IdleWaitTimeout'; Expression = { $_.IdleSettings.WaitTimeout } },
        @{ Name = 'IdleStopOnIdleEnd'; Expression = { $_.IdleSettings.StopOnIdleEnd } },
        @{ Name = 'IdleRestartOnIdle'; Expression = { $_.IdleSettings.RestartOnIdle } },
        @{ Name = 'NetworkId'; Expression = { $_.NetworkSettings.Id } },
        @{ Name = 'NetworkName'; Expression = { $_.NetworkSettings.Name } }
    } else { $null }
  }
} | ConvertTo-Json -Depth 5`

// WindowsScheduledTask is the projected JSON shape of a single Task Scheduler
// task. Pointer fields distinguish "absent" from a zero value so the resource
// layer can surface MQL null for properties the task does not set.
type WindowsScheduledTask struct {
	Name               string                         `json:"Name"`
	Path               string                         `json:"Path"`
	URI                string                         `json:"URI"`
	State              string                         `json:"State"`
	Description        string                         `json:"Description"`
	Author             string                         `json:"Author"`
	Documentation      string                         `json:"Documentation"`
	SecurityDescriptor string                         `json:"SecurityDescriptor"`
	Source             string                         `json:"Source"`
	Date               string                         `json:"Date"`
	Principal          *WindowsScheduledTaskPrincipal `json:"Principal"`
	Actions            []WindowsScheduledTaskAction   `json:"Actions"`
	Triggers           []WindowsScheduledTaskTrigger  `json:"Triggers"`
	Settings           *WindowsScheduledTaskSettings  `json:"Settings"`
}

type WindowsScheduledTaskPrincipal struct {
	UserId      string `json:"UserId"`
	GroupId     string `json:"GroupId"`
	DisplayName string `json:"DisplayName"`
	LogonType   string `json:"LogonType"`
	RunLevel    string `json:"RunLevel"`
}

type WindowsScheduledTaskAction struct {
	Execute          string `json:"Execute"`
	Arguments        string `json:"Arguments"`
	WorkingDirectory string `json:"WorkingDirectory"`
}

type WindowsScheduledTaskTrigger struct {
	Type                        string `json:"Type"`
	Enabled                     *bool  `json:"Enabled"`
	StartBoundary               string `json:"StartBoundary"`
	EndBoundary                 string `json:"EndBoundary"`
	ExecutionTimeLimit          string `json:"ExecutionTimeLimit"`
	RepetitionInterval          string `json:"RepetitionInterval"`
	RepetitionDuration          string `json:"RepetitionDuration"`
	RepetitionStopAtDurationEnd *bool  `json:"RepetitionStopAtDurationEnd"`
	Delay                       string `json:"Delay"`
	RandomDelay                 string `json:"RandomDelay"`
	DaysInterval                *int64 `json:"DaysInterval"`
	WeeksInterval               *int64 `json:"WeeksInterval"`
	DaysOfWeek                  *int64 `json:"DaysOfWeek"`
	UserId                      string `json:"UserId"`
}

type WindowsScheduledTaskSettings struct {
	Enabled                         *bool  `json:"Enabled"`
	Hidden                          *bool  `json:"Hidden"`
	AllowDemandStart                *bool  `json:"AllowDemandStart"`
	AllowHardTerminate              *bool  `json:"AllowHardTerminate"`
	StartWhenAvailable              *bool  `json:"StartWhenAvailable"`
	RunOnlyIfNetworkAvailable       *bool  `json:"RunOnlyIfNetworkAvailable"`
	RunOnlyIfIdle                   *bool  `json:"RunOnlyIfIdle"`
	WakeToRun                       *bool  `json:"WakeToRun"`
	DisallowStartIfOnBatteries      *bool  `json:"DisallowStartIfOnBatteries"`
	StopIfGoingOnBatteries          *bool  `json:"StopIfGoingOnBatteries"`
	DisallowStartOnRemoteAppSession *bool  `json:"DisallowStartOnRemoteAppSession"`
	RestartCount                    *int64 `json:"RestartCount"`
	RestartInterval                 string `json:"RestartInterval"`
	ExecutionTimeLimit              string `json:"ExecutionTimeLimit"`
	MultipleInstances               string `json:"MultipleInstances"`
	Priority                        *int64 `json:"Priority"`
	DeleteExpiredTaskAfter          string `json:"DeleteExpiredTaskAfter"`
	Compatibility                   string `json:"Compatibility"`
	IdleDuration                    string `json:"IdleDuration"`
	IdleWaitTimeout                 string `json:"IdleWaitTimeout"`
	IdleStopOnIdleEnd               *bool  `json:"IdleStopOnIdleEnd"`
	IdleRestartOnIdle               *bool  `json:"IdleRestartOnIdle"`
	NetworkId                       string `json:"NetworkId"`
	NetworkName                     string `json:"NetworkName"`
}

// ParseWindowsScheduledTasks decodes the JSON emitted by SCHEDULED_TASKS,
// handling the PowerShell quirk where a single task is emitted as a bare
// object rather than a one-element array.
func ParseWindowsScheduledTasks(input io.Reader) ([]WindowsScheduledTask, error) {
	return streamDecodeJSONArray[WindowsScheduledTask](input)
}

// WindowsScheduledTaskInfo is the projected JSON shape of Get-ScheduledTaskInfo
// for a single task.
type WindowsScheduledTaskInfo struct {
	LastRunTime        string `json:"LastRunTime"`
	NextRunTime        string `json:"NextRunTime"`
	LastTaskResult     int64  `json:"LastTaskResult"`
	NumberOfMissedRuns int64  `json:"NumberOfMissedRuns"`
}

// ScheduledTaskInfoScript builds a per-task Get-ScheduledTaskInfo query. Run-time
// values aren't part of Get-ScheduledTask, so they are fetched lazily, one task
// at a time, on first access of a run-time field. DateTime values are formatted
// round-trip ("o") for stable parsing.
func ScheduledTaskInfoScript(taskPath, taskName string) string {
	var b strings.Builder
	b.WriteString("Get-ScheduledTaskInfo -TaskPath '")
	b.WriteString(escapePSSingleQuote(taskPath))
	b.WriteString("' -TaskName '")
	b.WriteString(escapePSSingleQuote(taskName))
	b.WriteString("' | ForEach-Object { [PSCustomObject]@{")
	b.WriteString(" LastRunTime = if ($_.LastRunTime) { $_.LastRunTime.ToString('o') } else { $null };")
	b.WriteString(" NextRunTime = if ($_.NextRunTime) { $_.NextRunTime.ToString('o') } else { $null };")
	b.WriteString(" LastTaskResult = $_.LastTaskResult;")
	b.WriteString(" NumberOfMissedRuns = $_.NumberOfMissedRuns")
	b.WriteString(" } } | ConvertTo-Json")
	return b.String()
}

// escapePSSingleQuote escapes a value for inclusion inside a PowerShell
// single-quoted string literal, where the only metacharacter is the single
// quote itself (doubled to escape).
func escapePSSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// ParseWindowsScheduledTaskInfo decodes the JSON emitted by
// ScheduledTaskInfoScript. An empty payload (task without run-time info)
// yields a zero-valued struct.
func ParseWindowsScheduledTaskInfo(input io.Reader) (*WindowsScheduledTaskInfo, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &WindowsScheduledTaskInfo{}, nil
	}
	info := &WindowsScheduledTaskInfo{}
	if err := json.Unmarshal(data, info); err != nil {
		return nil, err
	}
	return info, nil
}
