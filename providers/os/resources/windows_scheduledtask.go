// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// mqlWindowsScheduledTaskInternal caches the parsed task so the nested
// principal/action/trigger/settings resources can be built from the single
// Get-ScheduledTask call, and memoizes the lazy Get-ScheduledTaskInfo lookup
// that backs the run-time fields.
type mqlWindowsScheduledTaskInternal struct {
	task        windows.WindowsScheduledTask
	infoLock    sync.Mutex
	infoFetched bool
	info        *windows.WindowsScheduledTaskInfo
}

func (w *mqlWindows) scheduledTasks() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	executedCmd, err := conn.RunCommand(powershell.Encode(windows.SCHEDULED_TASKS))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve scheduled tasks: " + string(stderr))
	}

	tasks, err := windows.ParseWindowsScheduledTasks(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(tasks))
	for i := range tasks {
		t := tasks[i]

		enabled := false
		if t.Settings != nil && t.Settings.Enabled != nil {
			enabled = *t.Settings.Enabled
		}

		mqlTask, err := CreateResource(w.MqlRuntime, "windows.scheduledTask", map[string]*llx.RawData{
			"__id":               llx.StringData(scheduledTaskID(t)),
			"name":               llx.StringData(t.Name),
			"path":               llx.StringData(t.Path),
			"uri":                llx.StringData(t.URI),
			"state":              llx.StringData(t.State),
			"enabled":            llx.BoolData(enabled),
			"description":        llx.StringData(t.Description),
			"author":             llx.StringData(t.Author),
			"documentation":      llx.StringData(t.Documentation),
			"securityDescriptor": llx.StringData(t.SecurityDescriptor),
			"source":             llx.StringData(t.Source),
			"date":               llx.TimeDataPtr(parseWindowsTaskTime(t.Date)),
		})
		if err != nil {
			return nil, err
		}

		mqlTask.(*mqlWindowsScheduledTask).task = t
		res = append(res, mqlTask)
	}

	return res, nil
}

// scheduledTaskID returns a stable cache key for a task, preferring its URI and
// falling back to the folder path plus name.
func scheduledTaskID(t windows.WindowsScheduledTask) string {
	if t.URI != "" {
		return t.URI
	}
	return t.Path + t.Name
}

func (t *mqlWindowsScheduledTask) principal() (*mqlWindowsScheduledTaskPrincipal, error) {
	p := t.task.Principal
	if p == nil {
		t.Principal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := CreateResource(t.MqlRuntime, "windows.scheduledTask.principal", map[string]*llx.RawData{
		"__id":        llx.StringData(scheduledTaskID(t.task) + "/principal"),
		"userId":      llx.StringData(p.UserId),
		"groupId":     llx.StringData(p.GroupId),
		"displayName": llx.StringData(p.DisplayName),
		"logonType":   llx.StringData(p.LogonType),
		"runLevel":    llx.StringData(p.RunLevel),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsScheduledTaskPrincipal), nil
}

func (t *mqlWindowsScheduledTask) actions() ([]any, error) {
	id := scheduledTaskID(t.task)
	res := make([]any, 0, len(t.task.Actions))
	for i := range t.task.Actions {
		a := t.task.Actions[i]
		r, err := CreateResource(t.MqlRuntime, "windows.scheduledTask.action", map[string]*llx.RawData{
			"__id":             llx.StringData(id + "/action/" + strconv.Itoa(i)),
			"execute":          llx.StringData(a.Execute),
			"arguments":        llx.StringData(a.Arguments),
			"workingDirectory": llx.StringData(a.WorkingDirectory),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (t *mqlWindowsScheduledTask) triggers() ([]any, error) {
	id := scheduledTaskID(t.task)
	res := make([]any, 0, len(t.task.Triggers))
	for i := range t.task.Triggers {
		tr := t.task.Triggers[i]
		r, err := CreateResource(t.MqlRuntime, "windows.scheduledTask.trigger", map[string]*llx.RawData{
			"__id":                        llx.StringData(id + "/trigger/" + strconv.Itoa(i)),
			"type":                        llx.StringData(normalizeTriggerType(tr.Type)),
			"enabled":                     llx.BoolDataPtr(tr.Enabled),
			"startBoundary":               llx.TimeDataPtr(parseWindowsTaskTime(tr.StartBoundary)),
			"endBoundary":                 llx.TimeDataPtr(parseWindowsTaskTime(tr.EndBoundary)),
			"executionTimeLimit":          llx.StringData(tr.ExecutionTimeLimit),
			"repetitionInterval":          llx.StringData(tr.RepetitionInterval),
			"repetitionDuration":          llx.StringData(tr.RepetitionDuration),
			"repetitionStopAtDurationEnd": llx.BoolDataPtr(tr.RepetitionStopAtDurationEnd),
			"delay":                       llx.StringData(tr.Delay),
			"randomDelay":                 llx.StringData(tr.RandomDelay),
			"daysInterval":                llx.IntDataPtr(tr.DaysInterval),
			"weeksInterval":               llx.IntDataPtr(tr.WeeksInterval),
			"daysOfWeek":                  llx.IntDataPtr(tr.DaysOfWeek),
			"userId":                      llx.StringData(tr.UserId),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (t *mqlWindowsScheduledTask) settings() (*mqlWindowsScheduledTaskSettings, error) {
	s := t.task.Settings
	if s == nil {
		t.Settings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := CreateResource(t.MqlRuntime, "windows.scheduledTask.settings", map[string]*llx.RawData{
		"__id":                            llx.StringData(scheduledTaskID(t.task) + "/settings"),
		"enabled":                         llx.BoolDataPtr(s.Enabled),
		"hidden":                          llx.BoolDataPtr(s.Hidden),
		"allowDemandStart":                llx.BoolDataPtr(s.AllowDemandStart),
		"allowHardTerminate":              llx.BoolDataPtr(s.AllowHardTerminate),
		"startWhenAvailable":              llx.BoolDataPtr(s.StartWhenAvailable),
		"runOnlyIfNetworkAvailable":       llx.BoolDataPtr(s.RunOnlyIfNetworkAvailable),
		"runOnlyIfIdle":                   llx.BoolDataPtr(s.RunOnlyIfIdle),
		"wakeToRun":                       llx.BoolDataPtr(s.WakeToRun),
		"disallowStartIfOnBatteries":      llx.BoolDataPtr(s.DisallowStartIfOnBatteries),
		"stopIfGoingOnBatteries":          llx.BoolDataPtr(s.StopIfGoingOnBatteries),
		"disallowStartOnRemoteAppSession": llx.BoolDataPtr(s.DisallowStartOnRemoteAppSession),
		"restartCount":                    llx.IntDataPtr(s.RestartCount),
		"restartInterval":                 llx.StringData(s.RestartInterval),
		"executionTimeLimit":              llx.StringData(s.ExecutionTimeLimit),
		"multipleInstances":               llx.StringData(s.MultipleInstances),
		"priority":                        llx.IntDataPtr(s.Priority),
		"deleteExpiredTaskAfter":          llx.StringData(s.DeleteExpiredTaskAfter),
		"compatibility":                   llx.StringData(s.Compatibility),
		"idleDuration":                    llx.StringData(s.IdleDuration),
		"idleWaitTimeout":                 llx.StringData(s.IdleWaitTimeout),
		"idleStopOnIdleEnd":               llx.BoolDataPtr(s.IdleStopOnIdleEnd),
		"idleRestartOnIdle":               llx.BoolDataPtr(s.IdleRestartOnIdle),
		"networkId":                       llx.StringData(s.NetworkId),
		"networkName":                     llx.StringData(s.NetworkName),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsScheduledTaskSettings), nil
}

// fetchInfo lazily loads run-time information for this task via a per-task
// Get-ScheduledTaskInfo call, memoizing the result.
func (t *mqlWindowsScheduledTask) fetchInfo() (*windows.WindowsScheduledTaskInfo, error) {
	t.infoLock.Lock()
	defer t.infoLock.Unlock()
	if t.infoFetched {
		return t.info, nil
	}

	conn := t.MqlRuntime.Connection.(shared.Connection)
	cmd := windows.ScheduledTaskInfoScript(t.task.Path, t.task.Name)
	executedCmd, err := conn.RunCommand(powershell.Encode(cmd))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve scheduled task info: " + string(stderr))
	}

	info, err := windows.ParseWindowsScheduledTaskInfo(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	t.info = info
	t.infoFetched = true
	return info, nil
}

func (t *mqlWindowsScheduledTask) lastRunTime() (*time.Time, error) {
	info, err := t.fetchInfo()
	if err != nil {
		return nil, err
	}
	return parseWindowsTaskTime(info.LastRunTime), nil
}

func (t *mqlWindowsScheduledTask) nextRunTime() (*time.Time, error) {
	info, err := t.fetchInfo()
	if err != nil {
		return nil, err
	}
	return parseWindowsTaskTime(info.NextRunTime), nil
}

func (t *mqlWindowsScheduledTask) lastTaskResult() (int64, error) {
	info, err := t.fetchInfo()
	if err != nil {
		return 0, err
	}
	return info.LastTaskResult, nil
}

func (t *mqlWindowsScheduledTask) missedRuns() (int64, error) {
	info, err := t.fetchInfo()
	if err != nil {
		return 0, err
	}
	return info.NumberOfMissedRuns, nil
}

// normalizeTriggerType turns a CIM trigger class name such as
// "MSFT_TaskDailyTrigger" into a friendly discriminator like "daily" or
// "monthlyDOW". An unrecognized or empty class name yields an empty string.
func normalizeTriggerType(cimClass string) string {
	s := strings.TrimPrefix(cimClass, "MSFT_Task")
	s = strings.TrimSuffix(s, "Trigger")
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

// parseWindowsTaskTime parses the date representations emitted by the Task
// Scheduler cmdlets: CIM datetime strings ("2024-01-01T03:00:00"), round-trip
// formatted DateTime values, and the legacy "/Date(ms)/" form. Empty values and
// the Task Scheduler "never ran" sentinel (a pre-1980 date) yield nil so the
// resource surfaces MQL null.
func parseWindowsTaskTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if strings.HasPrefix(value, "/Date(") && strings.HasSuffix(value, ")/") {
		inner := strings.TrimSuffix(strings.TrimPrefix(value, "/Date("), ")/")
		if idx := strings.IndexAny(inner, "+-"); idx > 0 {
			inner = inner[:idx]
		}
		if ms, err := strconv.ParseInt(inner, 10, 64); err == nil {
			tm := time.UnixMilli(ms)
			return normalizeWindowsTaskTime(&tm)
		}
		return nil
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.9999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if tm, err := time.Parse(layout, value); err == nil {
			return normalizeWindowsTaskTime(&tm)
		}
	}
	return nil
}

// taskSchedulerNeverRun is the "never ran" value the Task Scheduler 2.0 API
// reports for a task that has not run: 1999-11-30T00:00:00. It is not a
// plausible run time, but it is recent enough that a pre-1980 cutoff lets it
// through, and every task Windows ships with but never runs carries it. The
// legacy API uses 1899-12-30 instead, which the cutoff does catch.
var taskSchedulerNeverRun = time.Date(1999, time.November, 30, 0, 0, 0, 0, time.UTC)

// normalizeWindowsTaskTime maps the Task Scheduler "never ran" sentinels to
// nil: any pre-1980 date (e.g. 1899-12-30) and the 1999-11-30 value the modern
// API uses.
//
// Reporting the sentinel as a real timestamp is worse than reporting nothing.
// A task that has never run answers "when did this last run" with a concrete
// date, so an audit asserting that a task ran recently sees a value rather
// than a null, and one asserting the field is set passes on a task that has
// never executed.
func normalizeWindowsTaskTime(tm *time.Time) *time.Time {
	if tm == nil || tm.Year() < 1980 {
		return nil
	}
	if tm.UTC().Equal(taskSchedulerNeverRun) {
		return nil
	}
	return tm
}
