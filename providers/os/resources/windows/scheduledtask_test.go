// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// A script that no longer fits on the command line does not fail loudly. The
// target rejects the command before PowerShell runs, and the non-zero exit
// reads like the Task Scheduler being unavailable rather than like a script
// that outgrew the cap — which is how SCHEDULED_TASKS shipped at 3555
// characters (9626 encoded) against an 8191 cap without anyone noticing.
func TestScheduledTasksScriptFitsCommandLine(t *testing.T) {
	scripts := map[string]string{
		"SCHEDULED_TASKS": SCHEDULED_TASKS,
		// Built per task, so measure it with a long real-world path and name.
		"ScheduledTaskInfoScript": ScheduledTaskInfoScript(
			`\Microsoft\Windows\UpdateOrchestrator\`, "Schedule Scan Static Task"),
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			assert.LessOrEqual(t, len(script), powershell.MaxScriptLength,
				"script is too long to be encoded onto a Windows command line; "+
					"split it into two round trips rather than raising the cap")
			// The source-length budget is a proxy. Assert the real constraint too.
			assert.True(t, powershell.FitsCommandLine(script),
				"encoded length %d exceeds the %d character command-line cap",
				len(powershell.Encode(script)), powershell.MaxCommandLength)
		})
	}
}

func TestWindowsScheduledTasks(t *testing.T) {
	r, err := os.Open("./testdata/scheduled-tasks.json")
	require.NoError(t, err)
	defer r.Close()

	tasks, err := ParseWindowsScheduledTasks(r)
	require.NoError(t, err)
	require.Len(t, tasks, 2)

	core := tasks[0]
	assert.Equal(t, "GoogleUpdateTaskMachineCore", core.Name)
	assert.Equal(t, "\\", core.Path)
	assert.Equal(t, "\\GoogleUpdateTaskMachineCore", core.URI)
	assert.Equal(t, "Ready", core.State)

	require.NotNil(t, core.Principal)
	assert.Equal(t, "S-1-5-18", core.Principal.UserId)
	assert.Equal(t, "ServiceAccount", core.Principal.LogonType)
	assert.Equal(t, "Highest", core.Principal.RunLevel)

	require.Len(t, core.Actions, 1)
	assert.Equal(t, "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", core.Actions[0].Execute)
	assert.Equal(t, "/c", core.Actions[0].Arguments)

	require.Len(t, core.Triggers, 1)
	assert.Equal(t, "MSFT_TaskDailyTrigger", core.Triggers[0].Type)
	require.NotNil(t, core.Triggers[0].Enabled)
	assert.True(t, *core.Triggers[0].Enabled)
	require.NotNil(t, core.Triggers[0].DaysInterval)
	assert.Equal(t, int64(1), *core.Triggers[0].DaysInterval)
	assert.Nil(t, core.Triggers[0].WeeksInterval)

	require.NotNil(t, core.Settings)
	require.NotNil(t, core.Settings.Enabled)
	assert.True(t, *core.Settings.Enabled)
	require.NotNil(t, core.Settings.Priority)
	assert.Equal(t, int64(7), *core.Settings.Priority)
	assert.Equal(t, "IgnoreNew", core.Settings.MultipleInstances)

	reboot := tasks[1]
	assert.Equal(t, "RebootScan", reboot.Name)
	assert.Equal(t, "Disabled", reboot.State)
	require.NotNil(t, reboot.Settings)
	require.NotNil(t, reboot.Settings.Enabled)
	assert.False(t, *reboot.Settings.Enabled)
	require.NotNil(t, reboot.Settings.RestartCount)
	assert.Equal(t, int64(3), *reboot.Settings.RestartCount)
	require.Len(t, reboot.Triggers, 1)
	assert.Equal(t, "MSFT_TaskBootTrigger", reboot.Triggers[0].Type)
	assert.Equal(t, "PT5M", reboot.Triggers[0].Delay)
}

func TestWindowsScheduledTasksSingle(t *testing.T) {
	r, err := os.Open("./testdata/scheduled-task-single.json")
	require.NoError(t, err)
	defer r.Close()

	tasks, err := ParseWindowsScheduledTasks(r)
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	assert.Equal(t, "OneShot", tasks[0].Name)
	require.Len(t, tasks[0].Triggers, 1)
	require.NotNil(t, tasks[0].Triggers[0].WeeksInterval)
	assert.Equal(t, int64(2), *tasks[0].Triggers[0].WeeksInterval)
	require.NotNil(t, tasks[0].Triggers[0].DaysOfWeek)
	assert.Equal(t, int64(62), *tasks[0].Triggers[0].DaysOfWeek)
}

func TestWindowsScheduledTaskInfo(t *testing.T) {
	r, err := os.Open("./testdata/scheduled-task-info.json")
	require.NoError(t, err)
	defer r.Close()

	info, err := ParseWindowsScheduledTaskInfo(r)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.LastTaskResult)
	assert.Equal(t, int64(2), info.NumberOfMissedRuns)
	assert.NotEmpty(t, info.LastRunTime)
	assert.NotEmpty(t, info.NextRunTime)
}

func TestWindowsScheduledTaskInfoEmpty(t *testing.T) {
	info, err := ParseWindowsScheduledTaskInfo(strings.NewReader("   "))
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.LastTaskResult)
}

func TestScheduledTaskInfoScriptEscaping(t *testing.T) {
	cmd := ScheduledTaskInfoScript("\\Custom\\", "O'Brien's Task")
	assert.Contains(t, cmd, "-TaskPath '\\Custom\\'")
	assert.Contains(t, cmd, "-TaskName 'O''Brien''s Task'")
}
