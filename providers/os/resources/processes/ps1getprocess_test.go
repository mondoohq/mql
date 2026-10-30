// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/processes"
)

func TestWindows2019ServiceParser(t *testing.T) {
	data, err := os.Open("./testdata/windows2019.json")
	require.NoError(t, err)

	procs, err := processes.ParseWindowsProcesses(data)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(procs))

	expected := &processes.WindowsProcess{
		ID:                2736,
		Name:              "cmd",
		Description:       "Windows Command Processor",
		PriorityClass:     32,
		PM:                2424832,
		NPM:               5016,
		CPU:               0,
		VirtualMemorySize: 58183680,
		Responding:        true,
		SessionId:         0,
		StartTime:         "/Date(1587025497287)/",
		TotalProcessorTime: processes.WindowsTotalProcessorTime{
			Ticks:             0,
			Days:              0,
			Hours:             0,
			Milliseconds:      0,
			Minutes:           0,
			Seconds:           0,
			TotalDays:         0,
			TotalHours:        0,
			TotalMilliseconds: 0,
			TotalMinutes:      0,
			TotalSeconds:      0,
		},
		UserName: "Test\\chris",
		Path:     "c:\\windows\\system32\\cmd.exe",
	}
	found := findProcess(procs, 2736)
	assert.EqualValues(t, expected, found)

	expected = &processes.WindowsProcess{
		ID:                3820,
		Name:              "cmd",
		Description:       "Windows Command Processor",
		PriorityClass:     32,
		PM:                2412544,
		NPM:               5016,
		CPU:               0.015625,
		VirtualMemorySize: 58183680,
		Responding:        true,
		SessionId:         0,
		StartTime:         "/Date(1587027060471)/",
		TotalProcessorTime: processes.WindowsTotalProcessorTime{
			Ticks:             156250,
			Days:              0,
			Hours:             0,
			Milliseconds:      15,
			Minutes:           0,
			Seconds:           0,
			TotalDays:         1.808449074074074e-07,
			TotalHours:        4.340277777777778e-06,
			TotalMilliseconds: 15.625,
			TotalMinutes:      0.00026041666666666666,
			TotalSeconds:      0.015625,
		},
		UserName: "Test\\chris",
		Path:     "c:\\windows\\system32\\cmd.exe",
	}
	found = findProcess(procs, 3820)
	assert.EqualValues(t, expected, found)
}

func TestWindows2022ServiceParser(t *testing.T) {
	data, err := os.Open("./testdata/windows2022.json")
	require.NoError(t, err)

	procs, err := processes.ParseWindowsProcesses(data)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(procs))

	expected := &processes.WindowsProcess{
		ID:                2628,
		Name:              "cmd",
		Description:       "Windows Command Processor",
		PriorityClass:     32,
		PM:                4546560,
		NPM:               5976,
		CPU:               0.0625,
		VirtualMemorySize: 63016960,
		Responding:        true,
		SessionId:         0,
		StartTime:         "/Date(1666622681722)/",
		TotalProcessorTime: processes.WindowsTotalProcessorTime{
			Ticks:             625000,
			Days:              0,
			Hours:             0,
			Milliseconds:      62,
			Minutes:           0,
			Seconds:           0,
			TotalDays:         7.2337962962962959e-07,
			TotalHours:        1.7361111111111111e-05,
			TotalMilliseconds: 62.5,
			TotalMinutes:      0.0010416666666666667,
			TotalSeconds:      0.0625,
		},
		UserName: "WIN-E692AR0A0UB\\Administrator",
		Path:     "c:\\windows\\system32\\cmd.exe",
	}
	found := findProcess(procs, 2628)
	assert.EqualValues(t, expected, found)
}

func findProcess(procs []processes.WindowsProcess, id int64) *processes.WindowsProcess {
	for i := range procs {
		if procs[i].ID == id {
			return &procs[i]
		}
	}
	return nil
}
