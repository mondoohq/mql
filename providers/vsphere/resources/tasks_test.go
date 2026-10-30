// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	vmwaretypes "github.com/vmware/govmomi/vim25/types"

	"github.com/stretchr/testify/assert"
)

func TestSchedulerType(t *testing.T) {
	cases := []struct {
		sched vmwaretypes.BaseTaskScheduler
		want  string
	}{
		{&vmwaretypes.OnceTaskScheduler{}, "Once"},
		{&vmwaretypes.AfterStartupTaskScheduler{}, "AfterStartup"},
		{&vmwaretypes.HourlyTaskScheduler{}, "Hourly"},
		{&vmwaretypes.DailyTaskScheduler{}, "Daily"},
		{&vmwaretypes.WeeklyTaskScheduler{}, "Weekly"},
		{&vmwaretypes.MonthlyByDayTaskScheduler{}, "Monthly"},
		{&vmwaretypes.MonthlyByWeekdayTaskScheduler{}, "Monthly"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, schedulerType(c.sched))
	}
}

func TestActionName(t *testing.T) {
	assert.Equal(t, "PowerOnVM_Task", actionName(&vmwaretypes.MethodAction{Name: "PowerOnVM_Task"}))
	assert.Equal(t, "", actionName(nil))
	// non-method actions fall back to their type name
	assert.Equal(t, "RunScriptAction", actionName(&vmwaretypes.RunScriptAction{}))
}

func TestTaskUser(t *testing.T) {
	assert.Equal(t, "DOMAIN\\admin", taskUser(&vmwaretypes.TaskReasonUser{UserName: "DOMAIN\\admin"}))
	// system- and schedule-initiated tasks have no user
	assert.Equal(t, "", taskUser(&vmwaretypes.TaskReasonSystem{}))
	assert.Equal(t, "", taskUser(&vmwaretypes.TaskReasonSchedule{}))
}

func TestEventEntity(t *testing.T) {
	t.Run("vm takes precedence and yields moid+name", func(t *testing.T) {
		moid, name := eventEntity(&vmwaretypes.Event{
			Vm: &vmwaretypes.VmEventArgument{
				Name: "web-01",
				Vm:   vmwaretypes.ManagedObjectReference{Type: "VirtualMachine", Value: "vm-42"},
			},
		})
		assert.Equal(t, "web-01", name)
		assert.Contains(t, moid, "vm-42")
	})

	t.Run("host entity", func(t *testing.T) {
		moid, name := eventEntity(&vmwaretypes.Event{
			Host: &vmwaretypes.HostEventArgument{
				Name: "esxi-1",
				Host: vmwaretypes.ManagedObjectReference{Type: "HostSystem", Value: "host-9"},
			},
		})
		assert.Equal(t, "esxi-1", name)
		assert.Contains(t, moid, "host-9")
	})

	t.Run("entity-less event (e.g. session login) yields empty", func(t *testing.T) {
		moid, name := eventEntity(&vmwaretypes.Event{})
		assert.Equal(t, "", moid)
		assert.Equal(t, "", name)
	})
}
