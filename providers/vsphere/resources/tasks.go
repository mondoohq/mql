// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	vmwaretypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

// eventPageSize bounds how many of the most recent events vsphere.events
// returns. vCenter's event stream is effectively unbounded, so we cap it to
// the latest page to keep scans fast and result sets manageable.
const eventPageSize = 1000

func (v *mqlVsphere) scheduledTasks() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	client := conn.Client().Client

	if client.ServiceContent.ScheduledTaskManager == nil {
		return []any{}, nil
	}

	pc := property.DefaultCollector(client)
	var stm mo.ScheduledTaskManager
	if err := pc.RetrieveOne(ctx, *client.ServiceContent.ScheduledTaskManager, []string{"scheduledTask"}, &stm); err != nil {
		return nil, fmt.Errorf("failed to retrieve scheduled task manager: %w", err)
	}
	if len(stm.ScheduledTask) == 0 {
		return []any{}, nil
	}

	var stasks []mo.ScheduledTask
	if err := pc.Retrieve(ctx, stm.ScheduledTask, []string{"info"}, &stasks); err != nil {
		return nil, fmt.Errorf("failed to retrieve scheduled tasks: %w", err)
	}

	res := make([]any, 0, len(stasks))
	for i := range stasks {
		info := stasks[i].Info
		mqlTask, err := CreateResource(v.MqlRuntime, "vsphere.scheduledTask", map[string]*llx.RawData{
			"__id":             llx.StringData(stasks[i].Self.Encode()),
			"moid":             llx.StringData(stasks[i].Self.Encode()),
			"name":             llx.StringData(info.Name),
			"description":      llx.StringData(info.Description),
			"enabled":          llx.BoolData(info.Enabled),
			"schedulerType":    llx.StringData(schedulerType(info.Scheduler)),
			"action":           llx.StringData(actionName(info.Action)),
			"entityMoid":       llx.StringData(info.Entity.Encode()),
			"entityType":       llx.StringData(info.Entity.Type),
			"state":            llx.StringData(string(info.State)),
			"nextRunTime":      llx.TimeDataPtr(info.NextRunTime),
			"prevRunTime":      llx.TimeDataPtr(info.PrevRunTime),
			"lastModifiedTime": llx.TimeData(info.LastModifiedTime),
			"lastModifiedUser": llx.StringData(info.LastModifiedUser),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTask)
	}
	return res, nil
}

// schedulerType maps a vSphere task scheduler to a stable recurrence label.
func schedulerType(s vmwaretypes.BaseTaskScheduler) string {
	switch s.(type) {
	case *vmwaretypes.OnceTaskScheduler:
		return "Once"
	case *vmwaretypes.AfterStartupTaskScheduler:
		return "AfterStartup"
	case *vmwaretypes.HourlyTaskScheduler:
		return "Hourly"
	case *vmwaretypes.DailyTaskScheduler:
		return "Daily"
	case *vmwaretypes.WeeklyTaskScheduler:
		return "Weekly"
	case *vmwaretypes.MonthlyByDayTaskScheduler, *vmwaretypes.MonthlyByWeekdayTaskScheduler:
		return "Monthly"
	default:
		return strings.TrimPrefix(fmt.Sprintf("%T", s), "*types.")
	}
}

// actionName extracts the operation name from a scheduled-task action. The
// common case is a MethodAction naming the vSphere API method to invoke; other
// action kinds fall back to their type name.
func actionName(a vmwaretypes.BaseAction) string {
	switch action := a.(type) {
	case *vmwaretypes.MethodAction:
		return action.Name
	case nil:
		return ""
	default:
		return strings.TrimPrefix(fmt.Sprintf("%T", a), "*types.")
	}
}

func (v *mqlVsphere) recentTasks() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	client := conn.Client().Client

	if client.ServiceContent.TaskManager == nil {
		return []any{}, nil
	}

	pc := property.DefaultCollector(client)
	var tm mo.TaskManager
	if err := pc.RetrieveOne(ctx, *client.ServiceContent.TaskManager, []string{"recentTask"}, &tm); err != nil {
		return nil, fmt.Errorf("failed to retrieve task manager: %w", err)
	}
	if len(tm.RecentTask) == 0 {
		return []any{}, nil
	}

	var tasks []mo.Task
	if err := pc.Retrieve(ctx, tm.RecentTask, []string{"info"}, &tasks); err != nil {
		return nil, fmt.Errorf("failed to retrieve recent tasks: %w", err)
	}

	res := make([]any, 0, len(tasks))
	for i := range tasks {
		info := tasks[i].Info

		var entityMoid, entityType string
		if info.Entity != nil {
			entityMoid = info.Entity.Encode()
			entityType = info.Entity.Type
		}

		errorMessage := ""
		if info.Error != nil {
			errorMessage = info.Error.LocalizedMessage
		}

		mqlTask, err := CreateResource(v.MqlRuntime, "vsphere.task", map[string]*llx.RawData{
			"__id":         llx.StringData(info.Key),
			"key":          llx.StringData(info.Key),
			"operation":    llx.StringData(info.DescriptionId),
			"state":        llx.StringData(string(info.State)),
			"entityMoid":   llx.StringData(entityMoid),
			"entityType":   llx.StringData(entityType),
			"entityName":   llx.StringData(info.EntityName),
			"user":         llx.StringData(taskUser(info.Reason)),
			"queueTime":    llx.TimeData(info.QueueTime),
			"startTime":    llx.TimeDataPtr(info.StartTime),
			"completeTime": llx.TimeDataPtr(info.CompleteTime),
			"progress":     llx.IntData(int64(info.Progress)),
			"cancelable":   llx.BoolData(info.Cancelable),
			"cancelled":    llx.BoolData(info.Cancelled),
			"errorMessage": llx.StringData(errorMessage),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTask)
	}
	return res, nil
}

// taskUser extracts the initiating user from a task reason, returning empty for
// system- or schedule-initiated tasks.
func taskUser(r vmwaretypes.BaseTaskReason) string {
	if u, ok := r.(*vmwaretypes.TaskReasonUser); ok {
		return u.UserName
	}
	return ""
}

func (v *mqlVsphere) events() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	client := conn.Client().Client

	m := event.NewManager(client)
	collector, err := m.CreateCollectorForEvents(ctx, vmwaretypes.EventFilterSpec{})
	if err != nil {
		return nil, fmt.Errorf("failed to create event collector: %w", err)
	}
	defer func() {
		if err := collector.Destroy(ctx); err != nil {
			log.Debug().Err(err).Msg("vsphere> failed to destroy event collector")
		}
	}()

	if err := collector.SetPageSize(ctx, eventPageSize); err != nil {
		return nil, fmt.Errorf("failed to set event page size: %w", err)
	}
	events, err := collector.LatestPage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read events: %w", err)
	}

	res := make([]any, 0, len(events))
	for _, be := range events {
		e := be.GetEvent()
		eventType := strings.TrimPrefix(fmt.Sprintf("%T", be), "*types.")
		category, err := m.EventCategory(ctx, be)
		if err != nil {
			category = ""
		}
		entityMoid, entityName := eventEntity(e)

		mqlEvent, err := CreateResource(v.MqlRuntime, "vsphere.event", map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("vsphere.event/%d", e.Key)),
			"key":         llx.IntData(int64(e.Key)),
			"type":        llx.StringData(eventType),
			"category":    llx.StringData(category),
			"createdTime": llx.TimeData(e.CreatedTime),
			"userName":    llx.StringData(e.UserName),
			"message":     llx.StringData(e.FullFormattedMessage),
			"entityMoid":  llx.StringData(entityMoid),
			"entityName":  llx.StringData(entityName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEvent)
	}
	return res, nil
}

// eventEntity derives the most specific inventory object an event concerns,
// returning its encoded moid and name (empty when the event targets no entity,
// e.g. session logins).
func eventEntity(e *vmwaretypes.Event) (string, string) {
	switch {
	case e.Vm != nil:
		return e.Vm.Vm.Encode(), e.Vm.Name
	case e.Host != nil:
		return e.Host.Host.Encode(), e.Host.Name
	case e.ComputeResource != nil:
		return e.ComputeResource.ComputeResource.Encode(), e.ComputeResource.Name
	case e.Ds != nil:
		return e.Ds.Datastore.Encode(), e.Ds.Name
	case e.Net != nil:
		return e.Net.Network.Encode(), e.Net.Name
	case e.Dvs != nil:
		return e.Dvs.Dvs.Encode(), e.Dvs.Name
	case e.Datacenter != nil:
		return e.Datacenter.Datacenter.Encode(), e.Datacenter.Name
	default:
		return "", ""
	}
}
