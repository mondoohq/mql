// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/monitoring"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciMonitoring) id() (string, error) {
	return "oci.monitoring", nil
}

func (o *mqlOciMonitoring) alarms() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeSubtree,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci monitoring with region %s", region)

			admit, err := ociCompartmentAdmitter(ctx, conn)
			if err != nil {
				return nil, err
			}

			svc, err := conn.MonitoringClient(region)
			if err != nil {
				return nil, err
			}

			alarms, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]monitoring.AlarmSummary, *string, error) {
				response, err := svc.ListAlarms(ctx, monitoring.ListAlarmsRequest{
					CompartmentId: common.String(compartmentID),
					// Alarms are normally created in a workload compartment,
					// not the tenancy root.
					CompartmentIdInSubtree: common.Bool(true),
					Page:                   page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range alarms {
				alarm := alarms[i]
				if !admit(stringValue(alarm.CompartmentId)) {
					continue
				}

				destinations := make([]any, 0, len(alarm.Destinations))
				for _, d := range alarm.Destinations {
					destinations = append(destinations, d)
				}

				// A suppression is one optional struct on the alarm, so its
				// bounds are flattened onto it. Left as pointers so an alarm
				// with no suppression reports null on all three rather than a
				// window starting at the zero time, which would read as a
				// suppression that has been in force since year one.
				var suppressFrom, suppressUntil *time.Time
				var suppressDescription *string
				if alarm.Suppression != nil {
					if alarm.Suppression.TimeSuppressFrom != nil {
						t := alarm.Suppression.TimeSuppressFrom.Time
						suppressFrom = &t
					}
					if alarm.Suppression.TimeSuppressUntil != nil {
						t := alarm.Suppression.TimeSuppressUntil.Time
						suppressUntil = &t
					}
					suppressDescription = alarm.Suppression.Description
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.monitoring.alarm", stringValue(alarm.CompartmentId), map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(alarm.Id),
					"name":                   llx.StringDataPtr(alarm.DisplayName),
					"metricCompartmentId":    llx.StringDataPtr(alarm.MetricCompartmentId),
					"namespace":              llx.StringDataPtr(alarm.Namespace),
					"query":                  llx.StringDataPtr(alarm.Query),
					"severity":               llx.StringData(string(alarm.Severity)),
					"destinations":           llx.ArrayData(destinations, types.String),
					"suppressionFrom":        llx.TimeDataPtr(suppressFrom),
					"suppressionUntil":       llx.TimeDataPtr(suppressUntil),
					"suppressionDescription": llx.StringDataPtr(suppressDescription),
					"isEnabled":              llx.BoolDataPtr(alarm.IsEnabled),
					"state":                  llx.StringData(string(alarm.LifecycleState)),
					"freeformTags":           llx.MapData(strMapToAny(alarm.FreeformTags), types.String),
					"definedTags":            llx.MapData(definedTagsToAny(alarm.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlOciMonitoringAlarm).cacheDestinations = destinations
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciMonitoringAlarm) id() (string, error) {
	return "oci.monitoring.alarm/" + o.Id.Data, nil
}

// isSuppressed reports whether the alarm's notifications are silenced right
// now.
//
// An alarm under suppression still reports isEnabled true while sending
// nothing, so without this a silenced control is indistinguishable from a live
// one.
func (o *mqlOciMonitoringAlarm) isSuppressed() (bool, error) {
	from := o.GetSuppressionFrom()
	if from.Error != nil {
		return false, from.Error
	}
	until := o.GetSuppressionUntil()
	if until.Error != nil {
		return false, until.Error
	}
	return ociAlarmSuppressed(from.Data, until.Data, time.Now()), nil
}

// ociAlarmSuppressed reports whether a suppression window covers now.
//
// Both bounds are mandatory on an OCI suppression, so a missing one means the
// alarm carries no suppression at all rather than a window open at that end.
// Treating a half-window as open-ended would report an alarm as permanently
// silenced on the strength of a field the service never sent.
func ociAlarmSuppressed(from, until *time.Time, now time.Time) bool {
	if from == nil || until == nil {
		return false
	}
	// Both bounds are inclusive, per the service's own description of them.
	return !now.Before(*from) && !now.After(*until)
}
