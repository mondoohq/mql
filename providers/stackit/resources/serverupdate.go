// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	serverupdate "github.com/stackitcloud/stackit-sdk-go/services/serverupdate/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ------------------------- server update service -------------------------

// updateServiceEnabled reports whether the Server Update service is turned on
// for this server, which separates "no update runs because the service is
// off" from "no runs yet". Null when the service does not know the server
// (404) or the credential cannot read it.
func (r *mqlStackitServer) updateServiceEnabled() (bool, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerUpdate()
	if err != nil {
		return false, err
	}
	resp, err := client.DefaultAPI.GetServiceResource(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return nullBool(&r.UpdateServiceEnabled)
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return nullBool(&r.UpdateServiceEnabled)
			}
			return false, refusal(err)
		}
		return false, err
	}
	enabled, ok := resp.GetEnabledOk()
	if !ok || enabled == nil {
		return nullBool(&r.UpdateServiceEnabled)
	}
	return *enabled, nil
}

// serverUpdatePolicies lists the project's update policies: the named
// cadence-and-maintenance-window templates a server update schedule can be
// created from, including which one applies by default.
func (r *mqlStackit) serverUpdatePolicies() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerUpdate()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUpdatePolicies(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.server.updatePolicy", serverUpdatePolicyArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// serverUpdatePolicyArgs maps an update policy onto stackit.server.updatePolicy.
// The enabled and default flags and the maintenance window stay tri-state.
func serverUpdatePolicyArgs(p *serverupdate.UpdatePolicy) map[string]*llx.RawData {
	var window *int64
	if v, ok := p.GetMaintenanceWindowOk(); ok && v != nil {
		hours := int64(*v)
		window = &hours
	}
	return map[string]*llx.RawData{
		"id":                llx.StringData(p.GetId()),
		"name":              llx.StringData(p.GetName()),
		"description":       llx.StringData(p.GetDescription()),
		"enabled":           llx.BoolDataPtr(optBool(p.GetEnabledOk())),
		"default":           llx.BoolDataPtr(optBool(p.GetDefaultOk())),
		"rrule":             llx.StringData(p.GetRrule()),
		"maintenanceWindow": llx.IntDataPtr(window),
	}
}

func (r *mqlStackitServerUpdatePolicy) id() (string, error) {
	return "stackit.server.updatePolicy/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Id.Data, nil
}

// ------------------------- server updates -------------------------

func (r *mqlStackitServer) updates() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerUpdate()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUpdates(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			// A 404 means the Server Update service is not enabled for this
			// server, a legitimate "no updates" state rather than an error.
			return []any{}, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildServerUpdate(r.MqlRuntime, r.Id.Data, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildServerUpdate(runtime *plugin.Runtime, serverID string, u *serverupdate.Update) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"id":               llx.IntData(u.GetId()),
		"serverId":         llx.StringData(serverID),
		"status":           llx.StringData(u.GetStatus()),
		"startDate":        llx.TimeDataPtr(parseRFC3339(u.GetStartDate())),
		"endDate":          llx.TimeDataPtr(parseRFC3339(u.GetEndDate())),
		"installedUpdates": llx.IntData(u.GetInstalledUpdates()),
		"failedUpdates":    llx.IntData(u.GetFailedUpdates()),
		"failReason":       llx.StringData(u.GetFailReason()),
	}
	return CreateResource(runtime, "stackit.server.update", args)
}

func (r *mqlStackitServerUpdate) id() (string, error) {
	return "stackit.server.update/" + r.ServerId.Data + "/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlStackitServerUpdate) server() (*mqlStackitServer, error) {
	return serverRef(r.MqlRuntime, r.ServerId.Data, &r.Server)
}

// ------------------------- server update schedules -------------------------

func (r *mqlStackitServer) updateSchedules() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerUpdate()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUpdateSchedules(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildUpdateSchedule(r.MqlRuntime, r.Id.Data, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildUpdateSchedule(runtime *plugin.Runtime, serverID string, s *serverupdate.UpdateSchedule) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"id":                llx.IntData(s.GetId()),
		"serverId":          llx.StringData(serverID),
		"name":              llx.StringData(s.GetName()),
		"enabled":           llx.BoolData(s.GetEnabled()),
		"rrule":             llx.StringData(s.GetRrule()),
		"maintenanceWindow": llx.IntData(s.GetMaintenanceWindow()),
	}
	return CreateResource(runtime, "stackit.server.updateSchedule", args)
}

func (r *mqlStackitServerUpdateSchedule) id() (string, error) {
	return "stackit.server.updateSchedule/" + r.ServerId.Data + "/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlStackitServerUpdateSchedule) server() (*mqlStackitServer, error) {
	return serverRef(r.MqlRuntime, r.ServerId.Data, &r.Server)
}
