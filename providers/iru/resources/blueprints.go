// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/connection/client"
)

func (r *mqlIru) blueprints() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IruConnection)
	bps, err := conn.ListBlueprints()
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Msg("iru> access denied to blueprints; returning empty list")
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(bps))
	for i := range bps {
		item, err := CreateResource(r.MqlRuntime, "iru.blueprint", blueprintArgs(&bps[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (b *mqlIruBlueprint) id() (string, error) {
	return "iru.blueprint/" + b.Id.Data, nil
}

// initIruBlueprint hydrates an iru.blueprint created by id (as a
// cross-reference from iru.device.blueprint) using the tenant-wide
// blueprint listing memoized on the connection. Without this, stub
// resources created via NewResource would have empty name/description/etc.
func initIruBlueprint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.IruConnection)
	bps, err := conn.ListBlueprints()
	if err != nil {
		return args, nil, err
	}
	for i := range bps {
		if bps[i].ID != id {
			continue
		}
		return blueprintArgs(&bps[i]), nil, nil
	}
	return nil, nil, fmt.Errorf("iru.blueprint with id %q not found", id)
}

func blueprintArgs(b *client.Blueprint) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                   llx.StringData(b.ID),
		"name":                 llx.StringData(b.Name),
		"description":          llx.StringData(b.Description),
		"icon":                 llx.StringData(b.Icon),
		"color":                llx.StringData(b.Color),
		"blueprintType":        llx.StringData(b.Type),
		"computersCount":       llx.IntData(int64(b.ComputersCount)),
		"enrollmentCode":       llx.StringData(b.EnrollmentCode.Code),
		"enrollmentCodeActive": llx.BoolData(b.EnrollmentCode.IsActive),
		"created":              llx.TimeDataPtr(client.ParseTime(b.CreatedAt)),
		"updatedAt":            llx.TimeDataPtr(client.ParseTime(b.UpdatedAt)),
	}
}
