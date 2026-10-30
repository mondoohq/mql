// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	gkebackup "cloud.google.com/go/gkebackup/apiv1"
	"cloud.google.com/go/gkebackup/apiv1/gkebackuppb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectGkeBackupServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) gkeBackup() (*mqlGcpProjectGkeBackupService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.gkeBackupService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_gkebackup)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectGkeBackupService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_gkebackup).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectGkeBackupService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectGkeBackupService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.gkeBackupService", g.ProjectId.Data), nil
}

// ---------------------------------------------------------------
// Backup Plans
// ---------------------------------------------------------------

func (g *mqlGcpProjectGkeBackupServiceBackupPlan) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectGkeBackupService) backupPlans() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(gkebackup.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := gkebackup.NewBackupForGKEClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupPlans(ctx, &gkebackuppb.ListBackupPlansRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		bp, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list GKE Backup backup plans")
				break
			}
			return nil, err
		}

		retentionPolicy, err := protoToDict(bp.RetentionPolicy)
		if err != nil {
			return nil, err
		}

		backupSchedule, err := protoToDict(bp.BackupSchedule)
		if err != nil {
			return nil, err
		}

		backupConfig, err := protoToDict(bp.BackupConfig)
		if err != nil {
			return nil, err
		}

		mqlBp, err := CreateResource(g.MqlRuntime, "gcp.project.gkeBackupService.backupPlan", map[string]*llx.RawData{
			"name":              llx.StringData(bp.Name),
			"uid":               llx.StringData(bp.Uid),
			"description":       llx.StringData(bp.Description),
			"cluster":           llx.StringData(bp.Cluster),
			"retentionPolicy":   llx.DictData(retentionPolicy),
			"backupSchedule":    llx.DictData(backupSchedule),
			"backupConfig":      llx.DictData(backupConfig),
			"deactivated":       llx.BoolData(bp.Deactivated),
			"labels":            llx.MapData(convert.MapToInterfaceMap(bp.Labels), types.String),
			"state":             llx.StringData(bp.State.String()),
			"stateReason":       llx.StringData(bp.StateReason),
			"protectedPodCount": llx.IntData(int64(bp.ProtectedPodCount)),
			"etag":              llx.StringData(bp.Etag),
			"created":           llx.TimeDataPtr(timestampAsTimePtr(bp.CreateTime)),
			"updated":           llx.TimeDataPtr(timestampAsTimePtr(bp.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBp)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Restore Plans
// ---------------------------------------------------------------

func (g *mqlGcpProjectGkeBackupServiceRestorePlan) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectGkeBackupService) restorePlans() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(gkebackup.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := gkebackup.NewBackupForGKEClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListRestorePlans(ctx, &gkebackuppb.ListRestorePlansRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		rp, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list GKE Backup restore plans")
				break
			}
			return nil, err
		}

		restoreConfig, err := protoToDict(rp.RestoreConfig)
		if err != nil {
			return nil, err
		}

		mqlRp, err := CreateResource(g.MqlRuntime, "gcp.project.gkeBackupService.restorePlan", map[string]*llx.RawData{
			"name":           llx.StringData(rp.Name),
			"uid":            llx.StringData(rp.Uid),
			"description":    llx.StringData(rp.Description),
			"backupPlanName": llx.StringData(rp.BackupPlan),
			"cluster":        llx.StringData(rp.Cluster),
			"restoreConfig":  llx.DictData(restoreConfig),
			"labels":         llx.MapData(convert.MapToInterfaceMap(rp.Labels), types.String),
			"state":          llx.StringData(rp.State.String()),
			"stateReason":    llx.StringData(rp.StateReason),
			"etag":           llx.StringData(rp.Etag),
			"created":        llx.TimeDataPtr(timestampAsTimePtr(rp.CreateTime)),
			"updated":        llx.TimeDataPtr(timestampAsTimePtr(rp.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRp)
	}

	return res, nil
}

func (g *mqlGcpProjectGkeBackupServiceRestorePlan) backupPlan() (*mqlGcpProjectGkeBackupServiceBackupPlan, error) {
	if g.BackupPlanName.Error != nil {
		return nil, g.BackupPlanName.Error
	}
	name := g.BackupPlanName.Data
	if name == "" {
		g.BackupPlan.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.gkeBackupService.backupPlan", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectGkeBackupServiceBackupPlan), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectGkeBackupService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_gkebackup)
}
