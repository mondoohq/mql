// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	backupdr "cloud.google.com/go/backupdr/apiv1"
	"cloud.google.com/go/backupdr/apiv1/backupdrpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (g *mqlGcpProject) backupdr() (*mqlGcpProjectBackupdrService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectBackupdrService), nil
}

func initGcpProjectBackupdrService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectBackupdrService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/backupdrService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectBackupdrService) managementServers() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListManagementServers(ctx, &backupdrpb.ListManagementServersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		server, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Backup DR management servers")
				break
			}
			return nil, err
		}

		networks := make([]any, 0, len(server.Networks))
		for _, n := range server.Networks {
			d, err := protoToDict(n)
			if err != nil {
				return nil, err
			}
			networks = append(networks, d)
		}

		managementUri, err := protoToDict(server.ManagementUri)
		if err != nil {
			return nil, err
		}

		mqlServer, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.managementServer", map[string]*llx.RawData{
			"name":           llx.StringData(server.Name),
			"description":    llx.StringData(server.Description),
			"state":          llx.StringData(server.State.String()),
			"type":           llx.StringData(server.Type.String()),
			"networks":       llx.ArrayData(networks, types.Dict),
			"managementUri":  llx.DictData(managementUri),
			"oauth2ClientId": llx.StringData(server.Oauth2ClientId),
			"satisfiesPzs":   llx.BoolDataPtr(boolValueToPtr(server.SatisfiesPzs)),
			"etag":           llx.StringData(server.Etag),
			"labels":         llx.MapData(convert.MapToInterfaceMap(server.Labels), types.String),
			"createdAt":      llx.TimeDataPtr(timestampAsTimePtr(server.CreateTime)),
			"updatedAt":      llx.TimeDataPtr(timestampAsTimePtr(server.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceManagementServer) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrService) backupVaults() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupVaults(ctx, &backupdrpb.ListBackupVaultsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		vault, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Backup DR backup vaults")
				break
			}
			return nil, err
		}

		mqlVault, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.backupVault", map[string]*llx.RawData{
			"name":                                   llx.StringData(vault.Name),
			"description":                            llx.StringData(vault.GetDescription()),
			"state":                                  llx.StringData(vault.State.String()),
			"backupMinimumEnforcedRetentionDuration": llx.StringData(vault.GetBackupMinimumEnforcedRetentionDuration().String()),
			"deletable":                              llx.BoolData(vault.GetDeletable()),
			"etag":                                   llx.StringData(vault.GetEtag()),
			"effectiveTime":                          llx.TimeDataPtr(timestampAsTimePtr(vault.EffectiveTime)),
			"backupCount":                            llx.IntData(vault.GetBackupCount()),
			"serviceAccount":                         llx.StringData(vault.ServiceAccount),
			"totalStoredBytes":                       llx.IntData(vault.GetTotalStoredBytes()),
			"accessRestriction":                      llx.StringData(vault.AccessRestriction.String()),
			"kmsKeyName":                             llx.StringData(vault.GetEncryptionConfig().GetKmsKeyName()),
			"annotations":                            llx.MapData(convert.MapToInterfaceMap(vault.Annotations), types.String),
			"labels":                                 llx.MapData(convert.MapToInterfaceMap(vault.Labels), types.String),
			"createdAt":                              llx.TimeDataPtr(timestampAsTimePtr(vault.CreateTime)),
			"updatedAt":                              llx.TimeDataPtr(timestampAsTimePtr(vault.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVault)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceBackupVault) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceBackupVault) dataSources() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	vaultName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDataSources(ctx, &backupdrpb.ListDataSourcesRequest{
		Parent: vaultName,
	})

	var res []any
	for {
		ds, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Backup DR data sources")
				break
			}
			return nil, err
		}

		gcpResource, err := protoToDict(ds.GetDataSourceGcpResource())
		if err != nil {
			return nil, err
		}
		backupApplianceApp, err := protoToDict(ds.GetDataSourceBackupApplianceApplication())
		if err != nil {
			return nil, err
		}

		mqlDs, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.dataSource", map[string]*llx.RawData{
			"name":                                 llx.StringData(ds.Name),
			"state":                                llx.StringData(ds.State.String()),
			"labels":                               llx.MapData(convert.MapToInterfaceMap(ds.Labels), types.String),
			"dataSourceGcpResource":                llx.DictData(gcpResource),
			"dataSourceBackupApplianceApplication": llx.DictData(backupApplianceApp),
			"totalStoredBytes":                     llx.IntData(ds.GetTotalStoredBytes()),
			"backupCount":                          llx.IntData(ds.GetBackupCount()),
			"etag":                                 llx.StringData(ds.GetEtag()),
			"configState":                          llx.StringData(ds.ConfigState.String()),
			"createdAt":                            llx.TimeDataPtr(timestampAsTimePtr(ds.CreateTime)),
			"updatedAt":                            llx.TimeDataPtr(timestampAsTimePtr(ds.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDs)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceDataSource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrService) backupPlans() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupPlans(ctx, &backupdrpb.ListBackupPlansRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		plan, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Backup DR backup plans")
				break
			}
			return nil, err
		}

		backupRules := make([]any, 0, len(plan.BackupRules))
		for _, rule := range plan.BackupRules {
			d, err := protoToDict(rule)
			if err != nil {
				return nil, err
			}
			backupRules = append(backupRules, d)
		}

		mqlPlan, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.backupPlan", map[string]*llx.RawData{
			"name":                      llx.StringData(plan.Name),
			"description":               llx.StringData(plan.Description),
			"state":                     llx.StringData(plan.State.String()),
			"resourceType":              llx.StringData(plan.ResourceType),
			"backupVaultServiceAccount": llx.StringData(plan.BackupVaultServiceAccount),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(plan.Labels), types.String),
			"backupRules":               llx.ArrayData(backupRules, types.Dict),
			"etag":                      llx.StringData(plan.Etag),
			"createdAt":                 llx.TimeDataPtr(timestampAsTimePtr(plan.CreateTime)),
			"updatedAt":                 llx.TimeDataPtr(timestampAsTimePtr(plan.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlP := mqlPlan.(*mqlGcpProjectBackupdrServiceBackupPlan)
		mqlP.cacheBackupVaultName = plan.BackupVault
		res = append(res, mqlPlan)
	}
	return res, nil
}

type mqlGcpProjectBackupdrServiceBackupPlanInternal struct {
	cacheBackupVaultName string
}

func (g *mqlGcpProjectBackupdrServiceBackupPlan) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceBackupPlan) backupVault() (*mqlGcpProjectBackupdrServiceBackupVault, error) {
	if g.cacheBackupVaultName == "" {
		g.BackupVault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// The backupVault resource has no init, so a NewResource by-name would leave
	// a husk (only name populated). Scan the parent service's backupVaults()
	// list and return the real, fully-populated resource. The vault name is a
	// full resource path, so derive the project from it.
	projectId := projectFromResourceName(g.cacheBackupVaultName)
	if projectId == "" {
		g.BackupVault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := obj.(*mqlGcpProjectBackupdrService)
	vaults := svc.GetBackupVaults()
	if vaults.Error != nil {
		return nil, vaults.Error
	}
	for _, v := range vaults.Data {
		vault, ok := v.(*mqlGcpProjectBackupdrServiceBackupVault)
		if ok && vault.Name.Data == g.cacheBackupVaultName {
			return vault, nil
		}
	}
	g.BackupVault.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// backupdrListRefusal is the return path of a Backup and DR list whose call
// failed. A refusal (an API that is not enabled, a permission denial) goes
// through listRefusal. A 404 or Unimplemented means there is nothing to read
// in this project, which reads as an empty list, as the sibling listers do.
func backupdrListRefusal(err error, msg string, permission string) ([]any, error) {
	if classifyRefusal(err, permission) != nil {
		return listRefusal(err, msg, permission)
	}
	if isSkippable(err) {
		log.Warn().Err(err).Msg(msg)
		return []any{}, nil
	}
	return nil, err
}

// durationSecondsPtr returns the whole seconds of a protobuf duration, or nil
// when the duration is unset.
func durationSecondsPtr(d *durationpb.Duration) *int64 {
	if d == nil {
		return nil
	}
	s := d.GetSeconds()
	return &s
}

// restoreVerificationCleanup reads one cleanup rule of a restore verification
// plan. Both values are nil when the plan sets no rule, and skip stays nil
// when the rule leaves skip_cleanup unset.
func restoreVerificationCleanup(rule *backupdrpb.RestoreVerificationCleanupRule) (delaySeconds *int64, skip *bool) {
	if rule == nil {
		return nil, nil
	}
	return durationSecondsPtr(rule.GetCleanupDelay()), rule.SkipCleanup
}

func (g *mqlGcpProjectBackupdrService) restoreVerificationPlans() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListRestoreVerificationPlans(ctx, &backupdrpb.ListRestoreVerificationPlansRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	res := []any{}
	for {
		plan, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return backupdrListRefusal(err, "could not list Backup DR restore verification plans", "backupdr.restoreVerificationPlans.list")
		}

		successDelay, successSkip := restoreVerificationCleanup(plan.GetSuccessCleanupRule())
		failureDelay, failureSkip := restoreVerificationCleanup(plan.GetFailureCleanupRule())

		mqlPlan, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.restoreVerificationPlan", map[string]*llx.RawData{
			"name":                       llx.StringData(plan.Name),
			"description":                llx.StringData(plan.Description),
			"state":                      llx.StringData(plan.State.String()),
			"schedule":                   llx.StringData(plan.Schedule),
			"timeZone":                   llx.StringData(plan.TimeZone),
			"successCleanupDelaySeconds": llx.IntDataPtr(successDelay),
			"successCleanupSkipped":      llx.BoolDataPtr(successSkip),
			"failureCleanupDelaySeconds": llx.IntDataPtr(failureDelay),
			"failureCleanupSkipped":      llx.BoolDataPtr(failureSkip),
			"labels":                     llx.MapData(convert.MapToInterfaceMap(plan.Labels), types.String),
			"createdAt":                  llx.TimeDataPtr(timestampAsTimePtr(plan.CreateTime)),
			"updatedAt":                  llx.TimeDataPtr(timestampAsTimePtr(plan.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPlan)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceRestoreVerificationPlan) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceRestoreVerificationPlan) associations() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	planName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListRestoreVerificationPlanAssociations(ctx, &backupdrpb.ListRestoreVerificationPlanAssociationsRequest{
		Parent: planName,
	})

	res := []any{}
	for {
		assoc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return backupdrListRefusal(err, "could not list Backup DR restore verification plan associations", "backupdr.restoreVerificationPlanAssociations.list")
		}

		summary := assoc.GetTriggerSummary()
		mqlAssoc, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.restoreVerificationPlan.association", map[string]*llx.RawData{
			"name":                      llx.StringData(assoc.Name),
			"description":               llx.StringData(assoc.Description),
			"state":                     llx.StringData(assoc.State.String()),
			"resourceType":              llx.StringData(assoc.ResourceType),
			"lastTriggerTime":           llx.TimeDataPtr(timestampAsTimePtr(summary.GetLastTriggerTime())),
			"nextTriggerTime":           llx.TimeDataPtr(timestampAsTimePtr(summary.GetNextTriggerTime())),
			"lastTriggerError":          llx.StringDataPtr(restoreVerificationTriggerError(summary)),
			"lastVerificationExecution": llx.StringDataPtr(nonEmptyStringPtr(summary.GetLastVerificationExecution())),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(assoc.Labels), types.String),
			"createdAt":                 llx.TimeDataPtr(timestampAsTimePtr(assoc.CreateTime)),
			"updatedAt":                 llx.TimeDataPtr(timestampAsTimePtr(assoc.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlAssoc.(*mqlGcpProjectBackupdrServiceRestoreVerificationPlanAssociation).cacheRestoreTemplateName = assoc.GetRestoreTemplate()
		res = append(res, mqlAssoc)
	}
	return res, nil
}

// restoreVerificationTriggerError returns the message of the last failed
// trigger, or nil when the last trigger did not fail. A status carrying only a
// code still counts as a failure, so the code's name stands in for the message.
func restoreVerificationTriggerError(summary *backupdrpb.TriggerSummary) *string {
	st := summary.GetLastTriggerError()
	if st == nil {
		return nil
	}
	msg := st.GetMessage()
	if msg == "" {
		if st.GetCode() == 0 {
			return nil
		}
		msg = codes.Code(st.GetCode()).String()
	}
	return &msg
}

func nonEmptyStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type mqlGcpProjectBackupdrServiceRestoreVerificationPlanAssociationInternal struct {
	cacheRestoreTemplateName string
}

func (g *mqlGcpProjectBackupdrServiceRestoreVerificationPlanAssociation) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceRestoreVerificationPlanAssociation) restoreTemplate() (*mqlGcpProjectBackupdrServiceRestoreTemplate, error) {
	name := g.cacheRestoreTemplateName
	projectId := projectFromResourceName(name)
	if name == "" || projectId == "" {
		g.RestoreTemplate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	templates := obj.(*mqlGcpProjectBackupdrService).GetRestoreTemplates()
	if templates.Error != nil {
		return nil, templates.Error
	}
	for _, t := range templates.Data {
		tmpl, ok := t.(*mqlGcpProjectBackupdrServiceRestoreTemplate)
		if ok && tmpl.Name.Data == name {
			return tmpl, nil
		}
	}
	g.RestoreTemplate.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (g *mqlGcpProjectBackupdrService) restoreTemplates() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListRestoreTemplates(ctx, &backupdrpb.ListRestoreTemplatesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	res := []any{}
	for {
		tmpl, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return backupdrListRefusal(err, "could not list Backup DR restore templates", "backupdr.restoreTemplates.list")
		}

		lastExecution, lastExecutionState := restoreTemplateLastExecution(tmpl.GetExecutionSummary())
		mqlTmpl, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.restoreTemplate", map[string]*llx.RawData{
			"name":               llx.StringData(tmpl.Name),
			"description":        llx.StringData(tmpl.Description),
			"state":              llx.StringData(tmpl.State.String()),
			"resourceType":       llx.StringData(tmpl.ResourceType),
			"lastExecution":      llx.StringDataPtr(lastExecution),
			"lastExecutionState": llx.StringDataPtr(lastExecutionState),
			"labels":             llx.MapData(convert.MapToInterfaceMap(tmpl.Labels), types.String),
			"createdAt":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
			"updatedAt":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlTmpl.(*mqlGcpProjectBackupdrServiceRestoreTemplate).cacheDataSourceName = backupdrResourceName(tmpl.GetBackupSelectionConfig().GetDataSource())
		res = append(res, mqlTmpl)
	}
	return res, nil
}

// restoreTemplateLastExecution reads a restore template's execution summary.
// Both values are nil when the template has never run: the summary is absent,
// or it names no execution, in which case its state is only the enum's zero.
func restoreTemplateLastExecution(summary *backupdrpb.ExecutionSummary) (execution, state *string) {
	execution = nonEmptyStringPtr(summary.GetLastExecution())
	if execution == nil {
		return nil, nil
	}
	s := summary.GetLastExecutionState().String()
	return execution, &s
}

// backupdrResourceName reduces a Backup and DR resource URI to its relative
// resource name (projects/P/locations/L/...). The API documents the restore
// template's data source as a fully qualified URI, so the service-prefixed
// forms are accepted alongside the bare name.
func backupdrResourceName(uri string) string {
	for _, prefix := range []string{
		"//backupdr.googleapis.com/",
		"https://backupdr.googleapis.com/v1/",
	} {
		if rest, ok := strings.CutPrefix(uri, prefix); ok {
			return rest
		}
	}
	return uri
}

// backupVaultOfDataSource returns the backup vault a data source lives in,
// read from a name of the form .../backupVaults/V/dataSources/D. ok is false
// for any other shape.
func backupVaultOfDataSource(dataSourceName string) (string, bool) {
	vault, ds, ok := strings.Cut(dataSourceName, "/dataSources/")
	if !ok || ds == "" || !strings.Contains(vault, "/backupVaults/") {
		return "", false
	}
	return vault, true
}

type mqlGcpProjectBackupdrServiceRestoreTemplateInternal struct {
	cacheDataSourceName string
}

func (g *mqlGcpProjectBackupdrServiceRestoreTemplate) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceRestoreTemplate) dataSource() (*mqlGcpProjectBackupdrServiceDataSource, error) {
	dsName := g.cacheDataSourceName
	vaultName, ok := backupVaultOfDataSource(dsName)
	projectId := projectFromResourceName(dsName)
	if !ok || projectId == "" {
		g.DataSource.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	vaults := obj.(*mqlGcpProjectBackupdrService).GetBackupVaults()
	if vaults.Error != nil {
		return nil, vaults.Error
	}
	for _, v := range vaults.Data {
		vault, ok := v.(*mqlGcpProjectBackupdrServiceBackupVault)
		if !ok || vault.Name.Data != vaultName {
			continue
		}
		sources := vault.GetDataSources()
		if sources.Error != nil {
			return nil, sources.Error
		}
		for _, s := range sources.Data {
			ds, ok := s.(*mqlGcpProjectBackupdrServiceDataSource)
			if ok && ds.Name.Data == dsName {
				return ds, nil
			}
		}
	}
	g.DataSource.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}
