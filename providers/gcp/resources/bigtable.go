// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/bigtable"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// bigtablePartialResult reports whether err is the Bigtable SDK's
// ErrPartiallyUnavailable, which the admin client returns ALONGSIDE a populated
// result slice when some locations are unreachable ("Return partial results and
// an error in case of some locations are unavailable").
//
// It is a plain struct with no GRPCStatus(), so status.FromError does not
// recognise it and isSkippable returns false -- the callers therefore took
// the hard-error path and threw away the instances, clusters or backups the SDK
// had just handed them. A transient blip in one region emptied the whole
// Bigtable inventory.
func bigtablePartialResult(err error, what string) bool {
	var partial bigtable.ErrPartiallyUnavailable
	if !errors.As(err, &partial) {
		return false
	}
	log.Warn().Strs("locations", partial.Locations).Str("kind", what).
		Msg("some Bigtable locations were unreachable; returning partial results")
	return true
}

// bigtableAdminScopes are the OAuth scopes needed for Bigtable admin operations.
var bigtableAdminScopes = []string{
	bigtable.AdminScope,
	bigtable.InstanceAdminScope,
	"https://www.googleapis.com/auth/cloud-platform",
}

func (g *mqlGcpProject) bigtable() (*mqlGcpProjectBigtableService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectBigtableService), nil
}

func initGcpProjectBigtableService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

// initGcpProjectBigtableServiceInstance lets policies query a single Bigtable
// instance directly (e.g. when cnspec scans a gcp-bigtable-instance asset).
func initGcpProjectBigtableServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.bigtableService.instance requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.bigtableService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	bigtableSvc := obj.(*mqlGcpProjectBigtableService)
	instances := bigtableSvc.GetInstances()
	if instances.Error != nil {
		return nil, nil, instances.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.bigtableService.instance requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, i := range instances.Data {
		instance := i.(*mqlGcpProjectBigtableServiceInstance)
		// Bigtable instance name from the SDK is the short ID; it may also
		// arrive as the full resource path projects/{project}/instances/{id}.
		nameParts := strings.Split(instance.Name.Data, "/")
		instanceName := nameParts[len(nameParts)-1]
		if instanceName == nameVal {
			return args, instance, nil
		}
	}

	return nil, nil, fmt.Errorf("Bigtable instance %q not found", nameVal)
}

func (g *mqlGcpProjectBigtableService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/bigtableService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectBigtableService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iac, err := bigtable.NewInstanceAdminClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer iac.Close()

	instances, err := iac.Instances(ctx)
	if err != nil {
		if !bigtablePartialResult(err, "instances") {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Bigtable instances")
				return nil, nil
			}
			return nil, err
		}
		// fall through: instances holds the reachable locations' results
	}

	res := make([]any, 0, len(instances))
	for _, inst := range instances {
		mqlInst, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService.instance", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"name":         llx.StringData(inst.Name),
			"displayName":  llx.StringData(inst.DisplayName),
			"state":        llx.StringData(bigtableInstanceStateToString(inst.InstanceState)),
			"instanceType": llx.StringData(bigtableInstanceTypeToString(inst.InstanceType)),
			"labels":       llx.MapData(convert.MapToInterfaceMap(inst.Labels), types.String),
			"createdAt":    llx.NilData, // Bigtable SDK doesn't expose creation time in InstanceInfo
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}

	return res, nil
}

func bigtableInstanceStateToString(s bigtable.InstanceState) string {
	switch s {
	case bigtable.Ready:
		return "READY"
	case bigtable.Creating:
		return "CREATING"
	default:
		return "STATE_NOT_KNOWN"
	}
}

func bigtableInstanceTypeToString(t bigtable.InstanceType) string {
	switch t {
	case bigtable.PRODUCTION:
		return "PRODUCTION"
	case bigtable.DEVELOPMENT:
		return "DEVELOPMENT"
	default:
		return "UNSPECIFIED"
	}
}

func (g *mqlGcpProjectBigtableServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/bigtableService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectBigtableServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectBigtableServiceInstance) clusters() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iac, err := bigtable.NewInstanceAdminClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer iac.Close()

	clusters, err := iac.Clusters(ctx, instanceName)
	if err != nil && !bigtablePartialResult(err, "clusters") {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Bigtable clusters")
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(clusters))
	for _, c := range clusters {
		var autoscalingConfig map[string]any
		if c.AutoscalingConfig != nil {
			// The SDK models these as Go `int`, which is not JSON-native and so
			// fails dict2primitive at query time; widen to int64.
			autoscalingConfig = map[string]any{
				"minNodes":                  int64(c.AutoscalingConfig.MinNodes),
				"maxNodes":                  int64(c.AutoscalingConfig.MaxNodes),
				"cpuTargetPercent":          int64(c.AutoscalingConfig.CPUTargetPercent),
				"storageUtilizationPerNode": int64(c.AutoscalingConfig.StorageUtilizationPerNode),
			}
		}

		var encryptionConfig map[string]any
		if c.KMSKeyName != "" {
			encryptionConfig = map[string]any{
				"kmsKeyName": c.KMSKeyName,
			}
		}

		mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService.cluster", map[string]*llx.RawData{
			"projectId":          llx.StringData(projectId),
			"instanceName":       llx.StringData(instanceName),
			"name":               llx.StringData(c.Name),
			"location":           llx.StringData(c.Zone),
			"state":              llx.StringData(c.State),
			"serveNodes":         llx.IntData(int64(c.ServeNodes)),
			"defaultStorageType": llx.StringData(bigtableStorageTypeToString(c.StorageType)),
			"encryptionConfig":   llx.DictData(encryptionConfig),
			"nodeScalingFactor":  llx.StringData(bigtableNodeScalingFactorToString(c.NodeScalingFactor)),
			"autoscalingConfig":  llx.DictData(autoscalingConfig),
		})
		if err != nil {
			return nil, err
		}
		mqlCluster.(*mqlGcpProjectBigtableServiceCluster).cacheKmsKeyName = c.KMSKeyName
		res = append(res, mqlCluster)
	}

	return res, nil
}

func bigtableStorageTypeToString(t bigtable.StorageType) string {
	switch t {
	case bigtable.SSD:
		return "SSD"
	case bigtable.HDD:
		return "HDD"
	default:
		return "UNSPECIFIED"
	}
}

func bigtableNodeScalingFactorToString(f bigtable.NodeScalingFactor) string {
	switch f {
	case bigtable.NodeScalingFactor1X:
		return "NODE_SCALING_FACTOR_1X"
	case bigtable.NodeScalingFactor2X:
		return "NODE_SCALING_FACTOR_2X"
	default:
		return "NODE_SCALING_FACTOR_UNSPECIFIED"
	}
}

func (g *mqlGcpProjectBigtableServiceCluster) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	// Cluster names are unique only within an instance, so the instance must
	// be part of the cache key (matches the table/appProfile/backup ids).
	return fmt.Sprintf("gcp.project/%s/bigtableService/%s/cluster/%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data), nil
}

type mqlGcpProjectBigtableServiceClusterInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectBigtableServiceCluster) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectBigtableServiceInstance) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iac, err := bigtable.NewInstanceAdminClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer iac.Close()

	policy, err := iac.InstanceIAM(instanceName).Policy(ctx)
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not get Bigtable instance IAM policy")
			return nil, nil
		}
		return nil, err
	}

	resourcePath := fmt.Sprintf("projects/%s/instances/%s", projectId, instanceName)
	res := []any{}
	for _, role := range policy.Roles() {
		members := policy.Members(role)
		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resourcePath + "/" + string(role)),
			"role":                 llx.StringData(string(role)),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(members), types.String),
			"conditionTitle":       llx.StringData(""),
			"conditionExpression":  llx.StringData(""),
			"conditionDescription": llx.StringData(""),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectBigtableServiceInstance) tables() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	ac, err := bigtable.NewAdminClient(ctx, projectId, instanceName, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer ac.Close()

	tableNames, err := ac.Tables(ctx)
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Bigtable tables")
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(tableNames))
	for _, tableName := range tableNames {
		tableInfo, err := ac.TableInfo(ctx, tableName)
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Str("table", tableName).Msg("could not read Bigtable table info")
				continue
			}
			return nil, err
		}

		columnFamilies := map[string]any{}
		for _, fi := range tableInfo.FamilyInfos {
			columnFamilies[fi.Name] = map[string]any{
				"name":         fi.Name,
				"gcPolicy":     fi.GCPolicy,
				"fullGCPolicy": fi.FullGCPolicy.String(),
			}
		}

		configuredPolicy, _ := tableInfo.AutomatedBackupConfig.(*bigtable.TableAutomatedBackupPolicy)
		automatedBackupPolicy := bigtableAutomatedBackupPolicyDict(configuredPolicy)
		automatedBackupsDisabled := configuredPolicy != nil && configuredPolicy.Disabled

		var changeStreamConfig map[string]any
		if tableInfo.ChangeStreamRetention != 0 {
			changeStreamConfig = map[string]any{
				"retentionPeriod": fmt.Sprintf("%v", tableInfo.ChangeStreamRetention),
			}
		}

		var tieredStorageConfig map[string]any
		if tsc := tableInfo.TieredStorageConfig; tsc != nil {
			if rule, ok := tsc.InfrequentAccess.(*bigtable.TieredStorageIncludeIfOlderThan); ok && rule != nil {
				tieredStorageConfig = map[string]any{
					"infrequentAccess": map[string]any{
						"includeIfOlderThan": fmt.Sprintf("%v", rule.Duration),
					},
				}
			}
		}

		deletionProtection := false
		if tableInfo.DeletionProtection == bigtable.Protected {
			deletionProtection = true
		}

		tableId := fmt.Sprintf("gcp.project/%s/bigtableService/%s/table/%s", projectId, instanceName, tableName)
		tableArgs := map[string]*llx.RawData{
			"projectId":                llx.StringData(projectId),
			"instanceName":             llx.StringData(instanceName),
			"name":                     llx.StringData(tableName),
			"columnFamilies":           llx.DictData(columnFamilies),
			"granularity":              llx.StringData("MILLIS"),
			"deletionProtection":       llx.BoolData(deletionProtection),
			"automatedBackupPolicy":    llx.DictData(automatedBackupPolicy),
			"automatedBackupsDisabled": llx.BoolData(automatedBackupsDisabled),
			"changeStreamConfig":       llx.DictData(changeStreamConfig),
			"tieredStorageConfig":      llx.DictData(tieredStorageConfig),
		}
		var effectivePolicy plugin.Resource
		if ep := tableInfo.EffectiveAutomatedBackupPolicy; ep != nil {
			args := bigtableBackupPolicyArgs(ep)
			args["__id"] = llx.StringData(tableId + "/effectiveAutomatedBackupPolicy")
			effectivePolicy, err = CreateResource(g.MqlRuntime, "gcp.project.bigtableService.table.backupPolicy", args)
			if err != nil {
				return nil, err
			}
			tableArgs["effectiveAutomatedBackupPolicy"] = llx.ResourceData(effectivePolicy, "gcp.project.bigtableService.table.backupPolicy")
		}

		mqlTable, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService.table", tableArgs)
		if err != nil {
			return nil, err
		}
		if effectivePolicy == nil {
			mqlTable.(*mqlGcpProjectBigtableServiceTable).EffectiveAutomatedBackupPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		}
		res = append(res, mqlTable)
	}

	return res, nil
}

// bigtableOptionalDuration reads an optional.Duration, which the SDK leaves as
// a nil interface when the API response does not set it.
func bigtableOptionalDuration(d any) (time.Duration, bool) {
	switch v := d.(type) {
	case time.Duration:
		return v, true
	case *time.Duration:
		if v != nil {
			return *v, true
		}
	}
	return 0, false
}

// bigtableAutomatedBackupPolicyDict renders a table's configured automated
// backup policy. It returns nil when the table has no policy or explicitly
// disables automated backups, and omits duration keys the policy leaves unset.
func bigtableAutomatedBackupPolicyDict(abp *bigtable.TableAutomatedBackupPolicy) map[string]any {
	if abp == nil || abp.Disabled {
		return nil
	}
	res := map[string]any{
		// []string is not JSON-native inside a dict.
		"locations": convert.SliceAnyToInterface(abp.Locations),
	}
	if d, ok := bigtableOptionalDuration(abp.RetentionPeriod); ok {
		res["retentionPeriod"] = d.String()
	}
	if d, ok := bigtableOptionalDuration(abp.Frequency); ok {
		res["frequency"] = d.String()
	}
	if d, ok := bigtableOptionalDuration(abp.KeepHotDuration); ok {
		res["keepHotDuration"] = d.String()
	}
	return res
}

// bigtableBackupPolicyArgs maps an automated backup policy onto the fields of
// gcp.project.bigtableService.table.backupPolicy. Unset durations are null.
func bigtableBackupPolicyArgs(abp *bigtable.TableAutomatedBackupPolicy) map[string]*llx.RawData {
	seconds := func(d any) *llx.RawData {
		if v, ok := bigtableOptionalDuration(d); ok {
			return llx.IntData(int64(v / time.Second))
		}
		return llx.NilData
	}
	locations := abp.Locations
	if locations == nil {
		locations = []string{}
	}
	return map[string]*llx.RawData{
		"frequencySeconds":       seconds(abp.Frequency),
		"retentionPeriodSeconds": seconds(abp.RetentionPeriod),
		"keepHotDurationSeconds": seconds(abp.KeepHotDuration),
		"locations":              llx.ArrayData(convert.SliceAnyToInterface(locations), types.String),
		"disabled":               llx.BoolData(abp.Disabled),
	}
}

func (g *mqlGcpProjectBigtableServiceTable) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/bigtableService/%s/table/%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectBigtableServiceInstance) appProfiles() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iac, err := bigtable.NewInstanceAdminClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer iac.Close()

	it := iac.ListAppProfiles(ctx, instanceName)

	var res []any
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Bigtable app profiles")
				break
			}
			return nil, err
		}

		routingPolicy := map[string]any{}
		if mcr := p.GetMultiClusterRoutingUseAny(); mcr != nil {
			clusterIds := make([]any, 0, len(mcr.GetClusterIds()))
			for _, cid := range mcr.GetClusterIds() {
				clusterIds = append(clusterIds, cid)
			}
			routingPolicy = map[string]any{
				"type":       "MULTI_CLUSTER_ROUTING_USE_ANY",
				"clusterIds": clusterIds,
			}
		} else if scr := p.GetSingleClusterRouting(); scr != nil {
			routingPolicy = map[string]any{
				"type":                     "SINGLE_CLUSTER_ROUTING",
				"clusterId":                scr.GetClusterId(),
				"allowTransactionalWrites": scr.GetAllowTransactionalWrites(),
			}
		}

		mqlProfile, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService.appProfile", map[string]*llx.RawData{
			"projectId":     llx.StringData(projectId),
			"instanceName":  llx.StringData(instanceName),
			"name":          llx.StringData(p.GetName()),
			"description":   llx.StringData(p.GetDescription()),
			"routingPolicy": llx.DictData(routingPolicy),
			"etag":          llx.StringData(p.GetEtag()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}

	return res, nil
}

func (g *mqlGcpProjectBigtableServiceAppProfile) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/bigtableService/%s/appProfile/%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectBigtableServiceInstance) backups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	// First get all clusters for this instance
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(bigtableAdminScopes...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iac, err := bigtable.NewInstanceAdminClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer iac.Close()

	clusters, err := iac.Clusters(ctx, instanceName)
	if err != nil && !bigtablePartialResult(err, "clusters") {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Bigtable clusters for backup lookup")
			return nil, nil
		}
		return nil, err
	}

	// For each cluster, list backups
	ac, err := bigtable.NewAdminClient(ctx, projectId, instanceName, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer ac.Close()

	var res []any
	for _, c := range clusters {
		// Extract just the cluster ID from the full name
		clusterID := c.Name
		if idx := strings.LastIndex(c.Name, "/"); idx >= 0 {
			clusterID = c.Name[idx+1:]
		}

		it := ac.Backups(ctx, clusterID)
		for {
			backup, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("cluster", clusterID).Msg("could not list Bigtable backups")
					break
				}
				return nil, err
			}

			var encryptionInfo map[string]any
			if backup.EncryptionInfo != nil {
				encryptionInfo = map[string]any{
					"encryptionType":   fmt.Sprintf("%d", backup.EncryptionInfo.Type),
					"encryptionStatus": fmt.Sprintf("%v", backup.EncryptionInfo.Status),
					"kmsKeyVersion":    backup.EncryptionInfo.KMSKeyVersion,
				}
			}

			mqlBackup, err := CreateResource(g.MqlRuntime, "gcp.project.bigtableService.backup", map[string]*llx.RawData{
				// Cluster ids are unique only within an instance, so the key
				// must name the instance -- matching table/appProfile/cluster.
				// cacheInstanceName is assigned after CreateResource returns and
				// so is not visible to id(); pass the key explicitly instead.
				"__id": llx.StringData(fmt.Sprintf("gcp.project/%s/bigtableService/%s/cluster/%s/backup/%s",
					projectId, instanceName, c.Name, backup.Name)),
				"projectId":      llx.StringData(projectId),
				"clusterName":    llx.StringData(c.Name),
				"name":           llx.StringData(backup.Name),
				"sourceTable":    llx.StringData(backup.SourceTable),
				"expireTime":     llx.TimeData(backup.ExpireTime),
				"startTime":      llx.TimeData(backup.StartTime),
				"endTime":        llx.TimeData(backup.EndTime),
				"sizeBytes":      llx.IntData(backup.SizeBytes),
				"state":          llx.StringData(backup.State),
				"encryptionInfo": llx.DictData(encryptionInfo),
			})
			if err != nil {
				return nil, err
			}
			mqlBackup.(*mqlGcpProjectBigtableServiceBackup).cacheSourceBackup = backup.SourceBackup
			mqlBackup.(*mqlGcpProjectBigtableServiceBackup).cacheInstanceName = instanceName
			res = append(res, mqlBackup)
		}
	}

	return res, nil
}

func (g *mqlGcpProjectBigtableServiceBackup) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.ClusterName.Error != nil {
		return "", g.ClusterName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/bigtableService/%s/backup/%s", g.ProjectId.Data, g.ClusterName.Data, g.Name.Data), nil
}

type mqlGcpProjectBigtableServiceBackupInternal struct {
	cacheSourceBackup string
	cacheInstanceName string
}

// bigtableInstanceIDFromClusterName extracts the short instance ID from a full
// cluster resource name (projects/{project}/instances/{instance}/clusters/{cluster}).
// Returns "" when the name does not match that shape.
func bigtableInstanceIDFromClusterName(clusterName string) string {
	parts := strings.Split(clusterName, "/")
	if len(parts) < 4 || parts[0] != "projects" || parts[2] != "instances" {
		return ""
	}
	return parts[3]
}

// getBigtableTableByName resolves a Bigtable table by its short ID within an
// instance. The instance list is served from the runtime cache when the parent
// traversal already listed it. Returns nil when the table name is empty or no
// matching table exists.
func getBigtableTableByName(runtime *plugin.Runtime, projectId, instanceName, tableName string) (*mqlGcpProjectBigtableServiceTable, error) {
	if tableName == "" || instanceName == "" {
		return nil, nil
	}
	obj, err := CreateResource(runtime, "gcp.project.bigtableService.instance", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"name":      llx.StringData(instanceName),
	})
	if err != nil {
		return nil, err
	}
	inst := obj.(*mqlGcpProjectBigtableServiceInstance)
	tables := inst.GetTables()
	if tables.Error != nil {
		return nil, tables.Error
	}
	for _, t := range tables.Data {
		table := t.(*mqlGcpProjectBigtableServiceTable)
		if table.Name.Error != nil {
			return nil, table.Name.Error
		}
		if table.Name.Data == tableName {
			return table, nil
		}
	}
	return nil, nil
}

// getBigtableBackupByName resolves a Bigtable backup by its full resource name
// (projects/{project}/instances/{instance}/clusters/{cluster}/backups/{backup}).
// Returns nil when the name is empty, malformed, or no matching backup exists.
func getBigtableBackupByName(runtime *plugin.Runtime, backupResourceName string) (*mqlGcpProjectBigtableServiceBackup, error) {
	if backupResourceName == "" {
		return nil, nil
	}
	parts := strings.Split(backupResourceName, "/")
	if len(parts) < 8 || parts[0] != "projects" || parts[2] != "instances" || parts[4] != "clusters" || parts[6] != "backups" {
		return nil, nil
	}
	projectId := parts[1]
	instanceName := parts[3]
	// backups() stores ClusterInfo.Name, which the Bigtable SDK sets to the
	// short cluster id (the last path segment), not the full resource path.
	// Comparing against a full path here never matched, so sourceBackup was
	// always null and backup lineage was invisible.
	clusterShort := parts[5]
	backupShort := parts[7]

	obj, err := CreateResource(runtime, "gcp.project.bigtableService.instance", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"name":      llx.StringData(instanceName),
	})
	if err != nil {
		return nil, err
	}
	inst := obj.(*mqlGcpProjectBigtableServiceInstance)
	backups := inst.GetBackups()
	if backups.Error != nil {
		return nil, backups.Error
	}
	for _, b := range backups.Data {
		backup := b.(*mqlGcpProjectBigtableServiceBackup)
		if backup.Name.Error != nil {
			return nil, backup.Name.Error
		}
		if backup.ClusterName.Error != nil {
			return nil, backup.ClusterName.Error
		}
		if backup.Name.Data == backupShort && backup.ClusterName.Data == clusterShort {
			return backup, nil
		}
	}
	return nil, nil
}

func (g *mqlGcpProjectBigtableServiceBackup) sourceTableRef() (*mqlGcpProjectBigtableServiceTable, error) {
	if g.SourceTable.Error != nil {
		return nil, g.SourceTable.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ClusterName.Error != nil {
		return nil, g.ClusterName.Error
	}
	// Backups are keyed by the short cluster ID, so the instance cannot be
	// re-derived from ClusterName; use the instance name cached at creation
	// (falling back to the cluster-name parse for backups built elsewhere).
	instanceName := g.cacheInstanceName
	if instanceName == "" {
		instanceName = bigtableInstanceIDFromClusterName(g.ClusterName.Data)
	}
	table, err := getBigtableTableByName(g.MqlRuntime, g.ProjectId.Data, instanceName, g.SourceTable.Data)
	if err != nil {
		return nil, err
	}
	if table == nil {
		g.SourceTableRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return table, nil
}

func (g *mqlGcpProjectBigtableServiceBackup) sourceBackup() (*mqlGcpProjectBigtableServiceBackup, error) {
	backup, err := getBigtableBackupByName(g.MqlRuntime, g.cacheSourceBackup)
	if err != nil {
		return nil, err
	}
	if backup == nil {
		g.SourceBackup.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return backup, nil
}
