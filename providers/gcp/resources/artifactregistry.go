// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

type mqlGcpProjectArtifactRegistryServiceRepositoryInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProject) artifactRegistry() (*mqlGcpProjectArtifactRegistryService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.artifactRegistryService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryService), nil
}

func initGcpProjectArtifactRegistryService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectArtifactRegistryService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/artifactRegistryService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectArtifactRegistryService) repositories() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(artifactregistry.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := artifactregistry.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Artifact Registry doesn't support the "-" wildcard for locations,
	// so we enumerate locations first, then list repositories per location.
	locations, err := listArtifactRegistryLocations(ctx, client, projectId)
	if err != nil {
		return nil, err
	}

	var repos []any
	for _, loc := range locations {
		it := client.ListRepositories(ctx, &artifactregistrypb.ListRepositoriesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, loc),
		})

		for {
			r, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, err
			}

			mqlRepo, err := newArtifactRegistryRepository(g.MqlRuntime, projectId, r)
			if err != nil {
				return nil, err
			}
			repos = append(repos, mqlRepo)
		}
	}
	return repos, nil
}

func listArtifactRegistryLocations(ctx context.Context, client *artifactregistry.Client, projectId string) ([]string, error) {
	it := client.ListLocations(ctx, &locationpb.ListLocationsRequest{
		Name: fmt.Sprintf("projects/%s", projectId),
	})
	var locations []string
	for {
		l, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		locations = append(locations, l.LocationId)
	}
	return locations, nil
}

func newArtifactRegistryRepository(runtime *plugin.Runtime, projectId string, r *artifactregistrypb.Repository) (*mqlGcpProjectArtifactRegistryServiceRepository, error) {
	repoPath := r.Name

	vulnScanRes, err := newVulnScanConfig(runtime, repoPath, r.VulnerabilityScanningConfig)
	if err != nil {
		return nil, err
	}

	cleanupPolicyRes, err := newCleanupPolicies(runtime, repoPath, r.CleanupPolicies)
	if err != nil {
		return nil, err
	}

	formatConfigRes, err := newFormatConfig(runtime, repoPath, r)
	if err != nil {
		return nil, err
	}

	modeConfigRes, err := newModeConfig(runtime, repoPath, r)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository", map[string]*llx.RawData{
		"projectId":                   llx.StringData(projectId),
		"resourcePath":                llx.StringData(repoPath),
		"name":                        llx.StringData(parseResourceName(repoPath)),
		"location":                    llx.StringData(parseLocationFromPath(repoPath)),
		"description":                 llx.StringData(r.Description),
		"format":                      llx.StringData(r.Format.String()),
		"mode":                        llx.StringData(r.Mode.String()),
		"labels":                      llx.MapData(convert.MapToInterfaceMap(r.Labels), types.String),
		"createTime":                  llx.TimeDataPtr(timestampAsTimePtr(r.CreateTime)),
		"updateTime":                  llx.TimeDataPtr(timestampAsTimePtr(r.UpdateTime)),
		"sizeBytes":                   llx.IntData(r.SizeBytes),
		"registryUri":                 llx.StringData(r.RegistryUri),
		"satisfiesPzs":                llx.BoolData(r.SatisfiesPzs),
		"satisfiesPzi":                llx.BoolData(r.SatisfiesPzi),
		"cleanupPolicyDryRun":         llx.BoolData(r.CleanupPolicyDryRun),
		"vulnerabilityScanningConfig": llx.ResourceData(vulnScanRes, "gcp.project.artifactRegistryService.repository.vulnScanConfig"),
		"cleanupPolicies":             llx.ArrayData(cleanupPolicyRes, types.Resource("gcp.project.artifactRegistryService.repository.cleanupPolicy")),
		"formatConfig":                llx.ResourceData(formatConfigRes, "gcp.project.artifactRegistryService.repository.formatConfig"),
		"modeConfig":                  llx.ResourceData(modeConfigRes, "gcp.project.artifactRegistryService.repository.modeConfig"),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := res.(*mqlGcpProjectArtifactRegistryServiceRepository)
	mqlRef.cacheKmsKeyName = r.KmsKeyName
	return res.(*mqlGcpProjectArtifactRegistryServiceRepository), nil
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func initGcpProjectArtifactRegistryServiceRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		args = make(map[string]*llx.RawData)
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	nameRaw, ok := args["name"]
	if !ok || nameRaw == nil {
		return nil, nil, errors.New("artifact registry repository init requires a \"name\" argument")
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.artifactRegistryService.repository requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.artifactRegistryService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectArtifactRegistryService)
	repositories := svc.GetRepositories()
	if repositories.Error != nil {
		return nil, nil, repositories.Error
	}

	nameVal, ok := nameRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("artifact registry repository init: \"name\" must be a string")
	}
	var locationVal string
	if locRaw := args["location"]; locRaw != nil {
		if v, ok := locRaw.Value.(string); ok {
			locationVal = v
		}
	}
	for _, r := range repositories.Data {
		repo := r.(*mqlGcpProjectArtifactRegistryServiceRepository)
		if repo.Name.Data == nameVal && (locationVal == "" || repo.Location.Data == locationVal) {
			return args, repo, nil
		}
	}

	return nil, nil, fmt.Errorf("artifact registry repository %q not found", nameVal)
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) iamPolicy() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	repoPath := g.ResourcePath.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(artifactregistry.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := artifactregistry.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: repoPath, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(policy.Bindings))
	for _, b := range policy.Bindings {
		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(repoPath + "/" + b.Role),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(b.GetCondition().GetTitle()),
			"conditionExpression":  llx.StringData(b.GetCondition().GetExpression()),
			"conditionDescription": llx.StringData(b.GetCondition().GetDescription()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectArtifactRegistryServiceRepository) packages() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	repoPath := g.ResourcePath.Data
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(artifactregistry.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := artifactregistry.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListPackages(ctx, &artifactregistrypb.ListPackagesRequest{Parent: repoPath})

	var res []any
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		name := p.DisplayName
		if name == "" {
			name = parseResourceName(p.Name)
		}

		mqlPkg, err := CreateResource(g.MqlRuntime, "gcp.project.artifactRegistryService.repository.package", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"resourcePath": llx.StringData(p.Name),
			"name":         llx.StringData(name),
			"createTime":   llx.TimeDataPtr(timestampAsTimePtr(p.CreateTime)),
			"updateTime":   llx.TimeDataPtr(timestampAsTimePtr(p.UpdateTime)),
			"annotations":  llx.MapData(convert.MapToInterfaceMap(p.Annotations), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPkg)
	}
	return res, nil
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryPackage) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryPackage) versions() ([]any, error) {
	if g.ResourcePath.Error != nil {
		return nil, g.ResourcePath.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	pkgPath := g.ResourcePath.Data
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(artifactregistry.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := artifactregistry.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// FULL view is required to populate relatedTags and metadata.
	it := client.ListVersions(ctx, &artifactregistrypb.ListVersionsRequest{
		Parent: pkgPath,
		View:   artifactregistrypb.VersionView_FULL,
	})

	var res []any
	for {
		v, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		relatedTags := make([]any, 0, len(v.RelatedTags))
		for _, t := range v.RelatedTags {
			relatedTags = append(relatedTags, parseResourceName(t.Name))
		}

		fingerprints := make([]any, 0, len(v.Fingerprints))
		for _, h := range v.Fingerprints {
			fingerprints = append(fingerprints, map[string]any{
				"type":  h.Type.String(),
				"value": hex.EncodeToString(h.Value),
			})
		}

		var metadata any
		if v.Metadata != nil {
			metadata = v.Metadata.AsMap()
		}

		mqlVer, err := CreateResource(g.MqlRuntime, "gcp.project.artifactRegistryService.repository.package.version", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"resourcePath": llx.StringData(v.Name),
			"name":         llx.StringData(parseResourceName(v.Name)),
			"description":  llx.StringData(v.Description),
			"createTime":   llx.TimeDataPtr(timestampAsTimePtr(v.CreateTime)),
			"updateTime":   llx.TimeDataPtr(timestampAsTimePtr(v.UpdateTime)),
			"relatedTags":  llx.ArrayData(relatedTags, types.String),
			"fingerprints": llx.ArrayData(fingerprints, types.Dict),
			"metadata":     llx.DictData(metadata),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVer)
	}
	return res, nil
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryPackageVersion) id() (string, error) {
	return g.ResourcePath.Data, g.ResourcePath.Error
}

// Sub-resource id() methods

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryVulnScanConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyCondition) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyMostRecentVersions) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryFormatConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryModeConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectArtifactRegistryServiceRepositoryUpstreamPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// Sub-resource constructors

func newVulnScanConfig(runtime *plugin.Runtime, repoPath string, cfg *artifactregistrypb.Repository_VulnerabilityScanningConfig) (*mqlGcpProjectArtifactRegistryServiceRepositoryVulnScanConfig, error) {
	id := repoPath + "/vulnScanConfig"
	var enablementConfig, enablementState, enablementStateReason string
	if cfg != nil {
		enablementConfig = cfg.EnablementConfig.String()
		enablementState = cfg.EnablementState.String()
		enablementStateReason = cfg.EnablementStateReason
	}

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.vulnScanConfig", map[string]*llx.RawData{
		"id":                    llx.StringData(id),
		"enablementConfig":      llx.StringData(enablementConfig),
		"enablementState":       llx.StringData(enablementState),
		"enablementStateReason": llx.StringData(enablementStateReason),
		"lastEnableTime":        llx.TimeDataPtr(timestampAsTimePtrFromVulnScanConfig(cfg)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepositoryVulnScanConfig), nil
}

func timestampAsTimePtrFromVulnScanConfig(cfg *artifactregistrypb.Repository_VulnerabilityScanningConfig) *time.Time {
	if cfg == nil || cfg.LastEnableTime == nil {
		return nil
	}
	return timestampAsTimePtr(cfg.LastEnableTime)
}

func newCleanupPolicies(runtime *plugin.Runtime, repoPath string, policies map[string]*artifactregistrypb.CleanupPolicy) ([]any, error) {
	policyIds := make([]string, 0, len(policies))
	for id := range policies {
		policyIds = append(policyIds, id)
	}
	slices.Sort(policyIds)

	var result []any
	for _, policyId := range policyIds {
		p := policies[policyId]
		cpId := repoPath + "/cleanupPolicy/" + policyId

		// Build condition sub-resource
		condRes, err := newCleanupPolicyCondition(runtime, cpId, p.GetCondition())
		if err != nil {
			return nil, err
		}

		// Build most recent versions sub-resource
		mrvRes, err := newCleanupPolicyMostRecentVersions(runtime, cpId, p.GetMostRecentVersions())
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.cleanupPolicy", map[string]*llx.RawData{
			"id":                 llx.StringData(cpId),
			"action":             llx.StringData(p.Action.String()),
			"policyType":         llx.StringData(cleanupPolicyType(p)),
			"condition":          llx.ResourceData(condRes, "gcp.project.artifactRegistryService.repository.cleanupPolicy.condition"),
			"mostRecentVersions": llx.ResourceData(mrvRes, "gcp.project.artifactRegistryService.repository.cleanupPolicy.mostRecentVersions"),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func newCleanupPolicyCondition(runtime *plugin.Runtime, parentId string, cond *artifactregistrypb.CleanupPolicyCondition) (*mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyCondition, error) {
	id := parentId + "/condition"

	var tagState, olderThan, newerThan string
	var tagPrefixes, versionNamePrefixes, packageNamePrefixes []any

	if cond != nil {
		if cond.TagState != nil {
			tagState = cond.GetTagState().String()
		}
		tagPrefixes = convert.SliceAnyToInterface(cond.TagPrefixes)
		versionNamePrefixes = convert.SliceAnyToInterface(cond.VersionNamePrefixes)
		packageNamePrefixes = convert.SliceAnyToInterface(cond.PackageNamePrefixes)
		if cond.OlderThan != nil {
			olderThan = durationToString(cond.OlderThan)
		}
		if cond.NewerThan != nil {
			newerThan = durationToString(cond.NewerThan)
		}
	}

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.cleanupPolicy.condition", map[string]*llx.RawData{
		"id":                  llx.StringData(id),
		"tagState":            llx.StringData(tagState),
		"tagPrefixes":         llx.ArrayData(tagPrefixes, types.String),
		"versionNamePrefixes": llx.ArrayData(versionNamePrefixes, types.String),
		"packageNamePrefixes": llx.ArrayData(packageNamePrefixes, types.String),
		"olderThan":           llx.StringData(olderThan),
		"newerThan":           llx.StringData(newerThan),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyCondition), nil
}

func newCleanupPolicyMostRecentVersions(runtime *plugin.Runtime, parentId string, mrv *artifactregistrypb.CleanupPolicyMostRecentVersions) (*mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyMostRecentVersions, error) {
	id := parentId + "/mostRecentVersions"

	var keepCount int64
	var packageNamePrefixes []any

	if mrv != nil {
		keepCount = int64(mrv.GetKeepCount())
		packageNamePrefixes = convert.SliceAnyToInterface(mrv.PackageNamePrefixes)
	}

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.cleanupPolicy.mostRecentVersions", map[string]*llx.RawData{
		"id":                  llx.StringData(id),
		"keepCount":           llx.IntData(keepCount),
		"packageNamePrefixes": llx.ArrayData(packageNamePrefixes, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepositoryCleanupPolicyMostRecentVersions), nil
}

// formatConfigFields holds extracted format-specific configuration from a repository.
type formatConfigFields struct {
	immutableTags           bool
	allowSnapshotOverwrites bool
	mavenVersionPolicy      string
}

// extractFormatConfigFields extracts format-specific fields from a repository's FormatConfig oneof.
func extractFormatConfigFields(r *artifactregistrypb.Repository) formatConfigFields {
	var f formatConfigFields
	switch cfg := r.FormatConfig.(type) {
	case *artifactregistrypb.Repository_DockerConfig:
		if cfg.DockerConfig != nil {
			f.immutableTags = cfg.DockerConfig.ImmutableTags
		}
	case *artifactregistrypb.Repository_MavenConfig:
		if cfg.MavenConfig != nil {
			f.allowSnapshotOverwrites = cfg.MavenConfig.AllowSnapshotOverwrites
			f.mavenVersionPolicy = cfg.MavenConfig.VersionPolicy.String()
		}
	}
	return f
}

// cleanupPolicyType returns the policy type discriminator for a cleanup policy's oneof field.
func cleanupPolicyType(p *artifactregistrypb.CleanupPolicy) string {
	if p.GetCondition() != nil {
		return "condition"
	}
	if p.GetMostRecentVersions() != nil {
		return "mostRecentVersions"
	}
	return ""
}

func newFormatConfig(runtime *plugin.Runtime, repoPath string, r *artifactregistrypb.Repository) (*mqlGcpProjectArtifactRegistryServiceRepositoryFormatConfig, error) {
	id := repoPath + "/formatConfig"
	f := extractFormatConfigFields(r)

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.formatConfig", map[string]*llx.RawData{
		"id":                      llx.StringData(id),
		"format":                  llx.StringData(r.Format.String()),
		"immutableTags":           llx.BoolData(f.immutableTags),
		"allowSnapshotOverwrites": llx.BoolData(f.allowSnapshotOverwrites),
		"mavenVersionPolicy":      llx.StringData(f.mavenVersionPolicy),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepositoryFormatConfig), nil
}

func newModeConfig(runtime *plugin.Runtime, repoPath string, r *artifactregistrypb.Repository) (*mqlGcpProjectArtifactRegistryServiceRepositoryModeConfig, error) {
	id := repoPath + "/modeConfig"

	upstreamPolicies := []any{}
	var remoteDescription string
	var disableUpstreamValidation bool

	switch cfg := r.ModeConfig.(type) {
	case *artifactregistrypb.Repository_VirtualRepositoryConfig:
		if cfg.VirtualRepositoryConfig != nil {
			for _, up := range cfg.VirtualRepositoryConfig.UpstreamPolicies {
				upId := repoPath + "/upstreamPolicy/" + up.Id
				upRes, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.upstreamPolicy", map[string]*llx.RawData{
					"id":         llx.StringData(upId),
					"repository": llx.StringData(up.Repository),
					"priority":   llx.IntData(int64(up.Priority)),
				})
				if err != nil {
					return nil, err
				}
				upstreamPolicies = append(upstreamPolicies, upRes)
			}
		}
	case *artifactregistrypb.Repository_RemoteRepositoryConfig:
		if cfg.RemoteRepositoryConfig != nil {
			remoteDescription = cfg.RemoteRepositoryConfig.Description
			disableUpstreamValidation = cfg.RemoteRepositoryConfig.DisableUpstreamValidation
		}
	}

	res, err := CreateResource(runtime, "gcp.project.artifactRegistryService.repository.modeConfig", map[string]*llx.RawData{
		"id":                          llx.StringData(id),
		"upstreamPolicies":            llx.ArrayData(upstreamPolicies, types.Resource("gcp.project.artifactRegistryService.repository.upstreamPolicy")),
		"remoteRepositoryDescription": llx.StringData(remoteDescription),
		"disableUpstreamValidation":   llx.BoolData(disableUpstreamValidation),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepositoryModeConfig), nil
}
