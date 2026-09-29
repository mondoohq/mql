// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/utils/stringx"
	"google.golang.org/api/cloudresourcemanager/v3"
)

const (
	// Discovery flags
	DiscoveryAuto = "auto"
	DiscoveryAll  = "all"

	// top-level assets
	DiscoveryFolders      = "folders"
	DiscoveryOrganization = "organization"
	DiscoveryProjects     = "projects"

	// resources
	DiscoverCloudDNSZones                    = "cloud-dns-zones"
	DiscoverCloudKMSKeyrings                 = "cloud-kms-keyrings"
	DiscoverMemorystoreRedis                 = "memorystore-redis"
	DiscoverMemorystoreRedisCluster          = "memorystore-rediscluster"
	DiscoverCloudSQLMySQL                    = "cloud-sql-mysql"
	DiscoverCloudSQLPostgreSQL               = "cloud-sql-postgresql"
	DiscoverCloudSQLSQLServer                = "cloud-sql-sqlserver"
	DiscoveryBigQueryDatasets                = "bigquery-datasets"
	DiscoveryComputeFirewalls                = "compute-firewalls"
	DiscoveryComputeImages                   = "compute-images"
	DiscoveryComputeNetworks                 = "compute-networks"
	DiscoveryComputeSubnetworks              = "compute-subnetworks"
	DiscoveryGkeClusters                     = "gke-clusters"
	DiscoveryComputeInstances                = "instances"
	DiscoveryStorageBuckets                  = "storage-buckets"
	DiscoverSecretManager                    = "secretmanager-secrets"
	DiscoverPubSubTopics                     = "pubsub-topics"
	DiscoverPubSubSubscriptions              = "pubsub-subscriptions"
	DiscoverPubSubSnapshots                  = "pubsub-snapshots"
	DiscoverCloudRunServices                 = "cloudrun-services"
	DiscoverCloudRunJobs                     = "cloudrun-jobs"
	DiscoverCloudFunctions                   = "cloud-functions"
	DiscoverDataprocClusters                 = "dataproc-clusters"
	DiscoverLoggingBuckets                   = "logging-buckets"
	DiscoverApiKeys                          = "apikeys"
	DiscoverIamServiceAccounts               = "iam-service-accounts"
	DiscoverAlloyDBClusters                  = "alloydb-clusters"
	DiscoverSpannerInstances                 = "spanner-instances"
	DiscoverFirestoreDatabases               = "firestore-databases"
	DiscoverBigtableInstances                = "bigtable-instances"
	DiscoverMemorystoreInstances             = "memorystore-instances"
	DiscoverArtifactRegistryRepos            = "artifactregistry-repositories"
	DiscoverMemcacheInstances                = "memcache-instances"
	DiscoverVertexAIJobs                     = "vertexai-jobs"
	DiscoverVertexAIEndpoints                = "vertexai-endpoints"
	DiscoverVertexAIPipelineJobs             = "vertexai-pipelinejobs"
	DiscoverVertexAINotebookRuntimeTemplates = "vertexai-notebookruntimetemplates"
	DiscoverModelArmorTemplates              = "modelarmor-templates"
	DiscoverDatastreamProfiles               = "datastream-connectionprofiles"
)

// AdditionalResources holds the discovery targets that are not part of the
// default (auto) set. They remain selectable by name and are covered by "all".
//
// Pub/Sub snapshots expire after at most seven days, so discovering them by
// default churns the asset inventory with short-lived assets.
var AdditionalResources = []string{
	DiscoverPubSubSnapshots,
}

// All includes every discovery target: the default set plus the additional
// resources that are not discovered by default.
var All = append(slices.Clone(Auto), AdditionalResources...)

// Auto is the default discovery set, used when no explicit targets are given.
var Auto = []string{
	DiscoveryOrganization,
	DiscoveryFolders,
	DiscoveryProjects,
	DiscoveryComputeImages,
	DiscoveryComputeNetworks,
	DiscoveryComputeSubnetworks,
	DiscoveryComputeFirewalls,
	DiscoveryGkeClusters,
	DiscoveryStorageBuckets,
	DiscoveryBigQueryDatasets,
	DiscoverCloudSQLMySQL,
	DiscoverCloudSQLPostgreSQL,
	DiscoverCloudSQLSQLServer,
	DiscoverCloudDNSZones,
	DiscoverCloudKMSKeyrings,
	DiscoverMemorystoreRedis,
	DiscoverMemorystoreRedisCluster,
	DiscoveryComputeInstances,
	DiscoverSecretManager,
	DiscoverPubSubTopics,
	DiscoverPubSubSubscriptions,
	DiscoverCloudRunServices,
	DiscoverCloudRunJobs,
	DiscoverCloudFunctions,
	DiscoverDataprocClusters,
	DiscoverLoggingBuckets,
	DiscoverApiKeys,
	DiscoverIamServiceAccounts,
	DiscoverAlloyDBClusters,
	DiscoverSpannerInstances,
	DiscoverFirestoreDatabases,
	DiscoverBigtableInstances,
	DiscoverMemorystoreInstances,
	DiscoverArtifactRegistryRepos,
	DiscoverMemcacheInstances,
	DiscoverVertexAIJobs,
	DiscoverVertexAIEndpoints,
	DiscoverVertexAIPipelineJobs,
	DiscoverVertexAINotebookRuntimeTemplates,
	DiscoverModelArmorTemplates,
	DiscoverDatastreamProfiles,
}

var AllAPIResources = []string{
	DiscoveryComputeImages,
	DiscoveryComputeNetworks,
	DiscoveryComputeSubnetworks,
	DiscoveryComputeFirewalls,
	DiscoveryGkeClusters,
	DiscoveryStorageBuckets,
	DiscoveryBigQueryDatasets,
	DiscoverCloudSQLMySQL,
	DiscoverCloudSQLPostgreSQL,
	DiscoverCloudSQLSQLServer,
	DiscoverCloudDNSZones,
	DiscoverCloudKMSKeyrings,
	DiscoverMemorystoreRedis,
	DiscoverMemorystoreRedisCluster,
	DiscoveryComputeInstances,
	DiscoverSecretManager,
	DiscoverPubSubTopics,
	DiscoverPubSubSubscriptions,
	DiscoverPubSubSnapshots,
	DiscoverCloudRunServices,
	DiscoverCloudRunJobs,
	DiscoverCloudFunctions,
	DiscoverDataprocClusters,
	DiscoverLoggingBuckets,
	DiscoverApiKeys,
	DiscoverIamServiceAccounts,
	DiscoverAlloyDBClusters,
	DiscoverSpannerInstances,
	DiscoverFirestoreDatabases,
	DiscoverBigtableInstances,
	DiscoverMemorystoreInstances,
	DiscoverArtifactRegistryRepos,
	DiscoverMemcacheInstances,
	DiscoverVertexAIJobs,
	DiscoverVertexAIEndpoints,
	DiscoverVertexAIPipelineJobs,
	DiscoverVertexAINotebookRuntimeTemplates,
	DiscoverModelArmorTemplates,
	DiscoverDatastreamProfiles,
}

// List of all CloudSQL types, this will be used during discovery
var AllCloudSQLTypes = []string{DiscoverCloudSQLPostgreSQL, DiscoverCloudSQLSQLServer, DiscoverCloudSQLMySQL}

func getDiscoveryTargets(config *inventory.Config) []string {
	targets := config.Discover.Targets

	if stringx.ContainsAnyOf(targets, DiscoveryAll) {
		// return all discovery targets
		return All
	}

	res := []string{}
	for _, target := range targets {
		switch target {
		case DiscoveryAuto:
			res = append(res, Auto...)
		default:
			res = append(res, target)
		}
	}
	return stringx.DedupStringArray(res)
}

// gcpAPIServiceRe matches a GCP service-disabled error message of the form
// "<service> API has not been used in project ...". The captured group is
// the human-readable service name (e.g. "Memorystore",
// "Cloud Memorystore for Memcached", "Cloud KMS").
var gcpAPIServiceRe = regexp.MustCompile(`([A-Z][A-Za-z0-9 &.,/-]*?) API has not been used`)

// runDiscoveryStep runs fn for a single discovery target. A permission /
// API-not-enabled error is logged on one line and swallowed so the rest
// of discovery can continue; any other error is propagated unchanged.
func runDiscoveryStep(target string, fn func() error) error {
	log.Debug().Str("target", target).Msg("gcp.discovery> running discovery step")
	err := fn()
	if err == nil {
		return nil
	}
	if !isSkippable(err) {
		return err
	}
	if m := gcpAPIServiceRe.FindStringSubmatch(err.Error()); len(m) == 2 {
		log.Warn().Msgf("%s API not available. Skipping %s discovery", m[1], target)
	} else {
		log.Warn().Msgf("Permission denied. Skipping %s discovery", target)
	}
	return nil
}

func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}
	discoveryTargets := getDiscoveryTargets(conn.Conf)
	log.Debug().Strs("targets", discoveryTargets).Msg("gcp.discovery> resolved discovery targets")

	if conn.ResourceType() == connection.Organization {
		res, err := NewResource(runtime, "gcp.organization", nil)
		if err != nil {
			return nil, err
		}

		gcpOrg := res.(*mqlGcpOrganization)

		list, err := discoverOrganization(conn, gcpOrg, discoveryTargets)
		if err != nil {
			return nil, err
		}
		in.Spec.Assets = append(in.Spec.Assets, list...)
	} else if conn.ResourceType() == connection.Folder {
		res, err := NewResource(runtime, "gcp.folder", nil)
		if err != nil {
			return nil, err
		}

		gcpFolder := res.(*mqlGcpFolder)
		if stringx.Contains(discoveryTargets, DiscoveryFolders) {
			in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
				PlatformIds: []string{
					connection.NewFolderPlatformID(gcpFolder.Id.Data),
				},
				Name: "GCP Folder " + gcpFolder.Id.Data,
				Platform: &inventory.Platform{
					Name:    "gcp-folder",
					Title:   "GCP Folder",
					Runtime: "gcp",
					Kind:    "gcp-object",
					Family:  []string{"google"},
				},
				Labels: map[string]string{},
				// NOTE: we explicitly do not exclude discovery here, as we want to discover the projects for the folder
				Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithParentConnectionId(conn.Conf.Id))},
			})
		}

		list, err := discoverFolder(conn, gcpFolder, discoveryTargets)
		if err != nil {
			return nil, err
		}
		if len(in.Spec.Assets) > 0 {
			in.Spec.Assets[0].RelatedAssets = list
		}
		in.Spec.Assets = append(in.Spec.Assets, list...)
	} else if conn.ResourceType() == connection.Project {
		res, err := NewResource(runtime, "gcp.project", nil)
		if err != nil {
			return nil, err
		}

		gcpProject := res.(*mqlGcpProject)
		if stringx.Contains(discoveryTargets, DiscoveryProjects) {
			in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
				PlatformIds: []string{
					connection.NewProjectPlatformID(gcpProject.Id.Data),
				},
				Name: "GCP Project " + gcpProject.Id.Data,
				Platform: &inventory.Platform{
					Name:                  "gcp-project",
					Title:                 "GCP Project",
					Runtime:               "gcp",
					Kind:                  "gcp-object",
					Family:                []string{"google"},
					TechnologyUrlSegments: []string{"gcp", gcpProject.Id.Data, "project"},
				},
				Labels:      mapStrInterfaceToMapStrStr(gcpProject.GetLabels().Data),
				Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
			})
		}

		list, err := discoverProject(conn, gcpProject, discoveryTargets)
		if err != nil {
			return nil, err
		}
		if len(in.Spec.Assets) > 0 {
			in.Spec.Assets[0].RelatedAssets = list
		}
		in.Spec.Assets = append(in.Spec.Assets, list...)
	} else if conn.ResourceType() == connection.Gcr {
		conf := conn.Conf
		repository := "gcr.io/" + conf.Options["project-id"]
		if conf.Options["repository"] != "" {
			repository += "/" + conf.Options["repository"]
		}
		conf.Host = repository

		assets, err := resolveGcr(context.Background(), conf)
		if err != nil {
			return nil, err
		}
		in.Spec.Assets = append(in.Spec.Assets, assets...)
		// FIXME: This is a workaround to not double-resolve the GCR repository
		conn.Conf.Discover = nil
	}

	return in, nil
}

func discoverOrganization(conn *connection.GcpConnection, gcpOrg *mqlGcpOrganization, discoveryTargets []string) ([]*inventory.Asset, error) {
	assetList := []*inventory.Asset{}
	if stringx.Contains(discoveryTargets, DiscoveryProjects) {
		projects := gcpOrg.GetProjects()
		if projects.Error != nil {
			return nil, projects.Error
		}

		projectList := projects.Data.GetList() // resolve all projects including nested
		if projectList.Error != nil {
			return nil, projectList.Error
		}

		for i := range projectList.Data {
			project := projectList.Data[i].(*mqlGcpProject)

			projectConf := conn.Conf.Clone(inventory.WithParentConnectionId(conn.Conf.Id))
			if projectConf.Options == nil {
				projectConf.Options = map[string]string{}
			}
			delete(projectConf.Options, "organization-id")
			projectConf.Options["project-id"] = project.Id.Data

			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{
					connection.NewProjectPlatformID(project.Id.Data),
				},
				Name: project.Name.Data,
				Platform: &inventory.Platform{
					Name:                  "gcp-project",
					Title:                 "GCP Project " + project.Name.Data,
					Runtime:               "gcp",
					Kind:                  "gcp-object",
					Family:                []string{"google"},
					TechnologyUrlSegments: []string{"gcp", project.Id.Data, "project"},
				},
				Labels:      mapStrInterfaceToMapStrStr(project.GetLabels().Data),
				Connections: []*inventory.Config{projectConf}, // pass-in the parent connection config
			})

			projectAssets, err := discoverProject(conn, project, discoveryTargets)
			if err != nil {
				return nil, err
			}
			assetList = append(assetList, projectAssets...)
		}
	}
	if stringx.Contains(discoveryTargets, DiscoveryFolders) {
		folders := gcpOrg.GetFolders()
		if folders.Error != nil {
			return nil, folders.Error
		}

		folderList := folders.Data.GetList() // resolve all folders including nested
		if folderList.Error != nil {
			return nil, folderList.Error
		}

		for i := range folderList.Data {
			folder := folderList.Data[i].(*mqlGcpFolder)

			folderConf := conn.Conf.Clone(inventory.WithParentConnectionId(conn.Conf.Id))
			if folderConf.Options == nil {
				folderConf.Options = map[string]string{}
			}
			// Scope the child connection to this folder: drop the inherited
			// organization-id so the asset resolves as a folder (not the org),
			// and set folder-id.
			delete(folderConf.Options, "organization-id")
			folderConf.Options["folder-id"] = folder.Id.Data

			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{
					connection.NewFolderPlatformID(folder.Id.Data),
				},
				Name: "GCP Folder " + folder.Id.Data,
				Platform: &inventory.Platform{
					Name:    "gcp-folder",
					Title:   "GCP Folder",
					Runtime: "gcp",
					Kind:    "gcp-object",
					Family:  []string{"google"},
				},
				Labels: map[string]string{},
				// NOTE: we explicitly do not exclude discovery here, as we want to discover the projects for the folder
				Connections: []*inventory.Config{folderConf},
			})
		}
	}
	return assetList, nil
}

func discoverFolder(conn *connection.GcpConnection, gcpFolder *mqlGcpFolder, discoveryTargets []string) ([]*inventory.Asset, error) {
	assetList := []*inventory.Asset{}

	if stringx.Contains(discoveryTargets, DiscoveryProjects) {
		projects := gcpFolder.GetProjects()
		if projects.Error != nil {
			return nil, projects.Error
		}

		projectList := projects.Data.GetList() // resolve all projects including nested
		if projectList.Error != nil {
			return nil, projectList.Error
		}

		for i := range projectList.Data {
			project := projectList.Data[i].(*mqlGcpProject)

			projectConf := conn.Conf.Clone(inventory.WithParentConnectionId(conn.Conf.Id))
			if projectConf.Options == nil {
				projectConf.Options = map[string]string{}
			}
			delete(projectConf.Options, "folder-id")
			projectConf.Options["project-id"] = project.Id.Data

			assetList = append(assetList, &inventory.Asset{
				PlatformIds: []string{
					connection.NewProjectPlatformID(project.Id.Data),
				},
				Name: project.Name.Data,
				Platform: &inventory.Platform{
					Name:                  "gcp-project",
					Title:                 "GCP Project " + project.Name.Data,
					Runtime:               "gcp",
					Kind:                  "gcp-object",
					Family:                []string{"google"},
					TechnologyUrlSegments: []string{"gcp", project.Id.Data, "project"},
				},
				Labels:      mapStrInterfaceToMapStrStr(project.GetLabels().Data),
				Connections: []*inventory.Config{projectConf}, // pass-in the parent connection config
			})
		}
	}
	return assetList, nil
}

func discoverProject(conn *connection.GcpConnection, gcpProject *mqlGcpProject, discoveryTargets []string) ([]*inventory.Asset, error) {
	assetList := []*inventory.Asset{}
	if stringx.Contains(discoveryTargets, DiscoveryComputeInstances) {
		if err := runDiscoveryStep(DiscoveryComputeInstances, func() error {
			compute := gcpProject.GetCompute()
			if compute.Error != nil {
				return compute.Error
			}
			instances := compute.Data.GetInstances()
			if instances.Error != nil {
				return instances.Error
			}

			for i := range instances.Data {
				instance := instances.Data[i].(*mqlGcpProjectComputeServiceInstance)
				status := instance.GetStatus()
				if status.Data != "RUNNING" {
					continue
				}

				labels := map[string]string{}
				labels["mondoo.com/instance"] = instance.Id.Data
				instancelabels := instance.GetLabels()
				for k, v := range instancelabels.Data {
					labels[k] = v.(string)
				}

				zone := instance.GetZone()
				if zone.Error != nil {
					return zone.Error
				}

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("compute", gcpProject.Id.Data, zone.Data.Name.Data, "instance", instance.Name.Data),
					},
					Name: instance.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-compute-instance",
						Title:                 "GCP Compute Instance",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("compute", gcpProject.Id.Data, zone.Data.Name.Data, "instance", instance.Name.Data),
					},
					Labels: labels,
					// TODO: the current connection handling does not work well for instances
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.Contains(discoveryTargets, DiscoveryComputeImages) {
		if err := runDiscoveryStep(DiscoveryComputeImages, func() error {
			compute := gcpProject.GetCompute()
			if compute.Error != nil {
				return compute.Error
			}
			images := compute.Data.GetImages()
			if images.Error != nil {
				return images.Error
			}

			for i := range images.Data {
				image := images.Data[i].(*mqlGcpProjectComputeServiceImage)
				labels := map[string]string{}
				for k, v := range image.GetLabels().Data {
					labels[k] = v.(string)
				}
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("compute", gcpProject.Id.Data, "global", "image", image.Name.Data),
					},
					Name: image.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-compute-image",
						Title:                 "GCP Compute Image",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("compute", gcpProject.Id.Data, "global", "image", image.Name.Data),
					},
					Labels:      labels,
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.Contains(discoveryTargets, DiscoverCloudKMSKeyrings) {
		if err := runDiscoveryStep(DiscoverCloudKMSKeyrings, func() error {
			kmsservice := gcpProject.GetKms()
			if kmsservice.Error != nil {
				return kmsservice.Error
			}
			keyrings := kmsservice.Data.GetKeyrings()
			if keyrings.Error != nil {
				return keyrings.Error
			}

			for i := range keyrings.Data {
				keyring := keyrings.Data[i].(*mqlGcpProjectKmsServiceKeyring)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloud-kms", gcpProject.Id.Data, keyring.Location.Data, "keyring", keyring.Name.Data),
					},
					Name: keyring.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-kms-keyring",
						Title:                 "GCP Cloud KMS Keyring",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloud-kms", gcpProject.Id.Data, keyring.Location.Data, "keyring", keyring.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.Contains(discoveryTargets, DiscoverCloudDNSZones) {
		if err := runDiscoveryStep(DiscoverCloudDNSZones, func() error {
			dnsservice := gcpProject.GetDns()
			if dnsservice.Error != nil {
				return dnsservice.Error
			}
			managedzones := dnsservice.Data.GetManagedZones()
			if managedzones.Error != nil {
				return managedzones.Error
			}

			for i := range managedzones.Data {
				managedzone := managedzones.Data[i].(*mqlGcpProjectDnsServiceManagedzone)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloud-dns", gcpProject.Id.Data, "global", "zone", managedzone.Id.Data),
					},
					Name: managedzone.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-dns-zone",
						Title:                 "GCP Cloud DNS Zone",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloud-dns", gcpProject.Id.Data, "global", "zone", managedzone.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	// all Cloud SQL discovery flags/types
	if stringx.ContainsAnyOf(discoveryTargets, AllCloudSQLTypes...) {
		if err := runDiscoveryStep("cloud-sql", func() error {
			sqlservice := gcpProject.GetSql()
			if sqlservice.Error != nil {
				return sqlservice.Error
			}
			sqlinstances := sqlservice.Data.GetInstances()
			if sqlinstances.Error != nil {
				return sqlinstances.Error
			}

			for i := range sqlinstances.Data {
				var (
					sqlinstance    = sqlinstances.Data[i].(*mqlGcpProjectSqlServiceInstance)
					sqlTypeVersion = strings.Split(sqlinstance.DatabaseInstalledVersion.Data, "_")
					sqlType        = connection.ParseCloudSQLType(sqlTypeVersion[0])
					platformName   = fmt.Sprintf("gcp-sql-%s", sqlType)
				)

				if !slices.Contains(discoveryTargets, fmt.Sprintf("cloud-sql-%s", sqlType)) {
					log.Debug().
						Str("sql_type", sqlType).
						Msg("gcp.discovery> skipping cloud sql instance")
					continue // only discover known sql types
				}

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloud-sql", gcpProject.Id.Data, sqlinstance.Region.Data, sqlType, sqlinstance.Name.Data),
					},
					Name: sqlinstance.Name.Data,
					Platform: &inventory.Platform{
						Name:                  platformName,
						Title:                 connection.GetTitleForPlatformName(platformName),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloud-sql", gcpProject.Id.Data, sqlinstance.Region.Data, sqlType, sqlinstance.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverMemorystoreRedis) {
		if err := runDiscoveryStep(DiscoverMemorystoreRedis, func() error {
			redisService := gcpProject.GetRedis()
			if redisService.Error != nil {
				return redisService.Error
			}
			redisInstances := redisService.Data.GetInstances()
			if redisInstances.Error != nil {
				return redisInstances.Error
			}

			for i := range redisInstances.Data {
				redisInstance := redisInstances.Data[i].(*mqlGcpProjectRedisServiceInstance)

				// Extract instance name from full resource path
				// (projects/{project}/locations/{location}/instances/{instance_id})
				nameParts := strings.Split(redisInstance.Name.Data, "/")
				instanceName := nameParts[len(nameParts)-1]

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("memorystore", gcpProject.Id.Data, redisInstance.LocationId.Data, "redis", instanceName),
					},
					Name: instanceName,
					Platform: &inventory.Platform{
						Name:                  "gcp-memorystore-redis",
						Title:                 connection.GetTitleForPlatformName("gcp-memorystore-redis"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("memorystore", gcpProject.Id.Data, redisInstance.LocationId.Data, "redis", instanceName),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverMemorystoreRedisCluster) {
		if err := runDiscoveryStep(DiscoverMemorystoreRedisCluster, func() error {
			redisService := gcpProject.GetRedis()
			if redisService.Error != nil {
				return redisService.Error
			}
			redisClusters := redisService.Data.GetClusters()
			if redisClusters.Error != nil {
				return redisClusters.Error
			}

			for i := range redisClusters.Data {
				redisCluster := redisClusters.Data[i].(*mqlGcpProjectRedisServiceCluster)

				// Extract cluster name and location from full resource path
				// (projects/{project}/locations/{location}/clusters/{cluster_id})
				nameParts := strings.Split(redisCluster.Name.Data, "/")
				clusterName := nameParts[len(nameParts)-1]
				var location string
				if len(nameParts) >= 4 {
					location = nameParts[3]
				}

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("memorystore", gcpProject.Id.Data, location, "rediscluster", clusterName),
					},
					Name: clusterName,
					Platform: &inventory.Platform{
						Name:                  "gcp-memorystore-rediscluster",
						Title:                 connection.GetTitleForPlatformName("gcp-memorystore-rediscluster"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("memorystore", gcpProject.Id.Data, location, "rediscluster", clusterName),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverMemorystoreInstances) {
		if err := runDiscoveryStep(DiscoverMemorystoreInstances, func() error {
			memorystoreService := gcpProject.GetMemorystore()
			if memorystoreService.Error != nil {
				return memorystoreService.Error
			}
			instances := memorystoreService.Data.GetInstances()
			if instances.Error != nil {
				return instances.Error
			}
			for i := range instances.Data {
				instance := instances.Data[i].(*mqlGcpProjectMemorystoreServiceInstance)
				// Memorystore instance name is the full resource path:
				// projects/{project}/locations/{location}/instances/{instance}
				instanceName := parseResourceName(instance.Name.Data)
				location := parseLocationFromPath(instance.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("memorystore", gcpProject.Id.Data, location, "instance", instanceName),
					},
					// Short instance names are scoped per-location, so disambiguate
					// the asset display name with the location.
					Name: fmt.Sprintf("%s/%s", location, instanceName),
					Platform: &inventory.Platform{
						Name:                  "gcp-memorystore-instance",
						Title:                 connection.GetTitleForPlatformName("gcp-memorystore-instance"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("memorystore", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Labels:      mapStrInterfaceToMapStrStr(instance.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverArtifactRegistryRepos) {
		if err := runDiscoveryStep(DiscoverArtifactRegistryRepos, func() error {
			artifactSvc := gcpProject.GetArtifactRegistry()
			if artifactSvc.Error != nil {
				return artifactSvc.Error
			}
			repos := artifactSvc.Data.GetRepositories()
			if repos.Error != nil {
				return repos.Error
			}
			for i := range repos.Data {
				repo := repos.Data[i].(*mqlGcpProjectArtifactRegistryServiceRepository)
				repoName := repo.Name.Data
				location := repo.Location.Data
				if location == "" {
					location = "global"
				}

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("artifactregistry", gcpProject.Id.Data, location, "repository", repoName),
					},
					// Repository names are scoped per-location, so disambiguate the
					// asset display name with the location.
					Name: fmt.Sprintf("%s/%s", location, repoName),
					Platform: &inventory.Platform{
						Name:                  "gcp-artifactregistry-repository",
						Title:                 connection.GetTitleForPlatformName("gcp-artifactregistry-repository"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("artifactregistry", gcpProject.Id.Data, location, "repository", repoName),
					},
					Labels:      mapStrInterfaceToMapStrStr(repo.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverMemcacheInstances) {
		if err := runDiscoveryStep(DiscoverMemcacheInstances, func() error {
			memcacheService := gcpProject.GetMemcache()
			if memcacheService.Error != nil {
				return memcacheService.Error
			}
			instances := memcacheService.Data.GetInstances()
			if instances.Error != nil {
				return instances.Error
			}
			for i := range instances.Data {
				instance := instances.Data[i].(*mqlGcpProjectMemcacheServiceInstance)
				// Memcache instance name is the full resource path:
				// projects/{project}/locations/{location}/instances/{instance}
				instanceName := parseResourceName(instance.Name.Data)
				location := parseLocationFromPath(instance.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("memcache", gcpProject.Id.Data, location, "instance", instanceName),
					},
					// Short instance names are scoped per-location, so disambiguate
					// the asset display name with the location.
					Name: fmt.Sprintf("%s/%s", location, instanceName),
					Platform: &inventory.Platform{
						Name:                  "gcp-memcache-instance",
						Title:                 connection.GetTitleForPlatformName("gcp-memcache-instance"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("memcache", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Labels:      mapStrInterfaceToMapStrStr(instance.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverVertexAIJobs) {
		if err := runDiscoveryStep(DiscoverVertexAIJobs, func() error {
			vertexaiService := gcpProject.GetVertexai()
			if vertexaiService.Error != nil {
				return vertexaiService.Error
			}
			jobs := vertexaiService.Data.GetCustomJobs()
			if jobs.Error != nil {
				return jobs.Error
			}
			for i := range jobs.Data {
				job := jobs.Data[i].(*mqlGcpProjectVertexaiServiceCustomJob)
				// Custom job name is the full resource path:
				// projects/{project}/locations/{location}/customJobs/{job}
				jobName := parseResourceName(job.Name.Data)
				location := parseLocationFromPath(job.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("vertexai", gcpProject.Id.Data, location, "job", jobName),
					},
					// Custom job names are scoped per-region, so disambiguate the
					// asset display name with the region.
					Name: fmt.Sprintf("%s/%s", location, jobName),
					Platform: &inventory.Platform{
						Name:                  "gcp-vertexai-job",
						Title:                 connection.GetTitleForPlatformName("gcp-vertexai-job"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("vertexai", gcpProject.Id.Data, location, "job", jobName),
					},
					Labels:      mapStrInterfaceToMapStrStr(job.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverVertexAIEndpoints) {
		if err := runDiscoveryStep(DiscoverVertexAIEndpoints, func() error {
			vertexaiService := gcpProject.GetVertexai()
			if vertexaiService.Error != nil {
				return vertexaiService.Error
			}
			endpoints := vertexaiService.Data.GetEndpoints()
			if endpoints.Error != nil {
				return endpoints.Error
			}
			for i := range endpoints.Data {
				endpoint := endpoints.Data[i].(*mqlGcpProjectVertexaiServiceEndpoint)
				// Endpoint name is the full resource path:
				// projects/{project}/locations/{location}/endpoints/{endpoint}
				endpointName := parseResourceName(endpoint.Name.Data)
				location := parseLocationFromPath(endpoint.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("vertexai", gcpProject.Id.Data, location, "endpoint", endpointName),
					},
					Name: fmt.Sprintf("%s/%s", location, endpointName),
					Platform: &inventory.Platform{
						Name:                  "gcp-vertexai-endpoint",
						Title:                 connection.GetTitleForPlatformName("gcp-vertexai-endpoint"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("vertexai", gcpProject.Id.Data, location, "endpoint", endpointName),
					},
					Labels:      mapStrInterfaceToMapStrStr(endpoint.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverVertexAIPipelineJobs) {
		if err := runDiscoveryStep(DiscoverVertexAIPipelineJobs, func() error {
			vertexaiService := gcpProject.GetVertexai()
			if vertexaiService.Error != nil {
				return vertexaiService.Error
			}
			pipelineJobs := vertexaiService.Data.GetPipelineJobs()
			if pipelineJobs.Error != nil {
				return pipelineJobs.Error
			}
			for i := range pipelineJobs.Data {
				job := pipelineJobs.Data[i].(*mqlGcpProjectVertexaiServicePipelineJob)
				// Pipeline job name is the full resource path:
				// projects/{project}/locations/{location}/pipelineJobs/{job}
				jobName := parseResourceName(job.Name.Data)
				location := parseLocationFromPath(job.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("vertexai", gcpProject.Id.Data, location, "pipelinejob", jobName),
					},
					Name: fmt.Sprintf("%s/%s", location, jobName),
					Platform: &inventory.Platform{
						Name:                  "gcp-vertexai-pipelinejob",
						Title:                 connection.GetTitleForPlatformName("gcp-vertexai-pipelinejob"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("vertexai", gcpProject.Id.Data, location, "pipelinejob", jobName),
					},
					Labels:      mapStrInterfaceToMapStrStr(job.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverVertexAINotebookRuntimeTemplates) {
		if err := runDiscoveryStep(DiscoverVertexAINotebookRuntimeTemplates, func() error {
			vertexaiService := gcpProject.GetVertexai()
			if vertexaiService.Error != nil {
				return vertexaiService.Error
			}
			templates := vertexaiService.Data.GetNotebookRuntimeTemplates()
			if templates.Error != nil {
				return templates.Error
			}
			for i := range templates.Data {
				tmpl := templates.Data[i].(*mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate)
				// Template name is the full resource path:
				// projects/{project}/locations/{location}/notebookRuntimeTemplates/{tmpl}
				tmplName := parseResourceName(tmpl.Name.Data)
				location := parseLocationFromPath(tmpl.Name.Data)

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("vertexai", gcpProject.Id.Data, location, "notebookruntimetemplate", tmplName),
					},
					Name: fmt.Sprintf("%s/%s", location, tmplName),
					Platform: &inventory.Platform{
						Name:                  "gcp-vertexai-notebookruntimetemplate",
						Title:                 connection.GetTitleForPlatformName("gcp-vertexai-notebookruntimetemplate"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("vertexai", gcpProject.Id.Data, location, "notebookruntimetemplate", tmplName),
					},
					Labels:      mapStrInterfaceToMapStrStr(tmpl.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryComputeNetworks) {
		if err := runDiscoveryStep(DiscoveryComputeNetworks, func() error {
			compute := gcpProject.GetCompute()
			if compute.Error != nil {
				return compute.Error
			}
			networks := compute.Data.GetNetworks()
			if networks.Error != nil {
				return networks.Error
			}
			for i := range networks.Data {
				network := networks.Data[i].(*mqlGcpProjectComputeServiceNetwork)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("compute", gcpProject.Id.Data, "global", "network", network.Name.Data),
					},
					Name: network.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-compute-network",
						Title:                 "GCP Compute Network",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("compute", gcpProject.Id.Data, "global", "network", network.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryComputeSubnetworks) {
		if err := runDiscoveryStep(DiscoveryComputeSubnetworks, func() error {
			compute := gcpProject.GetCompute()
			if compute.Error != nil {
				return compute.Error
			}
			networks := compute.Data.GetSubnetworks()
			if networks.Error != nil {
				return networks.Error
			}
			for i := range networks.Data {
				network := networks.Data[i].(*mqlGcpProjectComputeServiceSubnetwork)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("compute", gcpProject.Id.Data, RegionNameFromRegionUrl(network.cacheRegionUrl), "subnetwork", network.Name.Data),
					},
					Name: network.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-compute-subnetwork",
						Title:                 "GCP Compute Subnetwork",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("compute", gcpProject.Id.Data, RegionNameFromRegionUrl(network.cacheRegionUrl), "subnetwork", network.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryComputeFirewalls) {
		if err := runDiscoveryStep(DiscoveryComputeFirewalls, func() error {
			compute := gcpProject.GetCompute()
			if compute.Error != nil {
				return compute.Error
			}
			firewalls := compute.Data.GetFirewalls()
			if firewalls.Error != nil {
				return firewalls.Error
			}
			for i := range firewalls.Data {
				firewall := firewalls.Data[i].(*mqlGcpProjectComputeServiceFirewall)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("compute", gcpProject.Id.Data, "global", "firewall", firewall.Name.Data),
					},
					Name: firewall.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-compute-firewall",
						Title:                 "GCP Compute Firewall",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("compute", gcpProject.Id.Data, "global", "firewall", firewall.Name.Data),
					},
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryGkeClusters) {
		if err := runDiscoveryStep(DiscoveryGkeClusters, func() error {
			gke := gcpProject.GetGke()
			if gke.Error != nil {
				return gke.Error
			}
			clusters := gke.Data.GetClusters()
			if clusters.Error != nil {
				return clusters.Error
			}
			for i := range clusters.Data {
				cluster := clusters.Data[i].(*mqlGcpProjectGkeServiceCluster)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("gke", gcpProject.Id.Data, cluster.GetLocation().Data, "cluster", cluster.Name.Data),
					},
					Name: cluster.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-gke-cluster",
						Title:                 "GCP GKE Cluster",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("gke", gcpProject.Id.Data, cluster.GetLocation().Data, "cluster", cluster.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(cluster.GetResourceLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryStorageBuckets) {
		if err := runDiscoveryStep(DiscoveryStorageBuckets, func() error {
			storage := gcpProject.GetStorage()
			if storage.Error != nil {
				return storage.Error
			}
			buckets := storage.Data.GetBuckets()
			if buckets.Error != nil {
				return buckets.Error
			}
			for i := range buckets.Data {
				bucket := buckets.Data[i].(*mqlGcpProjectStorageServiceBucket)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("storage", gcpProject.Id.Data, bucket.GetLocation().Data, "bucket", bucket.Name.Data),
					},
					Name: bucket.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-storage-bucket",
						Title:                 "GCP Storage Bucket",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("storage", gcpProject.Id.Data, bucket.GetLocation().Data, "bucket", bucket.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(bucket.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoveryBigQueryDatasets) {
		if err := runDiscoveryStep(DiscoveryBigQueryDatasets, func() error {
			bq := gcpProject.GetBigquery()
			if bq.Error != nil {
				return bq.Error
			}
			datasets := bq.Data.GetDatasets()
			if datasets.Error != nil {
				return datasets.Error
			}
			for i := range datasets.Data {
				dataset := datasets.Data[i].(*mqlGcpProjectBigqueryServiceDataset)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("bigquery", gcpProject.Id.Data, dataset.GetLocation().Data, "dataset", dataset.Id.Data),
					},
					Name: dataset.Id.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-bigquery-dataset",
						Title:                 "GCP BigQuery Dataset",
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("bigquery", gcpProject.Id.Data, dataset.GetLocation().Data, "dataset", dataset.Id.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(dataset.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))}, // pass-in the parent connection config
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if stringx.ContainsAnyOf(discoveryTargets, DiscoverSecretManager) {
		if err := runDiscoveryStep(DiscoverSecretManager, func() error {
			secretmanagerService := gcpProject.GetSecretmanager()
			if secretmanagerService.Error != nil {
				return secretmanagerService.Error
			}
			secrets := secretmanagerService.Data.GetSecrets()
			if secrets.Error != nil {
				return secrets.Error
			}
			for i := range secrets.Data {
				secret := secrets.Data[i].(*mqlGcpProjectSecretmanagerServiceSecret)
				// A regional secret is placed in its location, so it cannot
				// share a platform id with a global secret of the same name.
				assetRegion := "global"
				if secret.Location.Data != "" {
					assetRegion = secret.Location.Data
				}
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("secretmanager", gcpProject.Id.Data, assetRegion, "secret", secret.Name.Data),
					},
					Name: secret.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-secretmanager-secret",
						Title:                 connection.GetTitleForPlatformName("gcp-secretmanager-secret"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("secretmanager", gcpProject.Id.Data, assetRegion, "secret", secret.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(secret.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverModelArmorTemplates) {
		if err := runDiscoveryStep(DiscoverModelArmorTemplates, func() error {
			modelArmorService := gcpProject.GetModelArmor()
			if modelArmorService.Error != nil {
				return modelArmorService.Error
			}
			templates := modelArmorService.Data.GetTemplates()
			if templates.Error != nil {
				return templates.Error
			}
			for i := range templates.Data {
				template := templates.Data[i].(*mqlGcpProjectModelArmorServiceTemplate)
				location := parseLocationFromPath(template.Name.Data)
				shortName := parseResourceName(template.Name.Data)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("modelarmor", gcpProject.Id.Data, location, "template", shortName),
					},
					Name: shortName,
					Platform: &inventory.Platform{
						Name:                  "gcp-modelarmor-template",
						Title:                 connection.GetTitleForPlatformName("gcp-modelarmor-template"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("modelarmor", gcpProject.Id.Data, location, "template", shortName),
					},
					Labels:      mapStrInterfaceToMapStrStr(template.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverDatastreamProfiles) {
		if err := runDiscoveryStep(DiscoverDatastreamProfiles, func() error {
			datastreamService := gcpProject.GetDatastream()
			if datastreamService.Error != nil {
				return datastreamService.Error
			}
			profiles := datastreamService.Data.GetConnectionProfiles()
			if profiles.Error != nil {
				return profiles.Error
			}
			for i := range profiles.Data {
				profile := profiles.Data[i].(*mqlGcpProjectDatastreamServiceConnectionProfile)
				location := parseLocationFromPath(profile.Name.Data)
				shortName := parseResourceName(profile.Name.Data)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("datastream", gcpProject.Id.Data, location, "connectionprofile", shortName),
					},
					Name: shortName,
					Platform: &inventory.Platform{
						Name:                  "gcp-datastream-connectionprofile",
						Title:                 connection.GetTitleForPlatformName("gcp-datastream-connectionprofile"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("datastream", gcpProject.Id.Data, location, "connectionprofile", shortName),
					},
					Labels:      mapStrInterfaceToMapStrStr(profile.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverPubSubTopics) {
		if err := runDiscoveryStep(DiscoverPubSubTopics, func() error {
			pubsubService := gcpProject.GetPubsub()
			if pubsubService.Error != nil {
				return pubsubService.Error
			}
			topics := pubsubService.Data.GetTopics()
			if topics.Error != nil {
				return topics.Error
			}
			for i := range topics.Data {
				topic := topics.Data[i].(*mqlGcpProjectPubsubServiceTopic)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("pubsub", gcpProject.Id.Data, "global", "topic", topic.Name.Data),
					},
					Name: topic.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-pubsub-topic",
						Title:                 connection.GetTitleForPlatformName("gcp-pubsub-topic"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("pubsub", gcpProject.Id.Data, "global", "topic", topic.Name.Data),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverPubSubSubscriptions) {
		if err := runDiscoveryStep(DiscoverPubSubSubscriptions, func() error {
			pubsubService := gcpProject.GetPubsub()
			if pubsubService.Error != nil {
				return pubsubService.Error
			}
			subscriptions := pubsubService.Data.GetSubscriptions()
			if subscriptions.Error != nil {
				return subscriptions.Error
			}
			for i := range subscriptions.Data {
				sub := subscriptions.Data[i].(*mqlGcpProjectPubsubServiceSubscription)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("pubsub", gcpProject.Id.Data, "global", "subscription", sub.Name.Data),
					},
					Name: sub.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-pubsub-subscription",
						Title:                 connection.GetTitleForPlatformName("gcp-pubsub-subscription"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("pubsub", gcpProject.Id.Data, "global", "subscription", sub.Name.Data),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverPubSubSnapshots) {
		if err := runDiscoveryStep(DiscoverPubSubSnapshots, func() error {
			pubsubService := gcpProject.GetPubsub()
			if pubsubService.Error != nil {
				return pubsubService.Error
			}
			snapshots := pubsubService.Data.GetSnapshots()
			if snapshots.Error != nil {
				return snapshots.Error
			}
			for i := range snapshots.Data {
				snap := snapshots.Data[i].(*mqlGcpProjectPubsubServiceSnapshot)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("pubsub", gcpProject.Id.Data, "global", "snapshot", snap.Name.Data),
					},
					Name: snap.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-pubsub-snapshot",
						Title:                 connection.GetTitleForPlatformName("gcp-pubsub-snapshot"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("pubsub", gcpProject.Id.Data, "global", "snapshot", snap.Name.Data),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverCloudRunServices) {
		if err := runDiscoveryStep(DiscoverCloudRunServices, func() error {
			cloudRunService := gcpProject.GetCloudRun()
			if cloudRunService.Error != nil {
				return cloudRunService.Error
			}
			services := cloudRunService.Data.GetServices()
			if services.Error != nil {
				return services.Error
			}
			for i := range services.Data {
				svc := services.Data[i].(*mqlGcpProjectCloudRunServiceService)
				region := svc.Region.Data
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloudrun", gcpProject.Id.Data, region, "service", svc.Name.Data),
					},
					Name: svc.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-cloudrun-service",
						Title:                 connection.GetTitleForPlatformName("gcp-cloudrun-service"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloudrun", gcpProject.Id.Data, region, "service", svc.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(svc.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverCloudRunJobs) {
		if err := runDiscoveryStep(DiscoverCloudRunJobs, func() error {
			cloudRunService := gcpProject.GetCloudRun()
			if cloudRunService.Error != nil {
				return cloudRunService.Error
			}
			jobs := cloudRunService.Data.GetJobs()
			if jobs.Error != nil {
				return jobs.Error
			}
			for i := range jobs.Data {
				job := jobs.Data[i].(*mqlGcpProjectCloudRunServiceJob)
				region := job.Region.Data
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloudrun", gcpProject.Id.Data, region, "job", job.Name.Data),
					},
					Name: job.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-cloudrun-job",
						Title:                 connection.GetTitleForPlatformName("gcp-cloudrun-job"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloudrun", gcpProject.Id.Data, region, "job", job.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(job.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverCloudFunctions) {
		if err := runDiscoveryStep(DiscoverCloudFunctions, func() error {
			funcs := gcpProject.GetCloudFunctions()
			if funcs.Error != nil {
				return funcs.Error
			}
			for i := range funcs.Data {
				fn := funcs.Data[i].(*mqlGcpProjectCloudFunction)
				location := fn.Location.Data
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("cloud-functions", gcpProject.Id.Data, location, "function", fn.Name.Data),
					},
					Name: fn.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-cloud-function",
						Title:                 connection.GetTitleForPlatformName("gcp-cloud-function"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("cloud-functions", gcpProject.Id.Data, location, "function", fn.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(fn.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverDataprocClusters) {
		if err := runDiscoveryStep(DiscoverDataprocClusters, func() error {
			dataprocService := gcpProject.GetDataproc()
			if dataprocService.Error != nil {
				return dataprocService.Error
			}
			clusters := dataprocService.Data.GetClusters()
			if clusters.Error != nil {
				return clusters.Error
			}
			for i := range clusters.Data {
				cluster := clusters.Data[i].(*mqlGcpProjectDataprocServiceCluster)
				location := cluster.Location.Data
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("dataproc", gcpProject.Id.Data, location, "cluster", cluster.Name.Data),
					},
					Name: cluster.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-dataproc-cluster",
						Title:                 connection.GetTitleForPlatformName("gcp-dataproc-cluster"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("dataproc", gcpProject.Id.Data, location, "cluster", cluster.Name.Data),
					},
					Labels:      mapStrInterfaceToMapStrStr(cluster.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverAlloyDBClusters) {
		if err := runDiscoveryStep(DiscoverAlloyDBClusters, func() error {
			alloydbService := gcpProject.GetAlloydb()
			if alloydbService.Error != nil {
				return alloydbService.Error
			}
			clusters := alloydbService.Data.GetClusters()
			if clusters.Error != nil {
				return clusters.Error
			}
			for i := range clusters.Data {
				cluster := clusters.Data[i].(*mqlGcpProjectAlloydbServiceCluster)
				nameParts := strings.Split(cluster.Name.Data, "/")
				clusterName := nameParts[len(nameParts)-1]
				location := cluster.Location.Data

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("alloydb", gcpProject.Id.Data, location, "cluster", clusterName),
					},
					Name: clusterName,
					Platform: &inventory.Platform{
						Name:                  "gcp-alloydb-cluster",
						Title:                 connection.GetTitleForPlatformName("gcp-alloydb-cluster"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("alloydb", gcpProject.Id.Data, location, "cluster", clusterName),
					},
					Labels:      mapStrInterfaceToMapStrStr(cluster.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverSpannerInstances) {
		if err := runDiscoveryStep(DiscoverSpannerInstances, func() error {
			spannerService := gcpProject.GetSpanner()
			if spannerService.Error != nil {
				return spannerService.Error
			}
			instances := spannerService.Data.GetInstances()
			if instances.Error != nil {
				return instances.Error
			}
			for i := range instances.Data {
				instance := instances.Data[i].(*mqlGcpProjectSpannerServiceInstance)
				// Spanner instance names are global within a project (no location
				// segment); the regional placement is expressed by the instance's
				// config. Use "global" here to match the platform-id scheme used
				// by other non-regional resources (e.g. API keys, IAM).
				instanceName := parseResourceName(instance.Name.Data)
				location := "global"

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("spanner", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Name: instanceName,
					Platform: &inventory.Platform{
						Name:                  "gcp-spanner-instance",
						Title:                 connection.GetTitleForPlatformName("gcp-spanner-instance"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("spanner", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Labels:      mapStrInterfaceToMapStrStr(instance.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverFirestoreDatabases) {
		if err := runDiscoveryStep(DiscoverFirestoreDatabases, func() error {
			firestoreService := gcpProject.GetFirestore()
			if firestoreService.Error != nil {
				return firestoreService.Error
			}
			databases := firestoreService.Data.GetDatabases()
			if databases.Error != nil {
				return databases.Error
			}
			for i := range databases.Data {
				database := databases.Data[i].(*mqlGcpProjectFirestoreServiceDatabase)
				dbName := parseResourceName(database.Name.Data)
				location := database.LocationId.Data
				if location == "" {
					location = "global"
				}

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("firestore", gcpProject.Id.Data, location, "database", dbName),
					},
					Name: dbName,
					Platform: &inventory.Platform{
						Name:                  "gcp-firestore-database",
						Title:                 connection.GetTitleForPlatformName("gcp-firestore-database"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("firestore", gcpProject.Id.Data, location, "database", dbName),
					},
					// Firestore's adminpb.Database has Tags but no Labels field;
					// emit an empty map for consistency with other GCP assets.
					Labels:      map[string]string{},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverBigtableInstances) {
		if err := runDiscoveryStep(DiscoverBigtableInstances, func() error {
			bigtableService := gcpProject.GetBigtable()
			if bigtableService.Error != nil {
				return bigtableService.Error
			}
			instances := bigtableService.Data.GetInstances()
			if instances.Error != nil {
				return instances.Error
			}
			for i := range instances.Data {
				instance := instances.Data[i].(*mqlGcpProjectBigtableServiceInstance)
				// Bigtable instances are themselves location-independent; their
				// placement is per-cluster. Use "global" here to match the
				// project-scoped platform-id scheme used by API keys and IAM.
				instanceName := parseResourceName(instance.Name.Data)
				location := "global"

				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("bigtable", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Name: instanceName,
					Platform: &inventory.Platform{
						Name:                  "gcp-bigtable-instance",
						Title:                 connection.GetTitleForPlatformName("gcp-bigtable-instance"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("bigtable", gcpProject.Id.Data, location, "instance", instanceName),
					},
					Labels:      mapStrInterfaceToMapStrStr(instance.GetLabels().Data),
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverLoggingBuckets) {
		if err := runDiscoveryStep(DiscoverLoggingBuckets, func() error {
			loggingService := gcpProject.GetLogging()
			if loggingService.Error != nil {
				return loggingService.Error
			}
			buckets := loggingService.Data.GetBuckets()
			if buckets.Error != nil {
				return buckets.Error
			}
			for i := range buckets.Data {
				bucket := buckets.Data[i].(*mqlGcpProjectLoggingserviceBucket)
				bucketName := parseResourceName(bucket.Name.Data)
				location := bucket.Location.Data
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("logging", gcpProject.Id.Data, location, "bucket", bucketName),
					},
					Name: bucketName,
					Platform: &inventory.Platform{
						Name:                  "gcp-logging-bucket",
						Title:                 connection.GetTitleForPlatformName("gcp-logging-bucket"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("logging", gcpProject.Id.Data, location, "bucket", bucketName),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverApiKeys) {
		if err := runDiscoveryStep(DiscoverApiKeys, func() error {
			keys := gcpProject.GetApiKeys()
			if keys.Error != nil {
				return keys.Error
			}
			for i := range keys.Data {
				key := keys.Data[i].(*mqlGcpProjectApiKey)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("apikeys", gcpProject.Id.Data, "global", "key", key.Id.Data),
					},
					Name: key.Name.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-apikey",
						Title:                 connection.GetTitleForPlatformName("gcp-apikey"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("apikeys", gcpProject.Id.Data, "global", "key", key.Id.Data),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if stringx.ContainsAnyOf(discoveryTargets, DiscoverIamServiceAccounts) {
		if err := runDiscoveryStep(DiscoverIamServiceAccounts, func() error {
			iamSvc := gcpProject.GetIam()
			if iamSvc.Error != nil {
				return iamSvc.Error
			}
			sas := iamSvc.Data.GetServiceAccounts()
			if sas.Error != nil {
				return sas.Error
			}
			for i := range sas.Data {
				sa := sas.Data[i].(*mqlGcpProjectIamServiceServiceAccount)
				assetList = append(assetList, &inventory.Asset{
					PlatformIds: []string{
						connection.NewResourcePlatformID("iam", gcpProject.Id.Data, "global", "service-account", sa.UniqueId.Data),
					},
					Name: sa.Email.Data,
					Platform: &inventory.Platform{
						Name:                  "gcp-iam-service-account",
						Title:                 connection.GetTitleForPlatformName("gcp-iam-service-account"),
						Runtime:               "gcp",
						Kind:                  "gcp-object",
						Family:                []string{"google"},
						TechnologyUrlSegments: connection.ResourceTechnologyUrl("iam", gcpProject.Id.Data, "global", "service-account", sa.UniqueId.Data),
					},
					Connections: []*inventory.Config{conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))},
				})
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if conn.Filters.PropagateProjectLabels {
		projectLabels := mapStrInterfaceToMapStrStr(gcpProject.GetLabels().Data)
		propagateProjectLabelsToAssets(assetList, projectLabels)
	}

	log.Debug().
		Str("project", gcpProject.Id.Data).
		Int("assets", len(assetList)).
		Msg("gcp.discovery> project discovery complete")
	return assetList, nil
}

// propagateProjectLabelsToAssets merges the project's labels into every asset
// discovered under that project. An asset's own labels take precedence, so
// project labels only fill in keys the asset doesn't already define.
func propagateProjectLabelsToAssets(assets []*inventory.Asset, projectLabels map[string]string) {
	if len(projectLabels) == 0 {
		return
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		for k, v := range projectLabels {
			if _, exists := a.Labels[k]; !exists {
				a.Labels[k] = v
			}
		}
	}
}

func resolveGcr(ctx context.Context, conf *inventory.Config) ([]*inventory.Asset, error) {
	resolved := []*inventory.Asset{}
	repository := conf.Host

	log.Debug().Str("registry", repository).Msg("fetch meta information from gcr registry")
	gcrImages := NewGCRImages()
	assetList, err := gcrImages.ListRepository(repository, true)
	if err != nil {
		log.Error().Err(err).Msg("could not fetch gcr images")
		return nil, err
	}

	for i := range assetList {
		log.Debug().Str("name", assetList[i].Name).Str("image", assetList[i].Connections[0].Host+assetList[i].Connections[0].Path).Msg("resolved image")
		resolved = append(resolved, assetList[i])
	}

	return resolved, nil
}

func NewGCRImages() *GcrImages {
	return &GcrImages{}
}

type GcrImages struct{}

func (a *GcrImages) Name() string {
	return "GCP Container Registry Discover"
}

// lists a repository like "gcr.io/mondoo-base-infra"
func (a *GcrImages) ListRepository(repository string, recursive bool) ([]*inventory.Asset, error) {
	// Both of these are reachable with user-supplied input (the repository is
	// built from the connection's project-id and an optional --repository
	// option), so they must return an error rather than exit: log.Fatal calls
	// os.Exit and would take the whole provider process down.
	repo, err := name.NewRepository(repository)
	if err != nil {
		return nil, errors.Join(errors.New("could not create repository "+repository), err)
	}

	auth, err := google.Keychain.Resolve(repo.Registry)
	if err != nil {
		return nil, errors.Join(errors.New("failed to get auth for repository "+repository), err)
	}

	imgs := []*inventory.Asset{}

	toAssetFunc := func(repo name.Repository, tags *google.Tags, err error) error {
		if err != nil {
			return err
		}

		for digest := range tags.Manifests {
			repoURL := repo.String()
			imageUrl := repoURL + "@" + digest

			asset := &inventory.Asset{
				Connections: []*inventory.Config{
					{
						Type: "container-registry",
						Host: imageUrl,
					},
				},
			}
			imgs = append(imgs, asset)
		}
		return nil
	}

	// walk nested repos
	if recursive {
		err := google.Walk(repo, toAssetFunc, google.WithAuth(auth))
		if err != nil {
			return nil, err
		}
		return imgs, nil
	}

	// NOTE: since we're not recursing, we ignore tags.Children
	tags, err := google.List(repo, google.WithAuth(auth))
	if err != nil {
		return nil, err
	}

	err = toAssetFunc(repo, tags, nil)
	if err != nil {
		return nil, err
	}
	return imgs, nil
}

// List uses your GCP credentials to iterate over all your projects to identify potential repos
func (a *GcrImages) List() ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}

	ctx := context.Background()
	resSrv, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, err
	}

	var projectNames []string
	if err := resSrv.Projects.List().Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, p := range page.Projects {
			projectNames = append(projectNames, p.Name)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(len(projectNames))
	mux := &sync.Mutex{}
	for _, project := range projectNames {
		go func(project string) {
			repoAssets, err := a.ListRepository("gcr.io/"+project, true)
			if err == nil && repoAssets != nil {
				mux.Lock()
				assets = append(assets, repoAssets...)
				mux.Unlock()
			}
			wg.Done()
		}(project)
	}

	wg.Wait()
	return assets, nil
}

func mapStrInterfaceToMapStrStr(m map[string]any) map[string]string {
	strMap := make(map[string]string)
	for k, v := range m {
		if v != nil {
			strMap[k] = v.(string)
		}
	}
	return strMap
}
