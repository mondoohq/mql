// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validatedGCPPermissions is the authoritative set of GCP IAM permissions that
// our manifest (gcp.permissions.json) must contain — no more, no less.
//
// IMPORTANT: Do NOT edit this list just to make the test pass after a provider
// code change. Every entry here has been validated as a REAL GCP IAM permission
// against the live IAM API (`gcloud iam list-testable-permissions` on a project
// and an organization, cross-checked against predefined roles). The permission
// scanner derives permission strings heuristically from SDK method names and
// regularly emits names that are NOT real permissions (wrong casing, singular
// vs. plural, abbreviated resource segments such as certificatemanager.certs,
// or an entirely different resource). When the scanner produces a new
// permission, first confirm the real permission name, add a
// gcpPermissionOverrides entry in
// providers-sdk/v1/util/permissions/permissions.go if the derived name is
// wrong, regenerate the manifest, and only then add the validated name here.
//
// Note: when verifying against list-testable-permissions, remember that the API
// omits permissions whose customRolesSupportLevel is NOT_SUPPORTED, so absence
// from the testable list is not by itself proof that a permission is unreal —
// cross-check the IAM permissions reference and the method's REST docs. (For
// example, the Cloud Identity Groups API is governed by directory/OAuth scopes
// rather than Cloud IAM, so no cloudidentity.* permission exists; and
// dlp.discoveryConfigs.list is not real — discoveryConfigs.list requires
// dlp.jobTriggers.list per Google's REST reference.)
var validatedGCPPermissions = []string{
	"accessapproval.settings.get",
	"aiplatform.batchPredictionJobs.list",
	"aiplatform.cachedContents.list",
	"aiplatform.customJobs.get",
	"aiplatform.customJobs.list",
	"aiplatform.datasets.list",
	"aiplatform.deploymentResourcePools.list",
	"aiplatform.endpoints.get",
	"aiplatform.endpoints.list",
	"aiplatform.featureGroups.list",
	"aiplatform.featureOnlineStores.list",
	"aiplatform.hyperparameterTuningJobs.list",
	"aiplatform.indexEndpoints.list",
	"aiplatform.indexes.list",
	"aiplatform.metadataStores.list",
	"aiplatform.modelDeploymentMonitoringJobs.list",
	"aiplatform.models.get",
	"aiplatform.models.getIamPolicy",
	"aiplatform.models.list",
	"aiplatform.notebookExecutionJobs.list",
	"aiplatform.notebookRuntimeTemplates.get",
	"aiplatform.notebookRuntimeTemplates.getIamPolicy",
	"aiplatform.notebookRuntimeTemplates.list",
	"aiplatform.notebookRuntimes.list",
	"aiplatform.persistentResources.list",
	"aiplatform.pipelineJobs.get",
	"aiplatform.pipelineJobs.list",
	"aiplatform.ragCorpora.list",
	"aiplatform.reasoningEngines.list",
	"aiplatform.schedules.get",
	"aiplatform.schedules.list",
	"aiplatform.tensorboards.list",
	"aiplatform.trainingPipelines.list",
	"aiplatform.tuningJobs.list",
	"alloydb.backups.list",
	"alloydb.clusters.list",
	"alloydb.instances.list",
	"alloydb.users.list",
	"apikeys.keys.list",
	"artifactregistry.packages.list",
	"artifactregistry.repositories.getIamPolicy",
	"artifactregistry.repositories.list",
	"artifactregistry.versions.list",
	"backupdr.backupPlans.list",
	"backupdr.backupVaults.list",
	"backupdr.bvdataSources.list",
	"backupdr.managementServers.list",
	"batch.jobs.list",
	"bigquery.connections.list",
	"bigquery.reservations.list",
	"bigtable.appProfiles.list",
	"binaryauthorization.attestors.list",
	"binaryauthorization.policy.get",
	"certificatemanager.certissuanceconfigs.get",
	"certificatemanager.certissuanceconfigs.list",
	"certificatemanager.certmapentries.list",
	"certificatemanager.certmaps.list",
	"certificatemanager.certs.get",
	"certificatemanager.certs.list",
	"certificatemanager.dnsauthorizations.get",
	"certificatemanager.dnsauthorizations.list",
	"certificatemanager.trustconfigs.list",
	"cloudasset.assets.analyzeIamPolicy",
	"cloudasset.assets.searchAllIamPolicies",
	"cloudasset.assets.searchAllResources",
	"cloudbuild.builds.list",
	"cloudbuild.workerpools.list",
	"clouddeploy.deliveryPipelines.list",
	"clouddeploy.releases.list",
	"clouddeploy.targets.list",
	"cloudfunctions.functions.getIamPolicy",
	"cloudfunctions.functions.list",
	"cloudidentity.groups.getsecuritysettings",
	"cloudkms.cryptoKeyVersions.list",
	"cloudkms.cryptoKeys.get",
	"cloudkms.cryptoKeys.getIamPolicy",
	"cloudkms.cryptoKeys.list",
	"cloudkms.ekmConnections.list",
	"cloudkms.importJobs.list",
	"cloudkms.keyRings.list",
	"cloudkms.locations.list",
	"cloudkms.retiredResources.list",
	"cloudscheduler.jobs.list",
	"cloudsql.backupRuns.list",
	"cloudsql.databases.list",
	"cloudsql.instances.list",
	"cloudsql.sslCerts.list",
	"cloudsql.users.list",
	"cloudtasks.queues.getIamPolicy",
	"cloudtasks.queues.list",
	"composer.environments.list",
	"compute.addresses.list",
	"compute.backendBuckets.list",
	"compute.backendServices.list",
	"compute.disks.list",
	"compute.externalVpnGateways.list",
	"compute.firewallPolicies.get",
	"compute.firewallPolicies.list",
	"compute.firewalls.list",
	"compute.healthChecks.list",
	"compute.images.getIamPolicy",
	"compute.images.list",
	"compute.instanceGroupManagers.list",
	"compute.instanceGroups.list",
	"compute.instanceTemplates.list",
	"compute.instances.list",
	"compute.interconnectAttachments.list",
	"compute.interconnects.list",
	"compute.machineTypes.get",
	"compute.machineTypes.list",
	"compute.networkEndpointGroups.list",
	"compute.networks.get",
	"compute.networks.list",
	"compute.packetMirrorings.list",
	"compute.projects.get",
	"compute.publicAdvertisedPrefixes.list",
	"compute.regionSecurityPolicies.get",
	"compute.regions.get",
	"compute.regions.list",
	"compute.routers.list",
	"compute.routes.list",
	"compute.securityPolicies.get",
	"compute.securityPolicies.list",
	"compute.serviceAttachments.list",
	"compute.snapshots.getIamPolicy",
	"compute.snapshots.list",
	"compute.sslCertificates.list",
	"compute.sslPolicies.list",
	"compute.storagePools.list",
	"compute.targetHttpProxies.list",
	"compute.targetHttpsProxies.list",
	"compute.targetPools.list",
	"compute.targetSslProxies.list",
	"compute.targetTcpProxies.list",
	"compute.urlMaps.list",
	"compute.vpnGateways.list",
	"compute.vpnTunnels.list",
	"compute.zones.get",
	"compute.zones.list",
	"container.clusters.list",
	"containeranalysis.occurrences.list",
	"dataflow.jobs.list",
	"dataplex.assets.list",
	"dataplex.lakes.list",
	"dataplex.zones.list",
	"dataproc.autoscalingPolicies.list",
	"dataproc.clusters.getIamPolicy",
	"dataproc.clusters.list",
	"dataproc.jobs.list",
	"datastore.backupSchedules.list",
	"datastore.databases.list",
	"datastore.indexes.list",
	"datastream.connectionProfiles.get",
	"datastream.connectionProfiles.list",
	"datastream.privateConnections.get",
	"datastream.privateConnections.list",
	"datastream.routes.list",
	"datastream.streams.list",
	"discoveryengine.dataStores.get",
	"discoveryengine.dataStores.list",
	"discoveryengine.engines.list",
	"dlp.columnDataProfiles.list",
	"dlp.connections.list",
	"dlp.deidentifyTemplates.list",
	"dlp.fileStoreProfiles.list",
	"dlp.inspectTemplates.list",
	"dlp.jobTriggers.list",
	"dlp.jobs.list",
	"dlp.projectDataProfiles.list",
	"dlp.storedInfoTypes.list",
	"dlp.tableDataProfiles.list",
	"dns.dnsKeys.list",
	"dns.managedZones.getIamPolicy",
	"dns.managedZones.list",
	"dns.policies.list",
	"dns.resourceRecordSets.list",
	"dns.responsePolicies.list",
	"documentai.processorVersions.get",
	"documentai.processorVersions.list",
	"documentai.processors.list",
	// Real and required (Cloud Domains), but customRolesSupportLevel is
	// NOT_SUPPORTED: GCP grants it only via a predefined role (roles/domains.viewer),
	// never a custom role. It is therefore absent from list-testable-permissions and
	// rejected by `gcloud iam roles create` — that is expected, not a bug. Keep it.
	"domains.registrations.list",
	"essentialcontacts.contacts.list",
	"eventarc.channels.list",
	"eventarc.triggers.list",
	"file.instances.list",
	"gkebackup.backupPlans.list",
	"gkebackup.restorePlans.list",
	"iam.denypolicies.list",
	"iam.policyBindings.list",
	"iam.principalAccessBoundaryPolicies.list",
	"iam.roles.list",
	"iam.serviceAccountKeys.list",
	"iam.serviceAccounts.getIamPolicy",
	"iam.serviceAccounts.list",
	"iam.workforcePoolProviders.list",
	"iam.workforcePools.list",
	"iam.workloadIdentityPoolProviders.list",
	"iam.workloadIdentityPools.list",
	"iap.projects.getSettings",
	"iap.tunnelDestGroups.list",
	"iap.web.getIamPolicy",
	"iap.web.getSettings",
	"ids.endpoints.list",
	"logging.buckets.list",
	"logging.exclusions.list",
	"logging.logMetrics.list",
	"logging.settings.get",
	"logging.sinks.list",
	"logging.views.list",
	"memcache.instances.get",
	"memcache.instances.list",
	"memorystore.backupCollections.get",
	"memorystore.backupCollections.list",
	"memorystore.backups.list",
	"memorystore.instances.get",
	"memorystore.instances.list",
	"modelarmor.floorSettings.get",
	"modelarmor.templates.get",
	"modelarmor.templates.list",
	"monitoring.alertPolicies.list",
	"monitoring.dashboards.list",
	"monitoring.groups.list",
	"monitoring.notificationChannels.list",
	"monitoring.services.list",
	"monitoring.slos.list",
	"monitoring.uptimeCheckConfigs.list",
	"networkconnectivity.hubs.list",
	"networkconnectivity.spokes.list",
	"networkmanagement.connectivityTests.list",
	"networksecurity.addressGroups.list",
	"networksecurity.authorizationPolicies.list",
	"networksecurity.clientTlsPolicies.list",
	"networksecurity.securityProfileGroups.list",
	"networksecurity.securityProfiles.list",
	"networksecurity.serverTlsPolicies.list",
	"networksecurity.tlsInspectionPolicies.list",
	"networksecurity.urlLists.list",
	"orgpolicy.constraints.list",
	"orgpolicy.policies.list",
	"orgpolicy.policy.get",
	"osconfig.inventories.get",
	"osconfig.osPolicyAssignments.list",
	"osconfig.patchDeployments.list",
	"osconfig.vulnerabilityReports.get",
	"policyanalyzer.serviceAccountLastAuthenticationActivities.query",
	"privateca.caPools.getIamPolicy",
	"privateca.caPools.list",
	"privateca.certificateAuthorities.list",
	"privateca.certificateRevocationLists.list",
	"privateca.certificateTemplates.list",
	"privateca.certificates.list",
	"pubsub.schemas.get",
	"privilegedaccessmanager.entitlements.list",
	"privilegedaccessmanager.grants.list",
	"pubsub.schemas.list",
	"redis.backups.list",
	"redis.clusters.list",
	"redis.instances.list",
	"resourcemanager.projects.get",
	"resourcemanager.projects.getIamPolicy",
	"resourcemanager.resourceTagBindings.list",
	"run.jobs.getIamPolicy",
	"run.jobs.list",
	"run.operations.list",
	"run.services.getIamPolicy",
	"run.services.list",
	"secretmanager.secrets.getIamPolicy",
	"secretmanager.secrets.list",
	"secretmanager.versions.list",
	"serviceusage.services.get",
	"serviceusage.services.list",
	"source.repos.list",
	"spanner.backupSchedules.list",
	"spanner.backups.list",
	"spanner.databaseRoles.list",
	"spanner.databases.getDdl",
	"spanner.databases.getIamPolicy",
	"spanner.databases.list",
	"spanner.instanceConfigs.list",
	"spanner.instancePartitions.list",
	"spanner.instances.getIamPolicy",
	"spanner.instances.list",
	"storage.buckets.get",
	"storage.buckets.getIamPolicy",
	"storage.buckets.list",
	"storage.buckets.listEffectiveTags",
	"storage.hmacKeys.list",
	"workflows.workflows.list",
}

type permissionManifest struct {
	Permissions []string `json:"permissions"`
}

func TestGCPPermissionsMatchValidatedList(t *testing.T) {
	data, err := os.ReadFile("gcp.permissions.json")
	require.NoError(t, err, "failed to read gcp.permissions.json")

	var manifest permissionManifest
	require.NoError(t, json.Unmarshal(data, &manifest), "failed to parse gcp.permissions.json")

	actual := make([]string, len(manifest.Permissions))
	copy(actual, manifest.Permissions)
	sort.Strings(actual)

	expected := make([]string, len(validatedGCPPermissions))
	copy(expected, validatedGCPPermissions)
	sort.Strings(expected)

	// Build sets for detailed diff
	actualSet := map[string]bool{}
	for _, p := range actual {
		actualSet[p] = true
	}
	expectedSet := map[string]bool{}
	for _, p := range expected {
		expectedSet[p] = true
	}

	var unexpected, missing []string
	for _, p := range actual {
		if !expectedSet[p] {
			unexpected = append(unexpected, p)
		}
	}
	for _, p := range expected {
		if !actualSet[p] {
			missing = append(missing, p)
		}
	}

	if len(unexpected) > 0 {
		t.Errorf("unexpected permissions in manifest (not in validated list):\n")
		for _, p := range unexpected {
			t.Errorf("  - %s", p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("missing permissions from manifest (expected but not found):\n")
		for _, p := range missing {
			t.Errorf("  - %s", p)
		}
	}

	assert.Equal(t, expected, actual, "permissions in gcp.permissions.json must exactly match the validated list")
}
