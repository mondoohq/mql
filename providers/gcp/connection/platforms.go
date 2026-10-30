// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// gcpPlatformNames is the set of platform names the GCP provider can emit: the
// org/project/folder roots plus every discoverable GCP object type (the
// platformOverride values set during discovery). Titles are sourced from
// GetTitleForPlatformName so there is a single title source.
var gcpPlatformNames = []string{
	"gcp-org", "gcp-project", "gcp-folder",
	"gcp-compute-image", "gcp-compute-network", "gcp-compute-subnetwork",
	"gcp-compute-firewall", "gcp-compute-instance", "gcp-gke-cluster",
	"gcp-storage-bucket", "gcp-bigquery-dataset",
	"gcp-sql-mysql", "gcp-sql-postgresql", "gcp-sql-sqlserver",
	"gcp-dns-zone", "gcp-kms-keyring",
	"gcp-memorystore-redis", "gcp-memorystore-rediscluster", "gcp-memorystore-instance",
	"gcp-artifactregistry-repository", "gcp-memcache-instance", "gcp-vertexai-job",
	"gcp-vertexai-endpoint", "gcp-vertexai-pipelinejob", "gcp-vertexai-notebookruntimetemplate",
	"gcp-secretmanager-secret",
	"gcp-pubsub-topic", "gcp-pubsub-subscription", "gcp-pubsub-snapshot",
	"gcp-cloudrun-service", "gcp-cloudrun-job", "gcp-cloud-function",
	"gcp-dataproc-cluster", "gcp-alloydb-cluster", "gcp-spanner-instance",
	"gcp-firestore-database", "gcp-bigtable-instance", "gcp-logging-bucket",
	"gcp-apikey", "gcp-iam-service-account",
	"gcp-modelarmor-template", "gcp-datastream-connectionprofile",
}

// Platforms is the static catalog of platforms the GCP provider can emit. Every
// GCP platform is a "gcp-object" in the "google" family running in the "gcp"
// runtime. Single source of truth for the provider config and the runtime
// builder (see PlatformInfo / newGcpPlatform).
var Platforms = func() []*plugin.PlatformInfo {
	out := make([]*plugin.PlatformInfo, 0, len(gcpPlatformNames))
	for _, name := range gcpPlatformNames {
		out = append(out, &plugin.PlatformInfo{
			Name:    name,
			Title:   GetTitleForPlatformName(name),
			Family:  []string{"google"},
			Kind:    []string{"gcp-object"},
			Runtime: []string{"gcp"},
		})
	}
	return out
}()

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static descriptor for a platform name, or nil.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
