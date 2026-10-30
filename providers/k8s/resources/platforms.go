// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// objectRuntimes lists every connection runtime that can drive object
// discovery. createPlatformData is called with conn.Runtime(), and the
// discovering connection may be a cluster, manifest, or admission connection,
// so any discovered object platform can carry any of these runtimes.
var objectRuntimes = []string{"k8s-cluster", "k8s-manifest", "k8s-admission"}

// Platforms is the static catalog of platforms this provider can emit.
//
// The connection-level platforms (k8s-cluster, k8s-manifest, k8s-admission)
// are built in providers/k8s/connection/{api,manifest,admission}. The
// k8s-object platforms are built by createPlatformData in discovery.go. The
// k8s-admission name is emitted in two shapes: as a "code" connection platform
// (admission connection) and as a "k8s-object" discovered platform (admission
// review object), so it lists both kinds.
var Platforms = []*plugin.PlatformInfo{
	{
		Name:    "k8s-cluster",
		Title:   "Kubernetes Cluster",
		Family:  []string{"k8s"},
		Kind:    []string{"api"},
		Runtime: []string{"k8s-cluster"},
	},
	{
		Name:    "k8s-manifest",
		Title:   "Kubernetes Manifest",
		Family:  []string{"k8s"},
		Kind:    []string{"code"},
		Runtime: []string{"k8s-manifest"},
	},
	{
		Name:    "k8s-admission",
		Title:   "Kubernetes Admission",
		Family:  []string{"k8s"},
		Kind:    []string{"code", "k8s-object"},
		Runtime: []string{"k8s-manifest", "k8s-admission", "k8s-cluster"},
	},
	{
		Name:    "k8s-node",
		Title:   "Kubernetes Node",
		Family:  []string{"k8s"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-pod",
		Title:   "Kubernetes Pod",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-cronjob",
		Title:   "Kubernetes CronJob",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-statefulset",
		Title:   "Kubernetes StatefulSet",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-deployment",
		Title:   "Kubernetes Deployment",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-job",
		Title:   "Kubernetes Job",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-replicaset",
		Title:   "Kubernetes ReplicaSet",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-daemonset",
		Title:   "Kubernetes DaemonSet",
		Family:  []string{"k8s", "k8s-workload"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-ingress",
		Title:   "Kubernetes Ingress",
		Family:  []string{"k8s", "k8s-ingress"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-service",
		Title:   "Kubernetes Service",
		Family:  []string{"k8s", "k8s-service"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
	{
		Name:    "k8s-namespace",
		Title:   "Kubernetes Namespace",
		Family:  []string{"k8s", "k8s-namespace"},
		Kind:    []string{"k8s-object"},
		Runtime: objectRuntimes,
	},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the catalog entry for the given platform name.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
