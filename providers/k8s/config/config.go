// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/provider"
	"go.mondoo.com/mql/providers/k8s/resources"
)

var Config = plugin.Provider{
	Name:            "k8s",
	ID:              "go.mondoo.com/mql/providers/k8s",
	Version:         "13.10.0",
	ConnectionTypes: []string{provider.ConnectionType},
	Platforms:       resources.Platforms,
	// The client-go rate limiter is already raised well above its defaults, so
	// concurrent asset scans reach the API server rather than queueing locally.
	// Kept at 8 so a small control plane's API Priority and Fairness has room.
	DefaultParallelism: 8,
	Connectors: []plugin.Connector{
		{
			Name:    "k8s",
			Aliases: []string{"kubernetes"},
			Use:     "k8s (optional MANIFEST path)",
			Short:   "a Kubernetes cluster or local manifest file(s)",
			Long: `Use the k8s provider to query Kubernetes resources, including clusters, pods, services, containers, manifests, and more.

Requirement:
  To query or scan a Kubernetes cluster, you must install kubectl on your workstation. To learn how, read https://kubernetes.io/docs/tasks/tools/. 

Examples:
  cnspec shell k8s
  cnspec scan k8s
  cnspec scan k8s <MANIFEST-FILE>
`,
			MinArgs: 0,
			MaxArgs: 1,
			Discovery: []string{
				resources.DiscoveryAdmissionReviews,
				resources.DiscoveryClusters,
				resources.DiscoveryContainerImages,
				resources.DiscoveryCronJobs,
				resources.DiscoveryDaemonSets,
				resources.DiscoveryDeployments,
				resources.DiscoveryIngresses,
				resources.DiscoveryJobs,
				resources.DiscoveryKyverno,
				resources.DiscoveryNamespaces,
				resources.DiscoveryPods,
				resources.DiscoveryReplicaSets,
				resources.DiscoveryServices,
				resources.DiscoveryStatefulSets,
			},
			Flags: []plugin.Flag{
				{
					Long:    "context",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Target a specific Kubernetes context from your kubeconfig",
				},
				{
					Long:    "namespaces-exclude",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Filter out Kubernetes objects in the matching namespaces",
				},
				{
					Long:    "namespaces",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Only include Kubernetes objects in the matching namespaces",
				},
				{
					Long:    "namespace-label-selector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Only include Kubernetes namespaces matching the label selector, along with all objects discovered within those namespaces",
				},
				{
					Long:    "object-label-selector",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Only include Kubernetes objects matching the label selector; for container image discovery this matches the pod that references the image",
				},
				{
					Long:    "container-proxy",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "HTTP proxy to use for container pulls",
				},
				{
					Long:    "images",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Only include container images matching the given image references during discovery (comma-separated, glob supported)",
				},
				{
					Long:    "images-exclude",
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Filter out container images matching the given image references during discovery (comma-separated, glob supported)",
				},
				{
					Long:    "kubelogin",
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Authenticate against a remote Azure AD enabled Kubernetes cluster using an Azure identity.",
				},
				{
					Long:    shared.OPTION_KYVERNO_DEFAULT_MAPPINGS,
					Type:    plugin.FlagType_Bool,
					Default: "true",
					Desc:    "Enable built-in Kyverno to Mondoo policy mappings.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno policy annotation keys that define mapped Mondoo check UIDs.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_MRNS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno policy annotation keys that define mapped Mondoo check MRNs.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MAPPING_ANNOTATION_POLICY_UIDS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno policy annotation keys that define mapped Mondoo policy UIDs.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MAPPING_ANNOTATION_REASONS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno policy annotation keys that define mapping reasons.",
				},
				{
					Long:    shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_VALID_UNTIL,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno PolicyException annotation keys that define valid-until timestamps.",
				},
				{
					Long:    shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_JUSTIFICATIONS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno PolicyException annotation keys that define justifications.",
				},
				{
					Long:    shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno PolicyException annotation keys that define owners.",
				},
				{
					Long:    shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_TICKETS,
					Type:    plugin.FlagType_String,
					Default: "",
					Desc:    "Comma-separated Kyverno PolicyException annotation keys that define ticket references.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS,
					Type:    plugin.FlagType_Bool,
					Default: "false",
					Desc:    "Enable mirroring Kyverno PolicyExceptions into Mondoo external exceptions when platform support is available.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_APPROVAL,
					Type:    plugin.FlagType_String,
					Default: "externally-approved",
					Desc:    "Approval mode for mirrored Kyverno PolicyExceptions: externally-approved or requires-approval.",
				},
				{
					Long:    shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION,
					Type:    plugin.FlagType_String,
					Default: "RISK_ACCEPTED",
					Desc:    "Mondoo exception action for mirrored Kyverno PolicyExceptions.",
				},
				{
					Long:    shared.OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS,
					Type:    plugin.FlagType_Bool,
					Default: "true",
					Desc:    "Fail Kyverno hygiene checks when collected PolicyExceptions are expired.",
				},
				{
					Long:    shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_EXCEPTIONS,
					Type:    plugin.FlagType_Bool,
					Default: "true",
					Desc:    "Report unmapped Kyverno PolicyExceptions in Kyverno findings and inventory.",
				},
				{
					Long:    shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS,
					Type:    plugin.FlagType_Bool,
					Default: "true",
					Desc:    "Report unmapped Kyverno PolicyReport failures in Kyverno findings.",
				},
			},
		},
	},
	AssetUrlTrees: []*inventory.AssetUrlBranch{
		{
			PathSegments: []string{"technology=k8s"},
			Key:          "platform",
			Title:        "Platform",
			Values: map[string]*inventory.AssetUrlBranch{
				"*": nil,
			},
		},
		{
			PathSegments: []string{"technology=iac", "category=k8s-manifest"},
		},
	},
}
