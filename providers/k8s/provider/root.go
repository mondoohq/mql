// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// assetRoot returns the resource that roots this asset's tree, chosen from the
// platform the connection reports (ADR 031). It is what `_` resolves to, and
// what bounds the query: on a Pod asset `_.nodes` then fails to compile rather
// than answering with an unset field.
//
// This cannot be the provider's static `Root` declaration, which has to name one
// resource for a provider that serves a dozen kinds. Only the asset in hand says
// which of them this is.
//
// The mapping is keyed on the platform name because that is where the provider
// already records the kind, in createPlatformData (resources/discovery.go): the
// names below are the ones it assigns, so the two cannot drift into disagreeing
// about what a Pod is.
//
// A kind we do not recognize roots at the cluster, which is what a k8s
// connection is when it is nothing more specific.
func assetRoot(platform *inventory.Platform) string {
	if platform == nil {
		return "k8s"
	}

	switch platform.Name {
	case "k8s-pod":
		return "k8s.pod"
	case "k8s-deployment":
		return "k8s.deployment"
	case "k8s-daemonset":
		return "k8s.daemonset"
	case "k8s-statefulset":
		return "k8s.statefulset"
	case "k8s-replicaset":
		return "k8s.replicaset"
	case "k8s-job":
		return "k8s.job"
	case "k8s-cronjob":
		return "k8s.cronjob"
	case "k8s-node":
		return "k8s.node"
	case "k8s-namespace":
		return "k8s.namespace"
	case "k8s-service":
		return "k8s.service"
	case "k8s-ingress":
		return "k8s.ingress"
	default:
		return "k8s"
	}
}
