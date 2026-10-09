// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package distro

import (
	"regexp"
	"strings"
)

// Identity sources.
const (
	IdentityKubeconfig = "kubeconfig"
	IdentityMetadata   = "metadata"
	IdentityNodes      = "nodes"
)

var (
	// <dnsprefix>-<hash>.hcp.<region>.azmk8s.io and
	// <name>.privatelink.<region>.azmk8s.io
	aksHost = regexp.MustCompile(`\.(?:hcp|privatelink)\.([a-z0-9]+)\.azmk8s\.io$`)
	// <id>.<shard>.<region>.eks.amazonaws.com(.cn)
	eksHost = regexp.MustCompile(`\.([a-z]{2}(?:-[a-z]+)+-\d)\.eks\.amazonaws\.com(?:\.cn)?$`)
	// arn:<partition>:eks:<region>:<account>:cluster/<name>, the cluster entry
	// `aws eks update-kubeconfig` writes
	eksARN = regexp.MustCompile(`^arn:aws[a-z-]*:eks:([a-z0-9-]+):(\d{12}):cluster/(.+)$`)
	// gke_<project>_<location>_<name>, the cluster entry
	// `gcloud container clusters get-credentials` writes. Project IDs and
	// locations have no underscores; cluster names have none either.
	gkeEntry = regexp.MustCompile(`^gke_([a-z][a-z0-9:.-]*[a-z0-9])_([a-z0-9-]+)_([a-z0-9-]+)$`)
)

// identify works out the cluster's name, region and account. It reads the
// kubeconfig only for a distribution the server itself confirmed, so a cluster
// entry named like a managed cluster never makes one: the names in a kubeconfig
// can be edited by hand.
func identify(name, host string, k *Kubeconfig, nodes []Node, md *MetadataResult) Identity {
	var id Identity
	h := strings.ToLower(hostname(host))

	switch name {
	case AKS:
		if m := aksHost.FindStringSubmatch(h); m != nil {
			id.Region = m[1]
			id.Source = IdentityKubeconfig
			// `az aks get-credentials` names the cluster entry after the AKS
			// resource; the DNS prefix in the host can be anything.
			// An entry in another cloud's format was not written by it.
			if k != nil && k.ClusterEntry != "" && !eksARN.MatchString(k.ClusterEntry) && !gkeEntry.MatchString(k.ClusterEntry) {
				id.ClusterName = k.ClusterEntry
			}
		}
	case EKS:
		if k != nil {
			if m := eksARN.FindStringSubmatch(k.ClusterEntry); m != nil {
				id = Identity{Region: m[1], Account: m[2], ClusterName: m[3], Source: IdentityKubeconfig}
			}
			if id.ClusterName == "" || id.Region == "" {
				cluster, region := eksExecArgs(k.ExecArgs)
				if id.ClusterName == "" && cluster != "" {
					id.ClusterName, id.Source = cluster, IdentityKubeconfig
				}
				if id.Region == "" && region != "" {
					id.Region, id.Source = region, IdentityKubeconfig
				}
			}
		}
		if id.Region == "" {
			if m := eksHost.FindStringSubmatch(h); m != nil {
				id.Region, id.Source = m[1], IdentityKubeconfig
			}
		}
	case GKE:
		if k != nil {
			if m := gkeEntry.FindStringSubmatch(k.ClusterEntry); m != nil {
				id = Identity{Account: m[1], Region: m[2], ClusterName: m[3], Source: IdentityKubeconfig}
			}
		}
	}

	// in the cluster, there is no kubeconfig: the metadata service and the
	// nodes fill in what they know
	if md != nil && md.Distro == name {
		fill(&id, md.Identity, IdentityMetadata)
	}
	if name != Unknown {
		for _, n := range nodes {
			if r := n.Labels["topology.kubernetes.io/region"]; r != "" && id.Region == "" {
				id.Region = r
				if id.Source == "" {
					id.Source = IdentityNodes
				}
			}
		}
	}
	return id
}

func fill(id *Identity, from Identity, source string) {
	set := false
	if id.ClusterName == "" && from.ClusterName != "" {
		id.ClusterName, set = from.ClusterName, true
	}
	if id.Region == "" && from.Region != "" {
		id.Region, set = from.Region, true
	}
	if id.Account == "" && from.Account != "" {
		id.Account, set = from.Account, true
	}
	if set && id.Source == "" {
		id.Source = source
	}
}

func eksExecArgs(args []string) (cluster, region string) {
	for i, arg := range args {
		switch {
		case arg == "--cluster-name" && i+1 < len(args):
			cluster = args[i+1]
		case strings.HasPrefix(arg, "--cluster-name="):
			cluster = strings.TrimPrefix(arg, "--cluster-name=")
		case arg == "--region" && i+1 < len(args):
			region = args[i+1]
		case strings.HasPrefix(arg, "--region="):
			region = strings.TrimPrefix(arg, "--region=")
		}
	}
	return cluster, region
}
