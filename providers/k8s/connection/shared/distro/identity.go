// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package distro

import (
	"regexp"
	"strings"
)

// Identity sources.
const (
	IdentityKubeconfig  = "kubeconfig"
	IdentityCertificate = "certificate"
	IdentityMetadata    = "metadata"
	IdentityNodes       = "nodes"
)

var (
	// <dnsprefix>-<hash>.hcp.<region>.azmk8s.io and
	// <name>.privatelink.<region>.azmk8s.io
	aksHost = regexp.MustCompile(`^[a-z0-9.-]+\.(?:hcp|privatelink)\.([a-z0-9]+)\.azmk8s\.io$`)
	// <id>.<shard>.<region>.eks.amazonaws.com(.cn)
	eksHost = regexp.MustCompile(`^[a-z0-9.-]+\.([a-z]{2}(?:-[a-z]+)+-\d)\.eks\.amazonaws\.com(?:\.cn)?$`)
	// arn:<partition>:eks:<region>:<account>:cluster/<name>, the cluster entry
	// `aws eks update-kubeconfig` writes
	eksARN = regexp.MustCompile(`^arn:aws[a-z-]*:eks:([a-z0-9-]+):(\d{12}):cluster/(.+)$`)
	// gke_<project>_<location>_<name>, the cluster entry
	// `gcloud container clusters get-credentials` writes. Project IDs and
	// locations have no underscores; cluster names have none either.
	gkeEntry = regexp.MustCompile(`^gke_([a-z][a-z0-9:.-]*[a-z0-9])_([a-z0-9-]+)_([a-z0-9-]+)$`)
)

// cloudOf names the cloud of each managed distribution, as the metadata
// probe reports it when the instance carries no distribution mark.
var cloudOf = map[string]string{AKS: "azure", EKS: "aws", GKE: "gcp"}

// identify works out the cluster's name, region and account. It reads the
// kubeconfig only for a distribution the server itself confirmed, so a cluster
// entry named like a managed cluster never makes one: the names in a kubeconfig
// can be edited by hand.
//
// The API server's name comes from the kubeconfig's server URL or, through a
// tunnel or proxy, from the certificate the server presents.
func identify(name, host, certName string, k *Kubeconfig, nodes []Node, md *MetadataResult) Identity {
	var id Identity
	h := strings.ToLower(hostname(host))
	c := strings.TrimPrefix(strings.ToLower(certName), "*")
	// match tries the server URL, then the certificate name
	match := func(re *regexp.Regexp) ([]string, string) {
		if m := re.FindStringSubmatch(h); m != nil {
			return m, IdentityKubeconfig
		}
		if m := re.FindStringSubmatch(c); m != nil {
			return m, IdentityCertificate
		}
		return nil, ""
	}

	switch name {
	case AKS:
		if m, src := match(aksHost); m != nil {
			id.Region, id.Source = m[1], src
		}
		// `az aks get-credentials` names the cluster entry after the AKS
		// resource; the DNS prefix in the host can be anything. An entry in
		// another cloud's format was not written for this cluster.
		if k != nil && k.ClusterEntry != "" && !eksARN.MatchString(k.ClusterEntry) && !gkeEntry.MatchString(k.ClusterEntry) {
			id.ClusterName = k.ClusterEntry
			id.Source = IdentityKubeconfig
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
			if m, src := match(eksHost); m != nil {
				id.Region = m[1]
				if id.Source == "" {
					id.Source = src
				}
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
	if md != nil && (md.Distro == name || md.Distro == "" && md.Value == cloudOf[name]) {
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
