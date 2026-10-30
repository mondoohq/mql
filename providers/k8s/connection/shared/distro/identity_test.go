// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package distro

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentityAKSKubeconfig(t *testing.T) {
	// az aks get-credentials: the cluster entry is the AKS resource name
	res := Detect(context.Background(), Probes{
		Version:     version("v1.33.3"),
		Certificate: names("aks-test-dns-z659aolw.hcp.westus3.azmk8s.io"),
		Host:        "https://aks-test-dns-z659aolw.hcp.westus3.azmk8s.io:443",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "aks-test",
			ExecCommand:  "kubelogin",
		},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, Identity{ClusterName: "aks-test", Region: "westus3", Source: IdentityKubeconfig}, res.Identity)
}

func TestIdentityAKSPrivateLink(t *testing.T) {
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.3"),
		Host:    "https://cep-aks-pass-1a2b3c4d.privatelink.eastus.azmk8s.io:443",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "cep-aks-pass",
		},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, Identity{ClusterName: "cep-aks-pass", Region: "eastus", Source: IdentityKubeconfig}, res.Identity)
}

func TestIdentityEKSKubeconfig(t *testing.T) {
	// aws eks update-kubeconfig: the cluster entry is the cluster ARN
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.5-eks-113cf36"),
		Host:    "https://0123456789ABCDEF0123456789ABCDEF.gr7.us-east-1.eks.amazonaws.com",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "arn:aws:eks:us-east-1:123456789012:cluster/demo",
			ExecCommand:  "aws",
			ExecArgs:     []string{"--region", "us-east-1", "eks", "get-token", "--cluster-name", "demo", "--output", "json"},
		},
	})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, Identity{ClusterName: "demo", Region: "us-east-1", Account: "123456789012", Source: IdentityKubeconfig}, res.Identity)
}

func TestIdentityEKSRenamedContext(t *testing.T) {
	// eksctl or a hand-edited kubeconfig: the entry is a free name; the exec
	// arguments and the endpoint still identify the cluster
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.5-eks-113cf36"),
		Host:    "https://0123456789ABCDEF0123456789ABCDEF.gr7.eu-west-1.eks.amazonaws.com",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "prod",
			ExecCommand:  "aws",
			ExecArgs:     []string{"eks", "get-token", "--cluster-name=demo"},
		},
	})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, Identity{ClusterName: "demo", Region: "eu-west-1", Source: IdentityKubeconfig}, res.Identity)
}

func TestIdentityGKEKubeconfig(t *testing.T) {
	// gcloud container clusters get-credentials: gke_<project>_<location>_<name>
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.5-gke.1162000"),
		Host:    "https://34.123.45.67",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "gke_my-project-123_us-central1-a_cep-gke-pass",
			ExecCommand:  "gke-gcloud-auth-plugin",
		},
	})
	assert.Equal(t, GKE, res.Name)
	assert.Equal(t, Identity{ClusterName: "cep-gke-pass", Region: "us-central1-a", Account: "my-project-123", Source: IdentityKubeconfig}, res.Identity)
}

func TestIdentityGKERenamedContext(t *testing.T) {
	// a renamed entry gives no identity, but the distribution still holds
	res := Detect(context.Background(), Probes{
		Version:    version("v1.33.5-gke.1162000"),
		Host:       "https://34.123.45.67",
		Kubeconfig: &Kubeconfig{ClusterEntry: "staging"},
	})
	assert.Equal(t, GKE, res.Name)
	assert.Equal(t, Identity{}, res.Identity)
}

func TestIdentityNamesDoNotMakeADistribution(t *testing.T) {
	for _, entry := range []string{
		"aks-foo",
		"arn:aws:eks:us-east-1:123456789012:cluster/demo",
		"gke_my-project_us-central1_demo",
	} {
		res := Detect(context.Background(), Probes{
			Version:     version("v1.34.0"),
			Certificate: names("kubernetes", "localhost"),
			Host:        "https://10.0.0.10:6443",
			Kubeconfig:  &Kubeconfig{ClusterEntry: entry},
		})
		assert.Equal(t, Unknown, res.Name, entry)
		assert.Equal(t, Identity{}, res.Identity, entry)
	}

	// an EKS-looking entry on an AKS server: AKS, named after the entry, but
	// no AWS account or region from it
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.3"),
		Host:    "https://x-1.hcp.westus3.azmk8s.io:443",
		Kubeconfig: &Kubeconfig{
			ClusterEntry: "arn:aws:eks:us-east-1:123456789012:cluster/demo",
		},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, "westus3", res.Identity.Region)
	assert.Equal(t, "", res.Identity.Account)
	assert.Equal(t, "", res.Identity.ClusterName)
}

func TestIdentityFromNodes(t *testing.T) {
	res := Detect(context.Background(), Probes{
		Version: version("v1.33.3"),
		Nodes: func(context.Context) ([]Node, error) {
			return []Node{{Labels: map[string]string{
				"kubernetes.azure.com/cluster":  "MC_rg_aks_westus3",
				"topology.kubernetes.io/region": "westus3",
			}}}, nil
		},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, ProbeNodes, res.Source)
	assert.Equal(t, Identity{Region: "westus3", Source: IdentityNodes}, res.Identity)
}

func TestIdentityThroughTunnel(t *testing.T) {
	// the kubeconfig points at a local tunnel; the certificate names the
	// private endpoint
	res := Detect(context.Background(), Probes{
		Version:     version("v1.35.8"),
		Certificate: names("kubernetes", "cep6052fa91d3-zay8zrve.42a48b13-a6bf-4df0-b231-8faf5c1137d4.privatelink.eastus.azmk8s.io"),
		Host:        "https://127.0.0.1:53182",
		Kubeconfig:  &Kubeconfig{ClusterEntry: "cep-aks-pass"},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, "eastus", res.Identity.Region)
	assert.Equal(t, "cep-aks-pass", res.Identity.ClusterName)

	res = Detect(context.Background(), Probes{
		Version:     version("v1.33.5-eks-113cf36"),
		Certificate: names("0123456789ABCDEF0123456789ABCDEF.gr7.eu-west-1.eks.amazonaws.com", "kubernetes"),
		Host:        "https://127.0.0.1:53182",
		Kubeconfig:  &Kubeconfig{ClusterEntry: "demo"},
	})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, Identity{Region: "eu-west-1", Source: IdentityCertificate}, res.Identity)
}
