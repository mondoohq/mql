// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package distro

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func version(v string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return v, nil }
}

func names(n ...string) func(context.Context) ([]string, error) {
	return func(context.Context) ([]string, error) { return n, nil }
}

func failing[T any](msg string) func(context.Context) (T, error) {
	return func(context.Context) (T, error) {
		var zero T
		return zero, errors.New(msg)
	}
}

func TestFromVersion(t *testing.T) {
	cases := map[string]string{
		"v1.33.5-eks-113cf36":   EKS,
		"v1.28.3-eks-1-28-11":   EKSD,
		"v1.33.5-gke.1162000":   GKE,
		"v1.33.4+k3s1":          K3s,
		"v1.33.4+rke2r1":        RKE2,
		"v1.33.4+k0s":           K0s,
		"v1.33.3":               "",
		"v1.32.7+0f6d2f1":       "", // OpenShift: decided by its API groups
		"":                      "",
		"v1.30.0-something-eks": "",
	}
	for in, want := range cases {
		assert.Equal(t, want, FromVersion(in), in)
	}
}

func TestFromHostname(t *testing.T) {
	cases := map[string]string{
		"aks-test-dns-z659aolw.hcp.westus3.azmk8s.io":          AKS,
		"*.hcp.westus3.azmk8s.io":                              AKS,
		"cep-aks-pass-abc.privatelink.eastus.azmk8s.io":        AKS,
		"0123456789ABCDEF.gr7.us-east-1.eks.amazonaws.com":     EKS,
		"0123456789abcdef.yl4.cn-north-1.eks.amazonaws.com.cn": EKS,
		"gke-0123abcd-123456789.us-central1.gke.goog":          GKE,
		"api.cluster.abcd.p1.openshiftapps.com":                OpenShift,
		"api.abcdefgh.eastus.aroapp.io":                        OpenShift,
		"kubernetes.default.svc":                               "",
		"evil-azmk8s.io.example.com":                           "",
		"localhost":                                            "",
		"azmk8s.io":                                            "",
	}
	for in, want := range cases {
		assert.Equal(t, want, FromHostname(in), in)
	}
}

func TestFromAPIGroups(t *testing.T) {
	d, g := FromAPIGroups([]string{"apps", "vpcresources.k8s.aws", "config.openshift.io"})
	assert.Equal(t, OpenShift, d, "OpenShift wins over the cloud it runs on")
	assert.Equal(t, "config.openshift.io", g)

	d, _ = FromAPIGroups([]string{"apps", "networking.gke.io"})
	assert.Equal(t, GKE, d)

	d, g = FromAPIGroups([]string{"apps", "batch"})
	assert.Equal(t, "", d)
	assert.Equal(t, "", g)
}

func TestFromNodes(t *testing.T) {
	d, v := FromNodes([]Node{{Labels: map[string]string{"kubernetes.azure.com/cluster": "MC_rg_aks_westus3"}}})
	assert.Equal(t, AKS, d)
	assert.Equal(t, "kubernetes.azure.com/cluster", v)

	d, _ = FromNodes([]Node{{ProviderID: "kind://docker/kind/kind-control-plane"}})
	assert.Equal(t, Kind, d)

	// a provider ID only names the cloud, not a managed distribution
	d, _ = FromNodes([]Node{{ProviderID: "aws:///us-east-1a/i-0123"}})
	assert.Equal(t, "", d)
}

func TestFromKubeconfigAuth(t *testing.T) {
	d, _ := FromKubeconfigAuth(&Kubeconfig{ExecCommand: "/usr/local/bin/kubelogin"})
	assert.Equal(t, AKS, d)
	d, _ = FromKubeconfigAuth(&Kubeconfig{ExecCommand: "aws", ExecArgs: []string{"--region", "us-east-1", "eks", "get-token", "--cluster-name", "x"}})
	assert.Equal(t, EKS, d)
	d, _ = FromKubeconfigAuth(&Kubeconfig{ExecCommand: "aws", ExecArgs: []string{"sts", "get-caller-identity"}})
	assert.Equal(t, "", d)
	d, _ = FromKubeconfigAuth(&Kubeconfig{ExecCommand: `C:\tools\gke-gcloud-auth-plugin.exe`})
	assert.Equal(t, GKE, d)
	d, _ = FromKubeconfigAuth(nil)
	assert.Equal(t, "", d)
}

func TestDetectOrder(t *testing.T) {
	// version decides; later probes are evidence
	res := Detect(context.Background(), Probes{
		Version:     version("v1.33.5-eks-113cf36"),
		Certificate: names("kubernetes", "0123.gr7.us-east-1.eks.amazonaws.com"),
		Host:        "https://127.0.0.1:6443",
		APIGroups:   names("apps", "vpcresources.k8s.aws"),
		Nodes:       failing[[]Node]("nodes is forbidden"),
	})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, ProbeVersion, res.Source)
	assert.Equal(t, EKS, res.Evidence[ProbeCertificate].Distro)
	assert.Equal(t, "nodes is forbidden", res.Evidence[ProbeNodes].Error)
	assert.Equal(t, "", res.Evidence[ProbeHost].Distro)

	// AKS has no version suffix: the certificate decides, even through a
	// tunnel to localhost
	res = Detect(context.Background(), Probes{
		Version:     version("v1.33.3"),
		Certificate: names("kubernetes", "aks-test-dns-z659aolw.hcp.westus3.azmk8s.io"),
		Host:        "https://127.0.0.1:8443",
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, ProbeCertificate, res.Source)

	// a failing certificate probe falls through to the host
	res = Detect(context.Background(), Probes{
		Version:     version("v1.33.3"),
		Certificate: failing[[]string]("handshake failed"),
		Host:        "https://aks-test-dns-z659aolw.hcp.westus3.azmk8s.io:443",
	})
	assert.Equal(t, AKS, res.Name)
	assert.Equal(t, ProbeHost, res.Source)
	assert.Equal(t, "handshake failed", res.Evidence[ProbeCertificate].Error)
}

func TestDetectUnknownSelfManaged(t *testing.T) {
	res := Detect(context.Background(), Probes{
		Version:     version("v1.34.0"),
		Certificate: names("kind-control-plane", "kubernetes", "localhost"),
		Host:        "https://127.0.0.1:41234",
		APIGroups:   names("apps", "batch"),
		Nodes:       failing[[]Node]("forbidden"),
		Kubeconfig:  &Kubeconfig{ClusterEntry: "aks-foo"},
	})
	assert.Equal(t, Unknown, res.Name)
	assert.Equal(t, "", res.Source)
	assert.Equal(t, Identity{}, res.Identity, "a cluster entry name alone identifies nothing")
}

func TestDetectMetadataOnlyWhenUndecided(t *testing.T) {
	calls := 0
	md := func(context.Context) (*MetadataResult, error) {
		calls++
		return &MetadataResult{Distro: GKE, Value: "gcp instance attribute cluster-name",
			Identity: Identity{ClusterName: "c1", Region: "us-central1-a", Account: "proj-1"}}, nil
	}
	// named by the kubeconfig: no need to ask
	res := Detect(context.Background(), Probes{Version: version("v1.33.5-gke.1162000"), Metadata: md,
		Kubeconfig: &Kubeconfig{ClusterEntry: "gke_my-project_us-central1_c"}})
	assert.Equal(t, 0, calls)
	assert.Equal(t, GKE, res.Name)

	res = Detect(context.Background(), Probes{Version: version("v1.33.5"), Metadata: md})
	assert.Equal(t, 1, calls)
	assert.Equal(t, GKE, res.Name)
	assert.Equal(t, ProbeMetadata, res.Source)
	assert.Equal(t, Identity{ClusterName: "c1", Region: "us-central1-a", Account: "proj-1", Source: IdentityMetadata}, res.Identity)
}

func TestDetectOpenShift(t *testing.T) {
	res := Detect(context.Background(), Probes{
		Version:     version("v1.32.7"),
		Certificate: names("api.crc.testing"),
		Host:        "https://api.crc.testing:6443",
		APIGroups:   names("apps", "route.openshift.io", "config.openshift.io"),
	})
	assert.Equal(t, OpenShift, res.Name)
	assert.Equal(t, ProbeAPIGroups, res.Source)
}

func TestDetectMetadataNamesInClusterManagedCluster(t *testing.T) {
	calls := 0
	md := func(context.Context) (*MetadataResult, error) {
		calls++
		return &MetadataResult{Distro: GKE, Value: "gcp instance attribute cluster-name",
			Identity: Identity{ClusterName: "c1", Region: "us-central1-a", Account: "proj-1"}}, nil
	}
	// in the cluster: the version decides, the metadata names the cluster
	res := Detect(context.Background(), Probes{Version: version("v1.33.5-gke.1162000"), Host: "https://10.0.0.1", Metadata: md})
	assert.Equal(t, 1, calls)
	assert.Equal(t, GKE, res.Name)
	assert.Equal(t, ProbeVersion, res.Source)
	assert.Equal(t, Identity{ClusterName: "c1", Region: "us-central1-a", Account: "proj-1", Source: IdentityMetadata}, res.Identity)

	// EC2 without instance tags in the metadata: the region and nothing else
	aws := func(context.Context) (*MetadataResult, error) {
		return &MetadataResult{Value: "aws", Identity: Identity{Region: "us-east-1"}}, nil
	}
	res = Detect(context.Background(), Probes{Version: version("v1.33.5-eks-113cf36"), Metadata: aws})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, Identity{Region: "us-east-1", Source: IdentityMetadata}, res.Identity)
	assert.Nil(t, res.AssetAnnotations(), "no account known, nothing to annotate")

	// EC2 whose identity document names the account: the workloads of this
	// cluster can be attributed to it
	awsAccount := func(context.Context) (*MetadataResult, error) {
		return &MetadataResult{Value: "aws", Identity: Identity{Region: "us-east-1", Account: "111111111111"}}, nil
	}
	res = Detect(context.Background(), Probes{Version: version("v1.33.5-eks-113cf36"), Metadata: awsAccount})
	assert.Equal(t, EKS, res.Name)
	assert.Equal(t, Identity{Region: "us-east-1", Account: "111111111111", Source: IdentityMetadata}, res.Identity)
	assert.Equal(t, map[string]string{"mondoo.com/aws-account-id": "111111111111"}, res.AssetAnnotations())

	// a self-managed cluster in a cloud is not named after the instance
	res = Detect(context.Background(), Probes{Version: version("v1.33.4+k3s1"), Metadata: md})
	assert.Equal(t, K3s, res.Name)
	assert.Equal(t, Identity{}, res.Identity)
}

func TestCloudOf(t *testing.T) {
	assert.Equal(t, "aws", CloudOf(EKS))
	assert.Equal(t, "azure", CloudOf(AKS))
	assert.Equal(t, "gcp", CloudOf(GKE))
	// EKS Distro runs anywhere, so it has no cloud
	assert.Equal(t, "", CloudOf(EKSD))
	assert.Equal(t, "", CloudOf(OpenShift))
	assert.Equal(t, "", CloudOf(Unknown))
}

func TestResultAssetAnnotations(t *testing.T) {
	eks := &Result{Name: EKS, Identity: Identity{Account: "111111111111", Region: "eu-central-1"}}
	assert.Equal(t, map[string]string{"mondoo.com/aws-account-id": "111111111111"}, eks.AssetAnnotations())

	t.Run("no account, no annotation", func(t *testing.T) {
		assert.Nil(t, (&Result{Name: EKS, Identity: Identity{Region: "eu-central-1"}}).AssetAnnotations())
	})
	t.Run("another cloud's account is not an AWS account", func(t *testing.T) {
		assert.Nil(t, (&Result{Name: GKE, Identity: Identity{Account: "my-project"}}).AssetAnnotations())
		assert.Nil(t, (&Result{Name: AKS, Identity: Identity{Account: "00000000-0000-0000-0000-000000000000"}}).AssetAnnotations())
	})
	t.Run("EKS Distro outside AWS", func(t *testing.T) {
		assert.Nil(t, (&Result{Name: EKSD, Identity: Identity{Account: "111111111111"}}).AssetAnnotations())
	})
	t.Run("nil result", func(t *testing.T) {
		var r *Result
		assert.Nil(t, r.AssetAnnotations())
	})
}

// groupResources serves the given resources per API group.
func groupResources(byGroup map[string][]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, group string) ([]string, error) {
		return byGroup[group], nil
	}
}

func failingGroups(msg string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return nil, errors.New(msg) }
}

func nodesOf(n ...Node) func(context.Context) ([]Node, error) {
	return func(context.Context) ([]Node, error) { return n, nil }
}

// API groups a GKE 1.35 cluster serves, Autopilot and Standard alike.
var gkeGroups = []string{"apps", "auto.gke.io", "cloud.google.com", "hub.gke.io", "networking.gke.io", "node.gke.io", "nodemanagement.gke.io", "warden.gke.io"}

func gkeNode(name string) Node {
	return Node{
		Name:       name,
		ProviderID: "gce://project/us-central1-a/" + name,
		Labels:     map[string]string{"cloud.google.com/gke-nodepool": "pool-2", "cloud.google.com/gke-provisioning": "standard"},
	}
}

func eksNode(name, computeType string) Node {
	labels := map[string]string{"topology.kubernetes.io/region": "us-west-2"}
	if computeType != "" {
		labels["eks.amazonaws.com/compute-type"] = computeType
	} else {
		labels["eks.amazonaws.com/nodegroup"] = "ng-1"
	}
	return Node{Name: name, ProviderID: "aws:///us-west-2a/i-0123456789abcdef0", Labels: labels}
}

func TestManagedModeFromNodes(t *testing.T) {
	cases := []struct {
		name   string
		distro string
		nodes  []Node
		want   string
	}{
		{"eks auto mode node", EKS, []Node{eksNode("i-1", ""), eksNode("i-2", "auto")}, ModeEKSAutoMode},
		{"eks managed node group", EKS, []Node{eksNode("i-1", "")}, ""},
		{"eks fargate", EKS, []Node{eksNode("fargate-ip-10-0-1-1", "fargate")}, ""},
		{"gke autopilot", GKE, []Node{gkeNode("gk3-shop-pool-2-1c9908f0-o10s"), gkeNode("gk3-shop-pool-2-7d0c8137-asi2")}, ModeGKEAutopilot},
		{"gke standard", GKE, []Node{gkeNode("gke-shop-default-pool-41881a33-79uo")}, ""},
		{"gke standard with an autopilot compute class node", GKE, []Node{gkeNode("gke-shop-default-pool-41881a33-79uo"), gkeNode("gk3-shop-nap-1c9908f0-o10s")}, ""},
		{"gk3 name outside gke", AKS, []Node{gkeNode("gk3-node")}, ""},
		{"no nodes", GKE, nil, ""},
	}
	for _, tc := range cases {
		mode, value := ManagedModeFromNodes(tc.distro, tc.nodes)
		assert.Equal(t, tc.want, mode, tc.name)
		if tc.want == "" {
			assert.Empty(t, value, tc.name)
		} else {
			assert.NotEmpty(t, value, tc.name)
		}
	}
}

func TestDetectGKEAutopilot(t *testing.T) {
	t.Run("from API discovery, without node access", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:   version("v1.35.8-gke.1439001"),
			APIGroups: names(gkeGroups...),
			GroupResources: groupResources(map[string][]string{
				"auto.gke.io": {"allowlistedv2workloads", "allowlistedworkloads", "allowlistsynchronizers", "workloadallowlists"},
			}),
			Nodes: failing[[]Node]("nodes is forbidden"),
		})
		assert.Equal(t, GKE, res.Name)
		assert.Equal(t, ModeGKEAutopilot, res.ManagedMode)
		assert.Equal(t, Evidence{Distro: GKE, Value: "allowlistedworkloads.auto.gke.io"}, res.Evidence[ProbeManagedMode])
		assert.Equal(t, ModeGKEAutopilot, res.PlatformMetadata()[MetadataManagedMode])
	})

	t.Run("from node names when discovery has no signal", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:        version("v1.35.8-gke.1439001"),
			APIGroups:      names(gkeGroups...),
			GroupResources: failingGroups("discovery failed"),
			Nodes:          nodesOf(gkeNode("gk3-shop-pool-2-1c9908f0-o10s")),
		})
		assert.Equal(t, ModeGKEAutopilot, res.ManagedMode)
		assert.Equal(t, "node name prefix gk3-", res.Evidence[ProbeManagedMode].Value)
	})

	t.Run("standard cluster", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:   version("v1.35.8-gke.1439001"),
			APIGroups: names(gkeGroups...),
			GroupResources: groupResources(map[string][]string{
				"auto.gke.io": {"allowlistsynchronizers", "workloadallowlists"},
			}),
			Nodes: nodesOf(gkeNode("gke-shop-my-node-pool-41881a33-79uo")),
		})
		assert.Equal(t, GKE, res.Name)
		assert.Empty(t, res.ManagedMode)
		assert.NotContains(t, res.Evidence, ProbeManagedMode)
		assert.NotContains(t, res.PlatformMetadata(), MetadataManagedMode)
	})

	t.Run("discovery error without another signal is recorded", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:        version("v1.35.8-gke.1439001"),
			APIGroups:      names(gkeGroups...),
			GroupResources: failingGroups("the server is currently unable to handle the request"),
			Nodes:          failing[[]Node]("nodes is forbidden"),
		})
		assert.Equal(t, GKE, res.Name)
		assert.Empty(t, res.ManagedMode)
		assert.Equal(t, "the server is currently unable to handle the request", res.Evidence[ProbeManagedMode].Error)
	})
}

func TestDetectEKSAutoMode(t *testing.T) {
	t.Run("from API discovery", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:   version("v1.34.1-eks-113cf36"),
			APIGroups: names("apps", "eks.amazonaws.com", "karpenter.sh", "vpcresources.k8s.aws"),
			GroupResources: groupResources(map[string][]string{
				"eks.amazonaws.com": {"nodeclasses", "nodediagnostics"},
			}),
			Nodes: failing[[]Node]("nodes is forbidden"),
		})
		assert.Equal(t, EKS, res.Name)
		assert.Equal(t, ModeEKSAutoMode, res.ManagedMode)
		assert.Equal(t, "nodeclasses.eks.amazonaws.com", res.Evidence[ProbeManagedMode].Value)
	})

	t.Run("from the compute-type node label", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:        version("v1.34.1-eks-113cf36"),
			APIGroups:      names("apps", "vpcresources.k8s.aws"),
			GroupResources: groupResources(nil),
			Nodes:          nodesOf(eksNode("i-0123456789abcdef0", "auto")),
		})
		assert.Equal(t, ModeEKSAutoMode, res.ManagedMode)
		assert.Equal(t, "eks.amazonaws.com/compute-type=auto", res.Evidence[ProbeManagedMode].Value)
	})

	t.Run("standard cluster with managed node groups", func(t *testing.T) {
		res := Detect(context.Background(), Probes{
			Version:        version("v1.34.1-eks-113cf36"),
			APIGroups:      names("apps", "vpcresources.k8s.aws"),
			GroupResources: groupResources(nil),
			Nodes:          nodesOf(eksNode("i-0123456789abcdef0", "")),
		})
		assert.Equal(t, EKS, res.Name)
		assert.Empty(t, res.ManagedMode)
		assert.NotContains(t, res.Evidence, ProbeManagedMode)
	})
}

func TestDetectManagedModeOnlyAsksOwnGroups(t *testing.T) {
	asked := []string{}
	res := Detect(context.Background(), Probes{
		Host:      "https://aks-test-dns-z659aolw.hcp.westus3.azmk8s.io:443",
		APIGroups: names("apps", "auto.gke.io", "eks.amazonaws.com", "karpenter.azure.com"),
		GroupResources: func(_ context.Context, group string) ([]string, error) {
			asked = append(asked, group)
			return []string{"allowlistedworkloads", "nodeclasses"}, nil
		},
	})
	assert.Equal(t, AKS, res.Name)
	assert.Empty(t, res.ManagedMode, "AKS Automatic is not detected from the Kubernetes API")
	assert.Empty(t, asked)

	// a group the server does not serve is never asked for
	asked = asked[:0]
	res = Detect(context.Background(), Probes{
		Version:   version("v1.35.8-gke.1439001"),
		APIGroups: names("apps"),
		GroupResources: func(_ context.Context, group string) ([]string, error) {
			asked = append(asked, group)
			return nil, nil
		},
	})
	assert.Equal(t, GKE, res.Name)
	assert.Empty(t, asked)
}

func TestResultPlatformMetadata(t *testing.T) {
	var nilResult *Result
	assert.Equal(t, map[string]string{}, nilResult.PlatformMetadata())
	assert.Equal(t, map[string]string{
		MetadataDistribution:       EKS,
		MetadataDistributionSource: ProbeVersion,
	}, (&Result{Name: EKS, Source: ProbeVersion}).PlatformMetadata())
	assert.Equal(t, map[string]string{
		MetadataDistribution:       EKS,
		MetadataDistributionSource: ProbeVersion,
		MetadataManagedMode:        ModeEKSAutoMode,
	}, (&Result{Name: EKS, Source: ProbeVersion, ManagedMode: ModeEKSAutoMode}).PlatformMetadata())
}
