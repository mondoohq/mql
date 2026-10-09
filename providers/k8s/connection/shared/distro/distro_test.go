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

	// a self-managed cluster in a cloud is not named after the instance
	res = Detect(context.Background(), Probes{Version: version("v1.33.4+k3s1"), Metadata: md})
	assert.Equal(t, K3s, res.Name)
	assert.Equal(t, Identity{}, res.Identity)
}
