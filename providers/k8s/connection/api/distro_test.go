// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestKubeconfigInfo(t *testing.T) {
	kc := &clientcmdapi.Config{
		CurrentContext: "dev",
		Contexts: map[string]*clientcmdapi.Context{
			"dev":  {Cluster: "arn:aws:eks:us-east-1:123456789012:cluster/demo"},
			"prod": {Cluster: "gke_p_us-central1_c"},
		},
	}
	cfg := &rest.Config{ExecProvider: &clientcmdapi.ExecConfig{Command: "aws", Args: []string{"eks", "get-token", "--cluster-name", "demo"}}}
	k := kubeconfigInfo(kc, "", cfg, false)
	assert.Equal(t, "arn:aws:eks:us-east-1:123456789012:cluster/demo", k.ClusterEntry)
	assert.Equal(t, "aws", k.ExecCommand)
	assert.Equal(t, []string{"eks", "get-token", "--cluster-name", "demo"}, k.ExecArgs)

	// the helpers clear the exec plugin later; the captured copy stays
	cfg.ExecProvider.Args[0] = "changed"
	assert.Equal(t, "eks", k.ExecArgs[0])

	k = kubeconfigInfo(kc, "prod", &rest.Config{AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "gcp"}}, true)
	assert.Equal(t, "gke_p_us-central1_c", k.ClusterEntry)
	assert.Equal(t, "gcp", k.AuthProvider)
	assert.True(t, k.Kubelogin)

	k = kubeconfigInfo(nil, "", &rest.Config{}, false)
	assert.Equal(t, "", k.ClusterEntry)
}

func TestCertificateNames(t *testing.T) {
	// httptest's certificate names example.com; a 401 still completes the
	// handshake
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := &rest.Config{Host: srv.URL, CAData: caPEM}
	got, err := certificateNames(context.Background(), cfg)
	require.NoError(t, err)
	assert.Contains(t, got, "example.com")

	// plain HTTP has no certificate
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	_, err = certificateNames(context.Background(), &rest.Config{Host: plain.URL})
	assert.Error(t, err)
}

// an API server the connection does not trust is not read: the probe uses the
// connection's own TLS settings, as every other request does
func TestCertificateNamesUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := certificateNames(context.Background(), &rest.Config{Host: srv.URL})
	assert.Error(t, err)
}

func TestListNodes(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{
		Name: "n1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default"},
		Spec: corev1.NodeSpec{ProviderID: "gce://p/us-central1-a/n1"},
	})
	nodes, err := listNodes(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "gce://p/us-central1-a/n1", nodes[0].ProviderID)
	assert.Equal(t, "n1", nodes[0].Name)
	d, _ := distro.FromNodes(nodes)
	assert.Equal(t, distro.GKE, d)
}

// discoveryServer serves API discovery for the given group versions.
func discoveryServer(t *testing.T, resources map[string][]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api":
			_ = json.NewEncoder(w).Encode(metav1.APIVersions{Versions: []string{"v1"}})
			return
		case "/apis":
			groups := map[string]*metav1.APIGroup{}
			var order []string
			for gv := range resources {
				group, version, _ := strings.Cut(gv, "/")
				g, ok := groups[group]
				if !ok {
					g = &metav1.APIGroup{Name: group}
					groups[group] = g
					order = append(order, group)
				}
				g.Versions = append(g.Versions, metav1.GroupVersionForDiscovery{GroupVersion: gv, Version: version})
			}
			list := metav1.APIGroupList{}
			for _, name := range order {
				list.Groups = append(list.Groups, *groups[name])
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		gv := strings.TrimPrefix(r.URL.Path, "/apis/")
		names, ok := resources[gv]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		list := metav1.APIResourceList{GroupVersion: gv}
		for _, n := range names {
			list.APIResources = append(list.APIResources, metav1.APIResource{Name: n})
		}
		_ = json.NewEncoder(w).Encode(list)
	}))
}

func TestAPIGroupResources(t *testing.T) {
	// what a GKE Autopilot cluster serves in auto.gke.io
	srv := discoveryServer(t, map[string][]string{
		"auto.gke.io/v1":       {"allowlistedv2workloads", "allowlistedworkloads", "allowlistsynchronizers"},
		"auto.gke.io/v1alpha1": {"workloadallowlists", "workloadallowlists/status"},
		"apps/v1":              {"deployments"},
	})
	defer srv.Close()

	names, err := apiGroupResources(&rest.Config{Host: srv.URL}, "auto.gke.io")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"allowlistedv2workloads", "allowlistedworkloads", "allowlistsynchronizers", "workloadallowlists"}, names)

	names, err = apiGroupResources(&rest.Config{Host: srv.URL}, "eks.amazonaws.com")
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestGroupVersionResources(t *testing.T) {
	list := func(gv string) (*metav1.APIResourceList, error) {
		switch gv {
		case "eks.amazonaws.com/v1":
			return &metav1.APIResourceList{APIResources: []metav1.APIResource{{Name: "nodeclasses"}, {Name: "nodeclasses/status"}}}, nil
		case "eks.amazonaws.com/v1beta1":
			return &metav1.APIResourceList{APIResources: []metav1.APIResource{{Name: "nodeclasses"}, {Name: "nodediagnostics"}}}, nil
		}
		return nil, errors.New("unavailable")
	}

	names, err := groupVersionResources([]string{"eks.amazonaws.com/v1", "eks.amazonaws.com/v1beta1", "eks.amazonaws.com/v2"}, list)
	require.NoError(t, err, "a version that can't be read is skipped")
	assert.Equal(t, []string{"nodeclasses", "nodediagnostics"}, names)

	_, err = groupVersionResources([]string{"eks.amazonaws.com/v2"}, list)
	assert.Error(t, err, "no version could be read")

	names, err = groupVersionResources(nil, list)
	require.NoError(t, err)
	assert.Empty(t, names)
}

func metadataServer(t *testing.T, routes map[string]string, header [2]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			if body, ok := routes["PUT /latest/api/token"]; ok {
				_, _ = w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if header[0] != "" && r.Header.Get(header[0]) != header[1] {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, ok := routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

func TestCloudMetadataGKE(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"/computeMetadata/v1/project/project-id":                   "my-project",
		"/computeMetadata/v1/instance/attributes/cluster-name":     "cep-gke-pass",
		"/computeMetadata/v1/instance/attributes/cluster-location": "us-central1-a",
	}, [2]string{"Metadata-Flavor", "Google"})
	defer srv.Close()

	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, distro.GKE, res.Distro)
	assert.Equal(t, distro.Identity{ClusterName: "cep-gke-pass", Region: "us-central1-a", Account: "my-project"}, res.Identity)
}

func TestCloudMetadataAKS(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"/metadata/instance/compute": `{"location":"westus3","subscriptionId":"00000000-0000-0000-0000-000000000000",
			"tagsList":[{"name":"aks-managed-poolName","value":"system"}]}`,
	}, [2]string{"Metadata", "true"})
	defer srv.Close()

	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, distro.AKS, res.Distro)
	assert.Equal(t, "westus3", res.Identity.Region)
	assert.Equal(t, "00000000-0000-0000-0000-000000000000", res.Identity.Account)
}

func TestCloudMetadataAWSWithoutTags(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"PUT /latest/api/token":              "token",
		"/latest/meta-data/placement/region": "us-east-1",
	}, [2]string{"X-aws-ec2-metadata-token", "token"})
	defer srv.Close()

	// EC2 without instance tags in the metadata: the cloud, not EKS
	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "", res.Distro)
	assert.Equal(t, "aws", res.Value)
	assert.Equal(t, "", res.Identity.Account, "no identity document, no account")
}

func TestCloudMetadataAWSIdentityDocument(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"PUT /latest/api/token":                            "token",
		"/latest/meta-data/placement/region":               "eu-central-1",
		"/latest/meta-data/tags/instance/eks:cluster-name": "prod",
		"/latest/dynamic/instance-identity/document": `{"accountId":"111111111111","region":"eu-central-1",
			"instanceId":"i-0123456789abcdef0","imageId":"ami-0123"}`,
	}, [2]string{"X-aws-ec2-metadata-token", "token"})
	defer srv.Close()

	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, distro.EKS, res.Distro)
	assert.Equal(t, distro.Identity{ClusterName: "prod", Region: "eu-central-1", Account: "111111111111"}, res.Identity)
}

func TestCloudMetadataAWSIdentityDocumentRegionFallback(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"PUT /latest/api/token":                      "token",
		"/latest/dynamic/instance-identity/document": `{"accountId":"111111111111","region":"us-west-2"}`,
	}, [2]string{"X-aws-ec2-metadata-token", "token"})
	defer srv.Close()

	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "", res.Distro)
	assert.Equal(t, distro.Identity{Region: "us-west-2", Account: "111111111111"}, res.Identity)
}

func TestCloudMetadataAWSMalformedIdentityDocument(t *testing.T) {
	srv := metadataServer(t, map[string]string{
		"PUT /latest/api/token":                      "token",
		"/latest/meta-data/placement/region":         "us-east-1",
		"/latest/dynamic/instance-identity/document": `not json`,
	}, [2]string{"X-aws-ec2-metadata-token", "token"})
	defer srv.Close()

	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, distro.Identity{Region: "us-east-1"}, res.Identity, "a bad document costs the account, not the probe")
}

func TestCloudMetadataNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	res, err := cloudMetadata(context.Background(), srv.Client(), srv.URL)
	assert.NoError(t, err)
	assert.Nil(t, res)
}
