// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
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
	cfg := &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: caPEM}}
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
		ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default"}},
		Spec:       corev1.NodeSpec{ProviderID: "gce://p/us-central1-a/n1"},
	})
	nodes, err := listNodes(context.Background(), client)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "gce://p/us-central1-a/n1", nodes[0].ProviderID)
	d, _ := distro.FromNodes(nodes)
	assert.Equal(t, distro.GKE, d)
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
