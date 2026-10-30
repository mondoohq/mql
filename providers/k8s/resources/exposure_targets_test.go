// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
)

func exposureRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/exposure_targets.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func TestServicePods(t *testing.T) {
	runtime := exposureRuntime(t)

	svc, err := NewResource(runtime, "k8s.service", map[string]*llx.RawData{
		"name":      llx.StringData("web-svc"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pods := svc.(*mqlK8sService).GetPods()
	require.NoError(t, pods.Error)
	// Selects app=web in prod only — excludes other-1 and the same-labeled pod
	// in the staging namespace.
	assert.Equal(t, []string{"web-1", "web-2"}, mqlResourceNames(t, pods.Data))

	// Selectorless service selects nothing.
	headless, err := NewResource(runtime, "k8s.service", map[string]*llx.RawData{
		"name":      llx.StringData("headless"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	hp := headless.(*mqlK8sService).GetPods()
	require.NoError(t, hp.Error)
	assert.Empty(t, hp.Data)
}

func TestPodServices(t *testing.T) {
	runtime := exposureRuntime(t)

	pod, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("web-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	svcs := pod.(*mqlK8sPod).GetServices()
	require.NoError(t, svcs.Error)
	assert.Equal(t, []string{"web-svc"}, mqlResourceNames(t, svcs.Data))

	// A pod no service selects resolves to no services.
	other, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("other-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	os := other.(*mqlK8sPod).GetServices()
	require.NoError(t, os.Error)
	assert.Empty(t, os.Data)
}

func TestIngressPods(t *testing.T) {
	runtime := exposureRuntime(t)

	ing, err := NewResource(runtime, "k8s.ingress", map[string]*llx.RawData{
		"name":      llx.StringData("web-ing"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pods := ing.(*mqlK8sIngress).GetPods()
	require.NoError(t, pods.Error)
	assert.Equal(t, []string{"web-1", "web-2"}, mqlResourceNames(t, pods.Data))
}

func TestGatewayPods(t *testing.T) {
	runtime := exposureRuntime(t)

	gw, err := NewResource(runtime, "k8s.gateway", map[string]*llx.RawData{
		"name":      llx.StringData("gw"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	pods := gw.(*mqlK8sGateway).GetPods()
	require.NoError(t, pods.Error)
	// HTTPRoute and GRPCRoute both target web-svc; the backing pods dedup.
	assert.Equal(t, []string{"web-1", "web-2"}, mqlResourceNames(t, pods.Data))
}

func TestNetworkExposurePods(t *testing.T) {
	k8sObj, err := NewResource(exposureRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	exps := k8s.GetNetworkExposures()
	require.NoError(t, exps.Error)

	var serviceExposure *mqlK8sNetworkExposure
	for i := range exps.Data {
		e := exps.Data[i].(*mqlK8sNetworkExposure)
		if e.SourceKind.Data == "Service" && e.Name.Data == "web-svc" {
			serviceExposure = e
			break
		}
	}
	require.NotNil(t, serviceExposure, "expected a Service-sourced exposure for web-svc")

	pods := serviceExposure.GetPods()
	require.NoError(t, pods.Error)
	assert.Equal(t, []string{"web-1", "web-2"}, mqlResourceNames(t, pods.Data))
}

func secretByName(t *testing.T, runtime *plugin.Runtime, name string) *mqlK8sSecret {
	t.Helper()
	s, err := NewResource(runtime, "k8s.secret", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	return s.(*mqlK8sSecret)
}

func TestSecretHygiene(t *testing.T) {
	runtime := exposureRuntime(t)

	tests := []struct {
		name              string
		serviceAccountTok bool
		imagePull         bool
		unused            bool
	}{
		// mounted by web-1
		{"used-secret", false, false, false},
		// image-pull secret referenced by web-1
		{"pull", false, true, false},
		// no pod and no service account reference it
		{"orphan", false, false, true},
		// referenced only by web-sa, so not orphaned despite no pod use
		{"sa-token", true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secretByName(t, runtime, tt.name)

			sat := s.GetIsServiceAccountToken()
			require.NoError(t, sat.Error)
			assert.Equal(t, tt.serviceAccountTok, sat.Data, "isServiceAccountToken")

			ips := s.GetIsImagePullSecret()
			require.NoError(t, ips.Error)
			assert.Equal(t, tt.imagePull, ips.Data, "isImagePullSecret")

			unused := s.GetIsUnused()
			require.NoError(t, unused.Error)
			assert.Equal(t, tt.unused, unused.Data, "isUnused")
		})
	}
}

func TestPodExposures(t *testing.T) {
	runtime := exposureRuntime(t)

	// web-1 sits behind the public web-svc (and the ingress/gateway routing to
	// it), so it must report at least the Service-sourced exposure.
	web, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("web-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	exps := web.(*mqlK8sPod).GetExposures()
	require.NoError(t, exps.Error)

	var sawServiceExposure bool
	for i := range exps.Data {
		e := exps.Data[i].(*mqlK8sNetworkExposure)
		if e.SourceKind.Data == "Service" && e.Name.Data == "web-svc" {
			sawServiceExposure = true
		}
	}
	assert.True(t, sawServiceExposure, "web-1 must report the web-svc Service exposure")

	// other-1 is selected by no service, so nothing exposes it.
	other, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
		"name":      llx.StringData("other-1"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	otherExps := other.(*mqlK8sPod).GetExposures()
	require.NoError(t, otherExps.Error)
	assert.Empty(t, otherExps.Data)
}

// requireServiceExposure asserts that the exposure list contains the
// internet-exposed Service exposure for web-svc.
func requireServiceExposure(t *testing.T, exps []any) {
	t.Helper()
	for i := range exps {
		e, ok := exps[i].(*mqlK8sNetworkExposure)
		if !ok {
			continue
		}
		if e.SourceKind.Data == "Service" && e.Name.Data == "web-svc" {
			internet := e.GetInternetExposed()
			require.NoError(t, internet.Error)
			assert.True(t, internet.Data, "web-svc exposure must classify as internet exposed")
			return
		}
	}
	t.Fatalf("expected the web-svc Service exposure, got %d other exposures", len(exps))
}

func TestWorkloadExposures(t *testing.T) {
	runtime := exposureRuntime(t)

	// The deployment backing web-1/web-2 inherits the exposures that route to
	// its pods. This is the edge that lets controller-managed workloads carry
	// the internet exposure their pods serve, since owned pods are not
	// discovered as assets of their own.
	dep, err := NewResource(runtime, "k8s.deployment", map[string]*llx.RawData{
		"name":      llx.StringData("web"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	depExps := dep.(*mqlK8sDeployment).GetExposures()
	require.NoError(t, depExps.Error)
	requireServiceExposure(t, depExps.Data)

	// A bare ReplicaSet with the same selector resolves the same exposure.
	rs, err := NewResource(runtime, "k8s.replicaset", map[string]*llx.RawData{
		"name":      llx.StringData("web-rs"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	rsExps := rs.(*mqlK8sReplicaset).GetExposures()
	require.NoError(t, rsExps.Error)
	requireServiceExposure(t, rsExps.Data)

	// A workload whose pods no service selects reports no exposures.
	ds, err := NewResource(runtime, "k8s.daemonset", map[string]*llx.RawData{
		"name":      llx.StringData("other-ds"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	dsExps := ds.(*mqlK8sDaemonset).GetExposures()
	require.NoError(t, dsExps.Error)
	assert.Empty(t, dsExps.Data)

	// Same pod labels in another namespace must not inherit the prod service's
	// exposure: service selection is namespace scoped.
	sts, err := NewResource(runtime, "k8s.statefulset", map[string]*llx.RawData{
		"name":      llx.StringData("web-staging-sts"),
		"namespace": llx.StringData("staging"),
	})
	require.NoError(t, err)
	stsExps := sts.(*mqlK8sStatefulset).GetExposures()
	require.NoError(t, stsExps.Error)
	assert.Empty(t, stsExps.Data)
}

// testCertPEM generates a self-signed certificate that expires at notAfter.
func testCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func tlsSecret(certPEM []byte) *mqlK8sSecret {
	s := &mqlK8sSecret{}
	s.obj = &corev1.Secret{
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": certPEM},
	}
	return s
}

func TestSecretCertificateExpiry(t *testing.T) {
	valid := testCertPEM(t, time.Now().Add(90*24*time.Hour))
	expired := testCertPEM(t, time.Now().Add(-1*time.Hour))

	t.Run("valid certificate", func(t *testing.T) {
		s := tlsSecret(valid)
		he, err := s.hasExpiredCertificate()
		require.NoError(t, err)
		assert.False(t, he)

		exp, err := s.certificateExpiry()
		require.NoError(t, err)
		require.NotNil(t, exp)
		assert.True(t, exp.After(time.Now()))
	})

	t.Run("expired certificate", func(t *testing.T) {
		s := tlsSecret(expired)
		he, err := s.hasExpiredCertificate()
		require.NoError(t, err)
		assert.True(t, he)
	})

	t.Run("chain reports earliest expiry and any expired", func(t *testing.T) {
		chain := append(append([]byte{}, valid...), expired...)
		s := tlsSecret(chain)

		he, err := s.hasExpiredCertificate()
		require.NoError(t, err)
		assert.True(t, he, "a chain with one expired cert is expired")

		exp, err := s.certificateExpiry()
		require.NoError(t, err)
		require.NotNil(t, exp)
		assert.True(t, exp.Before(time.Now()), "earliest expiry is the already-expired cert")
	})

	t.Run("non-TLS secret has no certificates", func(t *testing.T) {
		s := &mqlK8sSecret{}
		s.obj = &corev1.Secret{
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"key": []byte("value")},
		}
		he, err := s.hasExpiredCertificate()
		require.NoError(t, err)
		assert.False(t, he)

		exp, err := s.certificateExpiry()
		require.NoError(t, err)
		assert.Nil(t, exp)
	})
}
