// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"

	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
)

func TestToNetworkingV1IngressLegacyVersions(t *testing.T) {
	for _, apiVersion := range []string{"extensions/v1beta1", "networking.k8s.io/v1beta1"} {
		t.Run(apiVersion, func(t *testing.T) {
			manifest := `apiVersion: ` + apiVersion + `
kind: Ingress
metadata:
  name: legacy
  namespace: default
spec:
  backend:
    serviceName: fallback
    servicePort: 8080
  tls:
  - hosts: [example.com]
    secretName: example-tls
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        backend:
          serviceName: web
          servicePort: http
`
			objs, err := resources.ResourcesFromManifest(strings.NewReader(manifest))
			require.NoError(t, err)
			require.Len(t, objs, 1)

			ing, err := toNetworkingV1Ingress(objs[0])
			require.NoError(t, err)
			assert.Equal(t, "legacy", ing.Name)
			assert.Equal(t, "default", ing.Namespace)

			require.NotNil(t, ing.Spec.DefaultBackend)
			require.NotNil(t, ing.Spec.DefaultBackend.Service)
			assert.Equal(t, "fallback", ing.Spec.DefaultBackend.Service.Name)
			assert.Equal(t, int32(8080), ing.Spec.DefaultBackend.Service.Port.Number)

			require.Len(t, ing.Spec.TLS, 1)
			assert.Equal(t, "example-tls", ing.Spec.TLS[0].SecretName)

			require.Len(t, ing.Spec.Rules, 1)
			assert.Equal(t, "example.com", ing.Spec.Rules[0].Host)
			require.NotNil(t, ing.Spec.Rules[0].HTTP)
			require.Len(t, ing.Spec.Rules[0].HTTP.Paths, 1)
			path := ing.Spec.Rules[0].HTTP.Paths[0]
			assert.Equal(t, "/", path.Path)
			require.NotNil(t, path.Backend.Service)
			assert.Equal(t, "web", path.Backend.Service.Name)
			assert.Equal(t, "http", path.Backend.Service.Port.Name)
			assert.Zero(t, path.Backend.Service.Port.Number)
		})
	}
}

func TestToNetworkingV1IngressCurrentVersion(t *testing.T) {
	in := &networkingv1.Ingress{}
	out, err := toNetworkingV1Ingress(in)
	require.NoError(t, err)
	assert.Same(t, in, out)
}
