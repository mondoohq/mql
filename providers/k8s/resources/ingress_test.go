// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

func TestIngressClassUsesEffectiveClass(t *testing.T) {
	k8s := ingressTestK8s(t, `
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: nginx
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: k8s.io/ingress-nginx
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: HAProxy
spec:
  controller: haproxy.org/ingress-controller
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spec-class
  namespace: sample
spec:
  ingressClassName: HAProxy
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: annotation-class
  namespace: sample
  annotations:
    kubernetes.io/ingress.class: nginx
spec: {}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: default-class
  namespace: sample
spec: {}
`)

	assert.Equal(t, "HAProxy", ingressByName(t, k8s, "spec-class").GetIngressClass().Data.GetName().Data)
	assert.Equal(t, "nginx", ingressByName(t, k8s, "annotation-class").GetIngressClass().Data.GetName().Data)
	defaultIngress := ingressByName(t, k8s, "default-class")
	assert.Equal(t, "", defaultIngress.GetIngressClassName().Data)
	assert.Equal(t, "nginx", defaultIngress.GetIngressClass().Data.GetName().Data)
}

func TestIngressClassRejectsAmbiguousDefaultClass(t *testing.T) {
	k8s := ingressTestK8s(t, `
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: nginx
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: k8s.io/ingress-nginx
---
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata:
  name: unapproved
  annotations:
    ingressclass.kubernetes.io/is-default-class: "true"
spec:
  controller: example.test/unapproved
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: default-class
  namespace: sample
spec: {}
`)

	class := ingressByName(t, k8s, "default-class").GetIngressClass()
	require.NoError(t, class.Error)
	assert.Nil(t, class.Data)
}

func ingressTestK8s(t *testing.T, content string) *mqlK8s {
	t.Helper()

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{
			Options: map[string]string{
				shared.OPTION_NAMESPACE: "",
			},
		}},
	}, manifest.WithManifestContent([]byte(content)), manifest.WithManifestFile("inline-test-manifest.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Resources:  &syncx.Map[plugin.Resource]{},
		Connection: conn,
	}
	res, err := CreateResource(runtime, "k8s", nil)
	require.NoError(t, err)
	return res.(*mqlK8s)
}

func ingressByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sIngress {
	t.Helper()

	ingresses := k8s.GetIngresses()
	require.NoError(t, ingresses.Error)
	for _, item := range ingresses.Data {
		ingress := item.(*mqlK8sIngress)
		if ingress.GetName().Data == name {
			return ingress
		}
	}
	t.Fatalf("ingress %q not found", name)
	return nil
}
