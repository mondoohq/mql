// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
	networkingv1 "k8s.io/api/networking/v1"
)

// tlsSecret builds a k8s.secret whose certificates field is already resolved,
// so getTLS reads it without needing the core provider's shared certificate
// resource.
func ingressTLSSecret(t *testing.T, runtime *plugin.Runtime, name string, certs []any, certErr error) *mqlK8sSecret {
	t.Helper()
	r, err := CreateResource(runtime, "k8s.secret", map[string]*llx.RawData{
		"id":        llx.StringData("secret:default:" + name),
		"name":      llx.StringData(name),
		"namespace": llx.StringData("default"),
	})
	require.NoError(t, err)
	s := r.(*mqlK8sSecret)
	s.Certificates = plugin.TValue[[]any]{Data: certs, Error: certErr, State: plugin.StateIsSet}
	return s
}

// TestGetTLSDegradesPerEntry pins that one unreadable certificate does not take
// the Ingress's other TLS entries with it.
//
// getTLS used to return an error for the whole field the moment any referenced
// Secret failed to yield a certificate, so an Ingress carrying a single
// placeholder or not-yet-issued certificate reported no TLS configuration at
// all rather than the entries that were fine. Its own comment already said the
// intent was to "keep trying to process as much as we can", which is what the
// missing-Secret and empty-data paths do.
func TestGetTLSDegradesPerEntry(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	secrets := []any{
		ingressTLSSecret(t, runtime, "tls-broken", nil, errors.New("certificate has invalid pem data")),
		ingressTLSSecret(t, runtime, "tls-good", []any{"cert"}, nil),
		ingressTLSSecret(t, runtime, "tls-empty", nil, nil),
	}
	getSecrets := func() *plugin.TValue[[]any] {
		return &plugin.TValue[[]any]{Data: secrets, State: plugin.StateIsSet}
	}

	ing := &networkingv1.Ingress{
		Name: "mixed", Namespace: "default",
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"broken.example.com"}, SecretName: "tls-broken"},
				{Hosts: []string{"good.example.com"}, SecretName: "tls-good"},
				{Hosts: []string{"empty.example.com"}, SecretName: "tls-empty"},
				{Hosts: []string{"absent.example.com"}, SecretName: "tls-absent"},
			},
		},
	}

	out, err := getTLS(ing, "ingress:default:mixed", runtime, getSecrets)
	require.NoError(t, err, "one bad certificate must not fail the whole tls field")
	require.Len(t, out, 1, "only the entry with a readable certificate is returned")

	entry := out[0].(*mqlK8sIngresstls)
	assert.Equal(t, []any{"good.example.com"}, entry.Hosts.Data)
	assert.Equal(t, []any{"cert"}, entry.Certificates.Data)
}

// TestGetTLSNoEntries keeps the empty case explicit: an Ingress without TLS
// yields an empty list and no error.
func TestGetTLSNoEntries(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	getSecrets := func() *plugin.TValue[[]any] {
		return &plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	}
	ing := &networkingv1.Ingress{Name: "none", Namespace: "default"}

	out, err := getTLS(ing, "ingress:default:none", runtime, getSecrets)
	require.NoError(t, err)
	assert.Empty(t, out)
}
