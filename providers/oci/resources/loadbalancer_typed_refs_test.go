// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const testLbId = "ocid1.loadbalancer.oc1..aaaa"

func testCipherSuites() map[string]loadbalancer.SslCipherSuite {
	return map[string]loadbalancer.SslCipherSuite{
		"custom-strong": {Ciphers: []string{"ECDHE-RSA-AES256-GCM-SHA384"}},
		"custom-weak":   {Ciphers: []string{"RC4-MD5"}},
	}
}

func testCertificates() map[string]loadbalancer.Certificate {
	return map[string]loadbalancer.Certificate{
		"wildcard": {
			CertificateName:   new("wildcard"),
			PublicCertificate: new("-----BEGIN CERTIFICATE-----"),
		},
	}
}

// TestLbSubResourceIdsMatchTheParentListing pins the one thing that makes the
// typed references share cache entries with the load balancer's own listings:
// both paths must build the same __id. If they diverge, a cipher suite reached
// through `loadBalancers.sslCipherSuites` and the same suite reached through
// `listeners.sslCipherSuite` become two instances of one object, and a query
// joining them compares different things.
func TestLbSubResourceIdsMatchTheParentListing(t *testing.T) {
	rt := testRuntime()

	suite, err := newMqlLbCipherSuite(rt, testLbId, "custom-strong", testCipherSuites()["custom-strong"])
	require.NoError(t, err)
	assert.Equal(t, testLbId+"/sslCipherSuite/custom-strong", suite.MqlID())

	bundle, err := newMqlLbCertificateBundle(rt, testLbId, "wildcard", testCertificates()["wildcard"])
	require.NoError(t, err)
	assert.Equal(t, testLbId+"/certificateBundle/wildcard", bundle.MqlID())

	ruleSet, err := newMqlLbRuleSet(rt, testLbId, "block-admin", loadbalancer.RuleSet{})
	require.NoError(t, err)
	assert.Equal(t, testLbId+"/ruleSet/block-admin", ruleSet.MqlID())
}

// TestResolveLbCipherSuite covers the three branches of the resolver, including
// the one that makes a miss a null rather than an error: OCI's predefined
// suites (oci-default-ssl-cipher-suite-v1 and friends) are named by listeners
// but are not part of the load balancer's own collection.
func TestResolveLbCipherSuite(t *testing.T) {
	tests := []struct {
		name      string
		lookup    string
		wantFound bool
	}{
		{name: "custom suite defined on the load balancer", lookup: "custom-strong", wantFound: true},
		{name: "OCI predefined suite is not enumerated", lookup: "oci-default-ssl-cipher-suite-v1"},
		{name: "listener terminates no TLS", lookup: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := testRuntime()
			var field plugin.TValue[*mqlOciLoadBalancerSslCipherSuite]

			got, err := resolveLbCipherSuite(rt, testLbId, tt.lookup, testCipherSuites(), &field)
			require.NoError(t, err)

			if !tt.wantFound {
				assert.Nil(t, got)
				// The field has to be marked set-and-null. Leaving it unset
				// makes the runtime treat the reference as unresolved rather
				// than as absent.
				assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, testLbId+"/sslCipherSuite/"+tt.lookup, got.MqlID())
			assert.Equal(t, tt.lookup, got.Name.Data)
			assert.Equal(t, []any{"ECDHE-RSA-AES256-GCM-SHA384"}, got.Ciphers.Data)
		})
	}
}

// TestResolveLbCertificateBundle covers the same three branches for the inline
// certificate bundle.
func TestResolveLbCertificateBundle(t *testing.T) {
	tests := []struct {
		name      string
		lookup    string
		wantFound bool
	}{
		{name: "bundle managed on the load balancer", lookup: "wildcard", wantFound: true},
		{name: "name the load balancer does not define", lookup: "missing"},
		{name: "backend set carries no SSL configuration", lookup: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := testRuntime()
			var field plugin.TValue[*mqlOciLoadBalancerCertificateBundle]

			got, err := resolveLbCertificateBundle(rt, testLbId, tt.lookup, testCertificates(), &field)
			require.NoError(t, err)

			if !tt.wantFound {
				assert.Nil(t, got)
				assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, testLbId+"/certificateBundle/wildcard", got.MqlID())
			assert.Equal(t, "-----BEGIN CERTIFICATE-----", got.PublicCertificate.Data)
		})
	}
}

// TestListenerRuleSetsSkipsUnknown exercises ruleSets() itself. A listener may
// name a rule set the load balancer does not define; the API permits it, so
// the entry is skipped rather than failing the whole listener.
func TestListenerRuleSetsSkipsUnknown(t *testing.T) {
	listener := &mqlOciLoadBalancerListener{MqlRuntime: testRuntime()}
	listener.cacheLbId = testLbId
	listener.cacheRuleSetNames = []string{"block-admin", "does-not-exist", "add-hsts"}
	listener.cacheLbRuleSets = map[string]loadbalancer.RuleSet{
		"block-admin": {Items: []loadbalancer.Rule{}},
		"add-hsts":    {Items: []loadbalancer.Rule{}},
	}

	got, err := listener.ruleSets()
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, testLbId+"/ruleSet/block-admin", got[0].(plugin.Resource).MqlID())
	assert.Equal(t, testLbId+"/ruleSet/add-hsts", got[1].(plugin.Resource).MqlID())
}

// TestListenerRuleSetsEmpty pins the no-rule-sets case as an empty list rather
// than null, so `ruleSets.length == 0` is answerable.
func TestListenerRuleSetsEmpty(t *testing.T) {
	listener := &mqlOciLoadBalancerListener{MqlRuntime: testRuntime()}
	listener.cacheLbId = testLbId

	got, err := listener.ruleSets()
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

// TestBackendSetTypedRefs exercises the accessors on the backend set, which
// share the resolvers with the listener but read different cache fields.
func TestBackendSetTypedRefs(t *testing.T) {
	bs := &mqlOciLoadBalancerBackendSet{MqlRuntime: testRuntime()}
	bs.cacheLbId = testLbId
	bs.cacheCipherSuiteName = "custom-weak"
	bs.cacheCertBundleName = "wildcard"
	bs.cacheLbCipherSuites = testCipherSuites()
	bs.cacheLbCertificates = testCertificates()

	suite, err := bs.sslCipherSuite()
	require.NoError(t, err)
	require.NotNil(t, suite)
	assert.Equal(t, []any{"RC4-MD5"}, suite.Ciphers.Data)

	bundle, err := bs.certificateBundle()
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Equal(t, testLbId+"/certificateBundle/wildcard", bundle.MqlID())
}

// TestBackendSetNoSslConfiguration pins the common case: a backend set that
// talks to its backends in the clear carries no SSL configuration at all, and
// both references must read null rather than unresolved.
func TestBackendSetNoSslConfiguration(t *testing.T) {
	bs := &mqlOciLoadBalancerBackendSet{MqlRuntime: testRuntime()}
	bs.cacheLbId = testLbId
	bs.cacheLbCipherSuites = testCipherSuites()
	bs.cacheLbCertificates = testCertificates()

	suite, err := bs.sslCipherSuite()
	require.NoError(t, err)
	assert.Nil(t, suite)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, bs.SslCipherSuite.State)

	bundle, err := bs.certificateBundle()
	require.NoError(t, err)
	assert.Nil(t, bundle)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, bs.CertificateBundle.State)
}
