// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// createTestR2 creates a cloudflare.r2 resource pre-wired with the test
// account ID so buckets() doesn't need a real zone navigation.
func createTestR2(t *testing.T, env *testEnv) *mqlCloudflareR2 {
	t.Helper()
	r, err := CreateResource(env.Runtime, "cloudflare.r2", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.r2@" + testAccountID),
	})
	require.NoError(t, err)
	r2 := r.(*mqlCloudflareR2)
	r2.AccountID = testAccountID
	return r2
}

func TestR2Buckets(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("r2_buckets"))
	})

	result, err := r2.buckets()
	require.NoError(t, err)
	require.Len(t, result, 3)

	b1 := result[0].(*mqlCloudflareR2Bucket)
	assert.Equal(t, "logs-archive", b1.Name.Data)
	assert.Equal(t, "ENAM", b1.Location.Data)
	require.NotNil(t, b1.CreatedOn.Data)

	b2 := result[1].(*mqlCloudflareR2Bucket)
	assert.Equal(t, "public-assets", b2.Name.Data)
	assert.Equal(t, "WNAM", b2.Location.Data)

	b3 := result[2].(*mqlCloudflareR2Bucket)
	assert.Equal(t, "backups", b3.Name.Data)
	assert.Equal(t, "WEUR", b3.Location.Data)
}

func TestR2BucketPublicAccess_enabled(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_buckets"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/public-assets/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_managed_domain_enabled"))
	})

	buckets, err := r2.buckets()
	require.NoError(t, err)
	require.Len(t, buckets, 3)

	bucket := buckets[1].(*mqlCloudflareR2Bucket)
	assert.Equal(t, "public-assets", bucket.Name.Data)

	enabled, err := bucket.publicAccessEnabled()
	require.NoError(t, err)
	assert.True(t, enabled)

	domain, err := bucket.publicAccessDomain()
	require.NoError(t, err)
	assert.Equal(t, "pub-deadbeef1234.r2.dev", domain)
}

func TestR2BucketPublicAccess_disabled(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_buckets"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/logs-archive/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_managed_domain_disabled"))
	})

	buckets, err := r2.buckets()
	require.NoError(t, err)
	bucket := buckets[0].(*mqlCloudflareR2Bucket)

	enabled, err := bucket.publicAccessEnabled()
	require.NoError(t, err)
	assert.False(t, enabled)

	domain, err := bucket.publicAccessDomain()
	require.NoError(t, err)
	assert.Equal(t, "pub-cafef00d5678.r2.dev", domain)
}

func TestR2BucketPublicAccess_forbidden(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_buckets"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/backups/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	buckets, err := r2.buckets()
	require.NoError(t, err)
	bucket := buckets[2].(*mqlCloudflareR2Bucket)

	// Caller can't read the managed-domain config — fields should be marked
	// unset/null without bubbling an error.
	enabled, err := bucket.publicAccessEnabled()
	require.NoError(t, err)
	assert.False(t, enabled)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, bucket.PublicAccessEnabled.State)

	domain, err := bucket.publicAccessDomain()
	require.NoError(t, err)
	assert.Equal(t, "", domain)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, bucket.PublicAccessDomain.State)
}

// TestR2BucketsUnboundAccountIssuesNoRequest is the regression guard for the
// empty account id. `cloudflare.r2` reached bare (not via cloudflare.account.r2)
// was built with no AccountID, so buckets() requested /accounts//r2/buckets. The
// API answers that 404, isUnavailable degrades a 404 to an empty list, and the
// malformed request read as "no buckets" — so r2-buckets-not-public passed on an
// account whose buckets were never listed. Fail before issuing the request.
func TestR2BucketsUnboundAccountIssuesNoRequest(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request may be issued without an account: %s", r.URL.Path)
	})

	r2 := &mqlCloudflareR2{MqlRuntime: env.Runtime} // no AccountID bound

	res, err := r2.buckets()
	require.ErrorIs(t, err, errNoAccountBound)
	assert.Nil(t, res, "must not degrade to an empty list, which would pass vacuously")
}

// bucketFor lists the account's buckets and returns the one named `name`,
// already wired to the test account so its per-bucket endpoints resolve.
func bucketFor(t *testing.T, r2 *mqlCloudflareR2, name string) *mqlCloudflareR2Bucket {
	t.Helper()
	buckets, err := r2.buckets()
	require.NoError(t, err)
	for _, b := range buckets {
		bucket := b.(*mqlCloudflareR2Bucket)
		if bucket.Name.Data == name {
			return bucket
		}
	}
	t.Fatalf("bucket %q not found", name)
	return nil
}

func handleBuckets(env *testEnv) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_buckets"))
	})
}

func TestR2BucketCustomDomains(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)
	handleBuckets(env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/public-assets/domains/custom", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, loadFixture("r2_custom_domains"))
	})

	bucket := bucketFor(t, r2, "public-assets")
	domains, err := bucket.customDomains()
	require.NoError(t, err)
	require.Len(t, domains, 2)

	d1 := domains[0].(*mqlCloudflareR2BucketCustomDomain)
	assert.Equal(t, "assets.example.com", d1.Domain.Data)
	assert.True(t, d1.Enabled.Data)
	assert.Equal(t, "active", d1.OwnershipStatus.Data)
	assert.Equal(t, "active", d1.SslStatus.Data)
	assert.True(t, d1.CertificateActive.Data)
	assert.Equal(t, "1.2", d1.MinTlsVersion.Data)

	// A domain still validating is registered but not yet serving TLS, and the
	// API omits minTLS entirely for it.
	d2 := domains[1].(*mqlCloudflareR2BucketCustomDomain)
	assert.Equal(t, "staging-assets.example.com", d2.Domain.Data)
	assert.False(t, d2.Enabled.Data)
	assert.Equal(t, "pending", d2.OwnershipStatus.Data)
	assert.Equal(t, "initializing", d2.SslStatus.Data)
	assert.False(t, d2.CertificateActive.Data, "a certificate that is still initializing is not active")
	assert.Equal(t, "", d2.MinTlsVersion.Data)

	// Each domain must get its own cache key, or the second overwrites the first.
	assert.NotEqual(t, d1.MqlID(), d2.MqlID())
}

// TestR2BucketIsPublicViaCustomDomainOnly is the regression guard for the false
// negative this file's fix addresses: a bucket published through a custom domain
// with the managed r2.dev subdomain switched off is world-readable, but
// publicAccessEnabled reports only the r2.dev path and so reads false.
func TestR2BucketIsPublicViaCustomDomainOnly(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)
	handleBuckets(env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/logs-archive/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_managed_domain_disabled"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/logs-archive/domains/custom", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_custom_domains"))
	})

	bucket := bucketFor(t, r2, "logs-archive")

	enabled, err := bucket.publicAccessEnabled()
	require.NoError(t, err)
	assert.False(t, enabled, "the r2.dev subdomain really is off; that field keeps its narrow meaning")

	public, err := bucket.isPublic()
	require.NoError(t, err)
	assert.True(t, public, "an enabled custom domain serves the bucket on the internet")
	assert.Zero(t, bucket.IsPublic.State&plugin.StateIsNull)
}

func TestR2BucketIsPublicViaManagedDomain(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)
	handleBuckets(env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/public-assets/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_managed_domain_enabled"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/public-assets/domains/custom", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the managed subdomain already answered the question; no custom-domain call is needed")
	})

	bucket := bucketFor(t, r2, "public-assets")
	public, err := bucket.isPublic()
	require.NoError(t, err)
	assert.True(t, public)
}

func TestR2BucketIsPublicNeitherPath(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)
	handleBuckets(env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/backups/domains/managed", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_managed_domain_disabled"))
	})
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/backups/domains/custom", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("r2_custom_domains_empty"))
	})

	bucket := bucketFor(t, r2, "backups")

	domains, err := bucket.customDomains()
	require.NoError(t, err)
	assert.Empty(t, domains)

	public, err := bucket.isPublic()
	require.NoError(t, err)
	assert.False(t, public)
	assert.Zero(t, bucket.IsPublic.State&plugin.StateIsNull, "both paths were read, so false is a real answer")
}

// TestR2BucketIsPublicUnreadablePathIsNull covers the half-read case. Reporting
// `false` when one of the two exposure paths could not be read would reproduce
// the same false negative in a new field, so the answer is null instead.
func TestR2BucketIsPublicUnreadablePathIsNull(t *testing.T) {
	for _, tc := range []struct{ name, unreadable, readable string }{
		{"custom domains forbidden", "custom", "managed"},
		{"managed subdomain forbidden", "managed", "custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			r2 := createTestR2(t, env)
			handleBuckets(env)

			base := fmt.Sprintf("/accounts/%s/r2/buckets/backups/domains/", testAccountID)
			env.Mux.HandleFunc(base+tc.unreadable, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
			})
			switch tc.readable {
			case "managed":
				env.Mux.HandleFunc(base+"managed", func(w http.ResponseWriter, r *http.Request) {
					jsonResponse(w, loadFixture("r2_managed_domain_disabled"))
				})
			case "custom":
				env.Mux.HandleFunc(base+"custom", func(w http.ResponseWriter, r *http.Request) {
					jsonResponse(w, loadFixture("r2_custom_domains_empty"))
				})
			}

			bucket := bucketFor(t, r2, "backups")
			public, err := bucket.isPublic()
			require.NoError(t, err)
			assert.False(t, public)
			assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, bucket.IsPublic.State,
				"exposure is unknown, so the bucket must not be reported as private")
		})
	}
}

func TestR2BucketCustomDomainsForbidden(t *testing.T) {
	env := setupTestEnv(t)
	r2 := createTestR2(t, env)
	handleBuckets(env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/r2/buckets/backups/domains/custom", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	bucket := bucketFor(t, r2, "backups")
	domains, err := bucket.customDomains()
	require.NoError(t, err, "a gated or unreadable add-on must not fail the whole query")
	assert.Empty(t, domains)
}

// TestR2BucketCustomDomainsUnboundAccountIssuesNoRequest mirrors the buckets()
// guard: with no account bound the request would go to /accounts//r2/... , which
// the API answers 404 and isUnavailable degrades to empty. Skip the request.
func TestR2BucketCustomDomainsUnboundAccountIssuesNoRequest(t *testing.T) {
	env := setupTestEnv(t)
	env.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request may be issued without an account: %s", r.URL.Path)
	})

	res, err := CreateResource(env.Runtime, "cloudflare.r2.bucket", map[string]*llx.RawData{
		"__id": llx.StringData("unbound"),
		"name": llx.StringData("backups"),
	})
	require.NoError(t, err)
	bucket := res.(*mqlCloudflareR2Bucket) // no accountID bound

	domains, err := bucket.customDomains()
	require.NoError(t, err)
	assert.Empty(t, domains)
}
