// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- error classifiers ---

// TestIsDoForbidden pins the 403 classifier. It has to match a denied read
// and nothing else: if a transport error were classified as "forbidden",
// callers that tolerate a denial would swallow a network blip and report a
// clean posture on data that was never read.
func TestIsDoForbidden(t *testing.T) {
	t.Run("nil is not a 403", func(t *testing.T) {
		assert.False(t, isDoForbidden(nil))
	})

	t.Run("godo 403 is a 403", func(t *testing.T) {
		assert.True(t, isDoForbidden(&godo.ErrorResponse{
			Response: &http.Response{StatusCode: http.StatusForbidden},
		}))
	})

	t.Run("godo 404 is not a 403", func(t *testing.T) {
		assert.False(t, isDoForbidden(&godo.ErrorResponse{
			Response: &http.Response{StatusCode: http.StatusNotFound},
		}))
	})

	t.Run("transport error is not a 403", func(t *testing.T) {
		// A connection reset says nothing about permissions. Classifying it
		// as a denial would let a caller degrade it to an empty result.
		assert.False(t, isDoForbidden(&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}))
	})

	t.Run("godo error with no response is not a 403", func(t *testing.T) {
		// godo builds an ErrorResponse with a nil Response on some paths;
		// dereferencing it would panic the provider.
		assert.False(t, isDoForbidden(&godo.ErrorResponse{Message: "boom"}))
	})
}

// --- URN parsing ---

func TestUrnResourceType(t *testing.T) {
	for _, tc := range []struct {
		name string
		urn  string
		want string
	}{
		{"droplet", "do:droplet:12345", "droplet"},
		{"load balancer", "do:loadbalancer:8f1d-4c2a", "loadbalancer"},
		{"database", "do:dbaas:0a1b-2c3d", "dbaas"},
		{"kubernetes", "do:kubernetes:9e8d-7c6b", "kubernetes"},
		{"surrounding whitespace", "  do:droplet:12345  ", "droplet"},
		{"id containing colons", "do:droplet:a:b:c", "droplet"},
		{"empty", "", ""},
		{"not a urn", "12345", ""},
		{"wrong scheme", "aws:droplet:12345", ""},
		{"missing id segment", "do:droplet", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, urnResourceType(tc.urn))
		})
	}
}

// --- pool connection endpoints ---

// TestPoolConnection is the guard on the finding this PR closes: a pool
// that terminates plaintext in front of a TLS-only cluster must not read
// as encrypted, and a pool with no such endpoint must read as null rather
// than as an endpoint with TLS switched off.
func TestPoolConnection(t *testing.T) {
	t.Run("absent endpoint is null, not a plaintext one", func(t *testing.T) {
		host, port, ssl := poolConnection(nil)
		assert.Nil(t, host, "an absent endpoint must not report a hostname")
		assert.Nil(t, port, "an absent endpoint must not report port 0")
		// The load-bearing assertion. A non-nil false here would claim
		// someone read the pool and found TLS off.
		assert.Nil(t, ssl, "an absent endpoint must not claim TLS is disabled")
	})

	t.Run("plaintext endpoint reports false", func(t *testing.T) {
		host, port, ssl := poolConnection(&godo.DatabaseConnection{
			Host: "pool.db.example", Port: 25061, SSL: false,
		})
		require.NotNil(t, ssl)
		assert.False(t, *ssl)
		assert.Equal(t, "pool.db.example", *host)
		assert.Equal(t, int64(25061), *port)
	})

	t.Run("tls endpoint reports true", func(t *testing.T) {
		_, _, ssl := poolConnection(&godo.DatabaseConnection{Host: "h", Port: 1, SSL: true})
		require.NotNil(t, ssl)
		assert.True(t, *ssl)
	})
}

// --- struct-tag decoding of the security-relevant fields ---

// TestDatabaseConnectionDecode pins the JSON tags the TLS verdicts are
// read through. A mistyped tag decodes to the zero value, so a cluster
// that enforces TLS would silently report that it does not.
func TestDatabaseConnectionDecode(t *testing.T) {
	var conn godo.DatabaseConnection
	require.NoError(t, json.Unmarshal([]byte(`{
		"host": "db.example",
		"port": 25060,
		"ssl": true,
		"protocol": "postgresql"
	}`), &conn))

	assert.True(t, conn.SSL, "the ssl tag must decode, or a TLS-only cluster reads as plaintext")
	assert.Equal(t, "db.example", conn.Host)
	assert.Equal(t, 25060, conn.Port)
}

// TestDatabasePoolDecode pins the private-connection tag. The private
// endpoint is the one most workloads use, so dropping it would leave the
// TLS verdict for the busiest path unread.
func TestDatabasePoolDecode(t *testing.T) {
	var pool godo.DatabasePool
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "pgbouncer",
		"db": "defaultdb",
		"connection": {"host": "public.example", "port": 25061, "ssl": false},
		"private_connection": {"host": "private.example", "port": 25061, "ssl": true}
	}`), &pool))

	require.NotNil(t, pool.Connection)
	assert.False(t, pool.Connection.SSL)
	require.NotNil(t, pool.PrivateConnection, "the private_connection tag must decode")
	assert.True(t, pool.PrivateConnection.SSL)

	// The reading this PR exists to make possible: a plaintext pooler in
	// front of a TLS private endpoint.
	_, _, publicSSL := poolConnection(pool.Connection)
	_, _, privateSSL := poolConnection(pool.PrivateConnection)
	require.NotNil(t, publicSSL)
	require.NotNil(t, privateSSL)
	assert.False(t, *publicSSL)
	assert.True(t, *privateSSL)
}

// TestKubernetesClusterIsolatedWorkersDecode pins the isolation flag.
func TestKubernetesClusterIsolatedWorkersDecode(t *testing.T) {
	t.Run("present and true", func(t *testing.T) {
		var c godo.KubernetesCluster
		require.NoError(t, json.Unmarshal([]byte(`{"isolated_workers": true}`), &c))
		assert.True(t, c.IsolatedWorkers, "the isolated_workers tag must decode")
	})

	t.Run("present and false", func(t *testing.T) {
		var c godo.KubernetesCluster
		require.NoError(t, json.Unmarshal([]byte(`{"isolated_workers": false}`), &c))
		assert.False(t, c.IsolatedWorkers)
	})
}

// TestAppDomainMinimumTLSVersionDecode pins the per-domain TLS floor.
func TestAppDomainMinimumTLSVersionDecode(t *testing.T) {
	var d godo.AppDomain
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "dom-1",
		"phase": "ACTIVE",
		"spec": {"domain": "www.example.com", "minimum_tls_version": "1.3"}
	}`), &d))

	require.NotNil(t, d.Spec)
	assert.Equal(t, "1.3", d.Spec.MinimumTLSVersion,
		"the minimum_tls_version tag must decode, or a 1.2 domain is indistinguishable from a 1.3 one")
}

// TestVPCMemberDecode pins the membership fields, including that an absent
// join time stays the zero time so timePtr can null it.
func TestVPCMemberDecode(t *testing.T) {
	t.Run("full record", func(t *testing.T) {
		var m godo.VPCMember
		require.NoError(t, json.Unmarshal([]byte(`{
			"urn": "do:droplet:12345",
			"name": "web-1",
			"created_at": "2026-01-02T03:04:05Z"
		}`), &m))
		assert.Equal(t, "do:droplet:12345", m.URN)
		assert.Equal(t, "web-1", m.Name)
		require.NotNil(t, timePtr(m.CreatedAt))
		assert.Equal(t, 2026, m.CreatedAt.Year())
	})

	t.Run("absent join time stays null", func(t *testing.T) {
		var m godo.VPCMember
		require.NoError(t, json.Unmarshal([]byte(`{"urn": "do:droplet:1"}`), &m))
		// Never the zero time, which would report 1 January year 1 as a
		// real join date.
		assert.Nil(t, timePtr(m.CreatedAt))
	})
}

// --- app log destinations ---

// TestLogDestinationTarget covers the derived provider verdict, including
// the self-hosted case, and asserts no credential is returned.
func TestLogDestinationTarget(t *testing.T) {
	t.Run("nil destination", func(t *testing.T) {
		provider, endpoint, os := logDestinationTarget(nil)
		assert.Empty(t, provider)
		assert.Empty(t, endpoint)
		assert.Equal(t, opensearchTarget{}, os)
	})

	t.Run("papertrail", func(t *testing.T) {
		provider, endpoint, _ := logDestinationTarget(&godo.AppLogDestinationSpec{
			Papertrail: &godo.AppLogDestinationSpecPapertrail{Endpoint: "syslog.example:514"},
		})
		assert.Equal(t, "papertrail", provider)
		assert.Equal(t, "syslog.example:514", endpoint)
	})

	t.Run("datadog does not leak the api key", func(t *testing.T) {
		provider, endpoint, _ := logDestinationTarget(&godo.AppLogDestinationSpec{
			Datadog: &godo.AppLogDestinationSpecDataDog{
				Endpoint: "https://http-intake.example",
				ApiKey:   "SECRET-DD-KEY",
			},
		})
		assert.Equal(t, "datadog", provider)
		assert.Equal(t, "https://http-intake.example", endpoint)
		assert.NotContains(t, endpoint, "SECRET-DD-KEY")
	})

	t.Run("logtail does not leak the token", func(t *testing.T) {
		provider, endpoint, _ := logDestinationTarget(&godo.AppLogDestinationSpec{
			Logtail: &godo.AppLogDestinationSpecLogtail{Token: "SECRET-LOGTAIL-TOKEN"},
		})
		assert.Equal(t, "logtail", provider)
		assert.Empty(t, endpoint, "the logtail token must never be surfaced as an endpoint")
	})

	t.Run("opensearch cluster", func(t *testing.T) {
		provider, _, os := logDestinationTarget(&godo.AppLogDestinationSpec{
			OpenSearch: &godo.AppLogDestinationSpecOpenSearch{
				IndexName:   "app-logs",
				ClusterName: "logs-cluster",
				BasicAuth:   &godo.OpenSearchBasicAuth{User: "u", Password: "SECRET"},
			},
		})
		assert.Equal(t, "opensearch", provider)
		assert.Equal(t, "app-logs", os.indexName)
		// A cluster NAME, not an id: the accessor resolves it by name.
		assert.Equal(t, "logs-cluster", os.clusterName)
	})

	t.Run("self-hosted endpoint is custom", func(t *testing.T) {
		provider, endpoint, _ := logDestinationTarget(&godo.AppLogDestinationSpec{
			Endpoint: "https://logs.internal/ingest",
		})
		assert.Equal(t, "custom", provider)
		assert.Equal(t, "https://logs.internal/ingest", endpoint)
	})
}

// TestLogDestinationHeaderKeys asserts header names are reported and their
// values, which routinely carry the destination's API token, are not.
func TestLogDestinationHeaderKeys(t *testing.T) {
	t.Run("nil destination", func(t *testing.T) {
		assert.Empty(t, logDestinationHeaderKeys(nil))
	})

	t.Run("nil and empty entries are skipped", func(t *testing.T) {
		keys := logDestinationHeaderKeys(&godo.AppLogDestinationSpec{
			Headers: []*godo.AppLogDestinationSpecHeader{
				{Key: "Authorization", Value: "Bearer SECRET-TOKEN"},
				nil,
				{Key: "", Value: "orphan"},
				{Key: "X-Tenant", Value: "acme"},
			},
		})
		assert.Equal(t, []any{"Authorization", "X-Tenant"}, keys)
		for _, k := range keys {
			assert.NotContains(t, k, "SECRET-TOKEN")
		}
	})
}

// TestAppLogDestinationsTLSInsecureDecode pins the flag the finding is
// about: application logs shipped with certificate verification off.
func TestAppLogDestinationsTLSInsecureDecode(t *testing.T) {
	var spec godo.AppServiceSpec
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "api",
		"log_destinations": [
			{"name": "siem", "endpoint": "https://logs.internal", "tls_insecure": true}
		]
	}`), &spec))

	require.Len(t, spec.LogDestinations, 1)
	assert.True(t, spec.LogDestinations[0].TLSInsecure,
		"the tls_insecure tag must decode, or an unverified log shipper reads as a verified one")
}

func TestAppLogDestinations(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		assert.Nil(t, appLogDestinations(nil))
	})

	t.Run("nil entries are skipped", func(t *testing.T) {
		got := appLogDestinations(&godo.AppSpec{
			Services: []*godo.AppServiceSpec{{
				Name:            "api",
				LogDestinations: []*godo.AppLogDestinationSpec{nil, {Name: "siem"}},
			}},
		})
		require.Len(t, got, 1)
		assert.Equal(t, "api", got[0].component)
		assert.Equal(t, "siem", got[0].spec.Name)
	})

	t.Run("every component's destinations are collected and attributed", func(t *testing.T) {
		got := appLogDestinations(&godo.AppSpec{
			Services:  []*godo.AppServiceSpec{{Name: "api", LogDestinations: []*godo.AppLogDestinationSpec{{Name: "a"}}}},
			Workers:   []*godo.AppWorkerSpec{{Name: "queue", LogDestinations: []*godo.AppLogDestinationSpec{{Name: "b"}}}},
			Jobs:      []*godo.AppJobSpec{{Name: "migrate", LogDestinations: []*godo.AppLogDestinationSpec{{Name: "c"}}}},
			Functions: []*godo.AppFunctionsSpec{{Name: "fn", LogDestinations: []*godo.AppLogDestinationSpec{{Name: "d"}}}},
		})

		byComponent := map[string]string{}
		for _, d := range got {
			byComponent[d.component] = d.spec.Name
		}
		assert.Equal(t, map[string]string{"api": "a", "queue": "b", "migrate": "c", "fn": "d"}, byComponent)
	})
}

// TestAppComponentLogDestinationsCoverage guards componentLogDestinations
// against SDK drift. A future godo release that adds LogDestinations to a
// component type fails here rather than silently dropping that
// component's log forwarding, which is exactly how an unverified shipper
// would go unnoticed.
func TestAppComponentLogDestinationsCoverage(t *testing.T) {
	spec := &godo.AppSpec{
		Services:    []*godo.AppServiceSpec{{Name: "svc"}},
		Workers:     []*godo.AppWorkerSpec{{Name: "worker"}},
		Jobs:        []*godo.AppJobSpec{{Name: "job"}},
		StaticSites: []*godo.AppStaticSiteSpec{{Name: "site"}},
		Functions:   []*godo.AppFunctionsSpec{{Name: "fn"}},
		Databases:   []*godo.AppDatabaseSpec{{Name: "db"}},
	}

	visited := 0
	err := spec.ForEachAppComponentSpec(func(c godo.AppComponentSpec) error {
		visited++
		field := reflect.ValueOf(c).Elem().FieldByName("LogDestinations")
		if !field.IsValid() {
			assert.Nil(t, componentLogDestinations(c),
				"componentLogDestinations returned destinations for %T, which declares none", c)
			return nil
		}

		field.Set(reflect.ValueOf([]*godo.AppLogDestinationSpec{{Name: "probe"}}))
		assert.Len(t, componentLogDestinations(c), 1,
			"componentLogDestinations does not handle %T, so its log destinations are dropped", c)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 6, visited, "godo changed the set of app component types; revisit componentLogDestinations")
}

// --- registries ---

// TestRegistryArgs pins the registry mapping, including that a registry
// whose storage has never been recomputed keeps a null timestamp.
func TestRegistryArgs(t *testing.T) {
	t.Run("full record", func(t *testing.T) {
		args := registryArgs(&godo.Registry{
			Name:                       "team-registry",
			Region:                     "nyc3",
			StorageUsageBytes:          4096,
			StorageUsageBytesUpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			CreatedAt:                  time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		}, "professional", map[string]any{"tierSlug": "professional"})

		assert.Equal(t, "team-registry", args["name"].Value)
		assert.Equal(t, "nyc3", args["region"].Value)
		assert.Equal(t, int64(4096), args["storageUsageBytes"].Value)
		assert.Equal(t, "professional", args["subscriptionTier"].Value)
		assert.NotNil(t, args["storageUsageBytesUpdatedAt"].Value)
	})

	t.Run("never-recomputed storage timestamp stays null", func(t *testing.T) {
		args := registryArgs(&godo.Registry{Name: "r"}, "", map[string]any{})
		assert.Nil(t, args["storageUsageBytesUpdatedAt"].Value,
			"a registry whose storage was never recomputed must not report the zero time")
	})
}

// TestRegistriesListDecode is the multi-registry regression guard. The
// provider previously read only the legacy singular endpoint, so every
// registry after the first was invisible on a multi-registry account.
func TestRegistriesListDecode(t *testing.T) {
	var root struct {
		Registries []*godo.Registry `json:"registries,omitempty"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"registries": [
		{"name": "primary", "region": "nyc3"},
		{"name": "secondary", "region": "fra1"},
		{"name": "third", "region": "sgp1"}
	]}`), &root))

	require.Len(t, root.Registries, 3, "every registry on the account must decode, not just the first")

	names := make([]string, 0, len(root.Registries))
	for _, r := range root.Registries {
		names = append(names, r.Name)
	}
	assert.Equal(t, []string{"primary", "secondary", "third"}, names)
}

// TestRegistryIDsAreDistinct guards the cache key through the real id()
// method. Every registry used to key on the bare kind, so an account with
// several would collapse them onto one cache entry and the inventory
// would silently report a single registry.
func TestRegistryIDsAreDistinct(t *testing.T) {
	newRegistry := func(name string) *mqlDigitaloceanRegistry {
		r := &mqlDigitaloceanRegistry{}
		r.Name.Data = name
		r.Name.State = plugin.StateIsSet
		return r
	}

	seen := map[string]bool{}
	for _, name := range []string{"primary", "secondary", "third"} {
		id, err := newRegistry(name).id()
		require.NoError(t, err)
		assert.False(t, seen[id], "registry %q reuses a cache key", name)
		assert.Contains(t, id, name, "the cache key must carry the registry name")
		seen[id] = true
	}
	assert.Len(t, seen, 3, "each registry on the account needs its own cache key")

	// The empty sentinel the init returns for an account with no registry
	// keeps the bare kind as its key, because resourceID refuses to build
	// one from an empty name.
	id, err := newRegistry("").id()
	require.NoError(t, err)
	assert.Equal(t, "digitalocean.registry", id)
}

// --- spaces key grants ---

// TestSpacesKeyGrantIDsAreDistinct covers the identity dimensions a grant
// repeats along. A grant repeats per key, and an account-wide grant
// carries no bucket name to distinguish it from another one on the same
// key, so the position stands in.
func TestSpacesKeyGrantIDsAreDistinct(t *testing.T) {
	ids := map[string]bool{}
	add := func(accessKey, bucket, permission string, i int) {
		key := bucket
		if key == "" {
			key = "all/" + string(rune('0'+i))
		}
		id, err := resourceID("digitalocean.spacesKey.grant", accessKey, key, permission)
		require.NoError(t, err)
		assert.False(t, ids[id], "grant %q/%q/%q reuses a cache key", accessKey, bucket, permission)
		ids[id] = true
	}

	// Two keys with an identical grant must not collide.
	add("KEY-A", "backups", "read", 0)
	add("KEY-B", "backups", "read", 0)
	// Two grants on one key differing only by permission must not collide.
	add("KEY-A", "backups", "readwrite", 0)
	// Two account-wide grants on one key must not collide.
	add("KEY-A", "", "read", 0)
	add("KEY-A", "", "readwrite", 1)

	assert.Len(t, ids, 5)
}

// TestSpacesKeyGrantDecode pins the grant tags and the derived
// all-buckets predicate.
func TestSpacesKeyGrantDecode(t *testing.T) {
	var key godo.SpacesKey
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "ci",
		"access_key": "AK123",
		"grants": [
			{"bucket": "backups", "permission": "readwrite"},
			{"bucket": "", "permission": "fullaccess"}
		]
	}`), &key))

	require.Len(t, key.Grants, 2)
	assert.Equal(t, "backups", key.Grants[0].Bucket)
	assert.Equal(t, godo.SpacesKeyReadWrite, key.Grants[0].Permission)

	// An empty bucket scopes the key to every bucket in the account, which
	// is the widest grant a key can hold.
	assert.Empty(t, key.Grants[1].Bucket)
	assert.True(t, key.Grants[1].Bucket == "", "an empty bucket name means all buckets")
}

// --- partner attachment routes ---

func TestRemoteRouteDecode(t *testing.T) {
	var root struct {
		RemoteRoutes []*godo.RemoteRoute `json:"remote_routes"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"remote_routes": [
		{"cidr": "10.10.0.0/16"},
		{"cidr": "0.0.0.0/0"}
	]}`), &root))

	require.Len(t, root.RemoteRoutes, 2)
	assert.Equal(t, "10.10.0.0/16", root.RemoteRoutes[0].Cidr)
	// A default route advertised into a VPC pulls all its egress across the
	// partner link, which is the reading this field exists for.
	assert.Equal(t, "0.0.0.0/0", root.RemoteRoutes[1].Cidr)
}

// --- kubernetes cluster user ---

func TestKubernetesClusterUserDecode(t *testing.T) {
	t.Run("with group bindings", func(t *testing.T) {
		var u godo.KubernetesClusterUser
		require.NoError(t, json.Unmarshal([]byte(`{
			"username": "d0-abc123",
			"groups": ["k8saas:authenticated", "system:masters"]
		}`), &u))
		assert.Equal(t, "d0-abc123", u.Username)
		assert.Equal(t, []string{"k8saas:authenticated", "system:masters"}, u.Groups)
		assert.Len(t, toStringSlice(u.Groups), 2)
	})

	t.Run("no groups decodes to an empty list", func(t *testing.T) {
		var u godo.KubernetesClusterUser
		require.NoError(t, json.Unmarshal([]byte(`{"username": "d0-abc123"}`), &u))
		assert.Nil(t, u.Groups)
		// An identity that was read and belongs to no groups is an empty
		// list. The accessor nulls the field only when nothing was read.
		assert.Empty(t, toStringSlice(u.Groups))
	})
}
