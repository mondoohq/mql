// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// errFailedBuild stands in for whatever a client constructor can fail with.
var errFailedBuild = errors.New("simulated build failure")

// endpointer is the one thing every OCI service client has in common: an
// Endpoint() promoted from the embedded common.BaseClient. It is what lets a
// single table cover fifty differently-typed accessors.
type endpointer interface {
	Endpoint() string
}

const (
	testTenancyOCID = "ocid1.tenancy.oc1..aaaaaaaatestonly"
	testUserOCID    = "ocid1.user.oc1..aaaaaaaatestonly"

	// Two real region names, deliberately in different realms' geographies, so
	// a client that ignored the requested region produces a visible collision.
	regionA = "us-ashburn-1"
	regionB = "eu-frankfurt-1"
)

// testConnection builds a connection backed by a freshly generated key. No
// request is ever sent - the SDK needs a parseable key to construct a signer,
// and generating one keeps the test free of fixtures and of anything that looks
// like a real credential.
func testConnection(t *testing.T) *OciConnection {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a test key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return &OciConnection{
		config: common.NewRawConfigurationProvider(
			testTenancyOCID, testUserOCID, regionA,
			"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
			string(keyPEM), nil,
		),
		// tenancyOcid is read by TenantID(); no client construction needs it.
		tenancyOcid: testTenancyOCID,
	}
}

// errorType and endpointerType support clientAccessorNames below.
var (
	errorType      = reflect.TypeFor[error]()
	endpointerType = reflect.TypeFor[endpointer]()
)

// clientAccessorNames reflects over OciConnection to find every method that
// hands back an OCI service client, identified structurally: it returns
// (something with an Endpoint(), error).
//
// Reflection rather than a hand-kept list, because the whole value of the
// coverage test below is that it notices an accessor a human forgot.
func clientAccessorNames(t *testing.T) []string {
	t.Helper()

	typ := reflect.TypeFor[*OciConnection]()
	names := make([]string, 0, typ.NumMethod())
	for method := range typ.Methods() {
		signature := method.Type
		if signature.NumOut() != 2 || signature.Out(1) != errorType {
			continue
		}
		returned := signature.Out(0)
		if returned.Implements(endpointerType) || reflect.PointerTo(returned).Implements(endpointerType) {
			names = append(names, method.Name)
		}
	}
	return names
}

// regionalAccessors is every client accessor addressed by region.
//
// The point of enumerating all of them is that clients.go builds each one
// through a shared generic helper. A mis-wired service string or constructor
// would compile perfectly and only show up as requests aimed at the wrong
// service or the wrong region, which no other test in this provider would
// catch. Keep this list in sync with clients.go; a new regional accessor
// belongs here.
var regionalAccessors = map[string]func(*OciConnection, string) (endpointer, error){
	// Identity
	"IdentityClientWithRegion": func(c *OciConnection, r string) (endpointer, error) { return c.IdentityClientWithRegion(r) },

	// Core
	"ComputeClient":      func(c *OciConnection, r string) (endpointer, error) { return c.ComputeClient(r) },
	"NetworkClient":      func(c *OciConnection, r string) (endpointer, error) { return c.NetworkClient(r) },
	"BlockstorageClient": func(c *OciConnection, r string) (endpointer, error) { return c.BlockstorageClient(r) },

	// Storage
	"ArtifactsClient":     func(c *OciConnection, r string) (endpointer, error) { return c.ArtifactsClient(r) },
	"ObjectStorageClient": func(c *OciConnection, r string) (endpointer, error) { return c.ObjectStorageClient(r) },
	"FileStorageClient":   func(c *OciConnection, r string) (endpointer, error) { return c.FileStorageClient(r) },

	// Databases
	"DatabaseClient":          func(c *OciConnection, r string) (endpointer, error) { return c.DatabaseClient(r) },
	"MysqlDbSystemClient":     func(c *OciConnection, r string) (endpointer, error) { return c.MysqlDbSystemClient(r) },
	"PostgresqlClient":        func(c *OciConnection, r string) (endpointer, error) { return c.PostgresqlClient(r) },
	"NosqlClient":             func(c *OciConnection, r string) (endpointer, error) { return c.NosqlClient(r) },
	"OpensearchClusterClient": func(c *OciConnection, r string) (endpointer, error) { return c.OpensearchClusterClient(r) },
	"RedisClusterClient":      func(c *OciConnection, r string) (endpointer, error) { return c.RedisClusterClient(r) },
	"GoldenGateClient":        func(c *OciConnection, r string) (endpointer, error) { return c.GoldenGateClient(r) },
	"DataSafeClient":          func(c *OciConnection, r string) (endpointer, error) { return c.DataSafeClient(r) },

	// Messaging
	"StreamAdminClient":              func(c *OciConnection, r string) (endpointer, error) { return c.StreamAdminClient(r) },
	"QueueAdminClient":               func(c *OciConnection, r string) (endpointer, error) { return c.QueueAdminClient(r) },
	"KafkaClusterClient":             func(c *OciConnection, r string) (endpointer, error) { return c.KafkaClusterClient(r) },
	"EventsClient":                   func(c *OciConnection, r string) (endpointer, error) { return c.EventsClient(r) },
	"NotificationControlPlaneClient": func(c *OciConnection, r string) (endpointer, error) { return c.NotificationControlPlaneClient(r) },
	"NotificationDataPlaneClient":    func(c *OciConnection, r string) (endpointer, error) { return c.NotificationDataPlaneClient(r) },
	"ServiceConnectorClient":         func(c *OciConnection, r string) (endpointer, error) { return c.ServiceConnectorClient(r) },

	// Networking edge
	"LoadBalancerClient":        func(c *OciConnection, r string) (endpointer, error) { return c.LoadBalancerClient(r) },
	"NetworkLoadBalancerClient": func(c *OciConnection, r string) (endpointer, error) { return c.NetworkLoadBalancerClient(r) },
	"NetworkFirewallClient":     func(c *OciConnection, r string) (endpointer, error) { return c.NetworkFirewallClient(r) },
	"WafClient":                 func(c *OciConnection, r string) (endpointer, error) { return c.WafClient(r) },
	"DnsClient":                 func(c *OciConnection, r string) (endpointer, error) { return c.DnsClient(r) },
	"BastionClient":             func(c *OciConnection, r string) (endpointer, error) { return c.BastionClient(r) },

	// Operating system management
	"OsManagementHubManagedInstanceClient": func(c *OciConnection, r string) (endpointer, error) {
		return c.OsManagementHubManagedInstanceClient(r)
	},

	// Zero Trust Packet Routing and the security attributes its policies name.
	// Both answer tenancy-wide, but they are built per region like everything
	// else so a caller already inside a regional fan-out does not need a second
	// way to reach them.
	"ZprClient":               func(c *OciConnection, r string) (endpointer, error) { return c.ZprClient(r) },
	"SecurityAttributeClient": func(c *OciConnection, r string) (endpointer, error) { return c.SecurityAttributeClient(r) },

	// API gateway
	"ApiGatewayClient":           func(c *OciConnection, r string) (endpointer, error) { return c.ApiGatewayClient(r) },
	"ApiGatewayGatewayClient":    func(c *OciConnection, r string) (endpointer, error) { return c.ApiGatewayGatewayClient(r) },
	"ApiGatewayDeploymentClient": func(c *OciConnection, r string) (endpointer, error) { return c.ApiGatewayDeploymentClient(r) },

	// Containers and functions
	"ContainerEngineClient":     func(c *OciConnection, r string) (endpointer, error) { return c.ContainerEngineClient(r) },
	"ContainerInstanceClient":   func(c *OciConnection, r string) (endpointer, error) { return c.ContainerInstanceClient(r) },
	"FunctionsManagementClient": func(c *OciConnection, r string) (endpointer, error) { return c.FunctionsManagementClient(r) },

	// Keys, secrets, certificates
	"KmsVaultClient":               func(c *OciConnection, r string) (endpointer, error) { return c.KmsVaultClient(r) },
	"VaultsClient":                 func(c *OciConnection, r string) (endpointer, error) { return c.VaultsClient(r) },
	"CertificatesManagementClient": func(c *OciConnection, r string) (endpointer, error) { return c.CertificatesManagementClient(r) },

	// Governance and observability
	"AuditClient":                 func(c *OciConnection, r string) (endpointer, error) { return c.AuditClient(r) },
	"CloudGuardClient":            func(c *OciConnection, r string) (endpointer, error) { return c.CloudGuardClient(r) },
	"LoggingClient":               func(c *OciConnection, r string) (endpointer, error) { return c.LoggingClient(r) },
	"MonitoringClient":            func(c *OciConnection, r string) (endpointer, error) { return c.MonitoringClient(r) },
	"ResourceManagerClient":       func(c *OciConnection, r string) (endpointer, error) { return c.ResourceManagerClient(r) },
	"VulnerabilityScanningClient": func(c *OciConnection, r string) (endpointer, error) { return c.VulnerabilityScanningClient(r) },

	// Access by parties outside the tenancy
	"OperatorControlClient":           func(c *OciConnection, r string) (endpointer, error) { return c.OperatorControlClient(r) },
	"OperatorControlAssignmentClient": func(c *OciConnection, r string) (endpointer, error) { return c.OperatorControlAssignmentClient(r) },
	"OperatorAccessRequestsClient":    func(c *OciConnection, r string) (endpointer, error) { return c.OperatorAccessRequestsClient(r) },
	"OperatorActionsClient":           func(c *OciConnection, r string) (endpointer, error) { return c.OperatorActionsClient(r) },
	"DelegateAccessControlClient":     func(c *OciConnection, r string) (endpointer, error) { return c.DelegateAccessControlClient(r) },
	"PrivilegedApiControlClient":      func(c *OciConnection, r string) (endpointer, error) { return c.PrivilegedApiControlClient(r) },
	"PrivilegedApiRequestsClient":     func(c *OciConnection, r string) (endpointer, error) { return c.PrivilegedApiRequestsClient(r) },
	"LockboxClient":                   func(c *OciConnection, r string) (endpointer, error) { return c.LockboxClient(r) },

	// AI services
	"GenerativeAiClient":      func(c *OciConnection, r string) (endpointer, error) { return c.GenerativeAiClient(r) },
	"GenerativeAiAgentClient": func(c *OciConnection, r string) (endpointer, error) { return c.GenerativeAiAgentClient(r) },
	"DataScienceClient":       func(c *OciConnection, r string) (endpointer, error) { return c.DataScienceClient(r) },
	"AILanguageClient":        func(c *OciConnection, r string) (endpointer, error) { return c.AILanguageClient(r) },
	"AIVisionClient":          func(c *OciConnection, r string) (endpointer, error) { return c.AIVisionClient(r) },
	"AISpeechClient":          func(c *OciConnection, r string) (endpointer, error) { return c.AISpeechClient(r) },
	"AIDocumentClient":        func(c *OciConnection, r string) (endpointer, error) { return c.AIDocumentClient(r) },
}

// TestRegionalClientsTargetTheRequestedRegion is the proof that collapsing ~50
// hand-written accessors onto one generic helper did not mis-wire any of them.
//
// Each accessor has to satisfy three things at once: the endpoint names the
// region it was asked for, two regions do not share a client, and the same
// region hands back the same client. The first catches a dropped SetRegion, the
// second a cache key missing its region, the third a cache key that is not
// shared at all.
func TestRegionalClientsTargetTheRequestedRegion(t *testing.T) {
	for name, accessor := range regionalAccessors {
		t.Run(name, func(t *testing.T) {
			conn := testConnection(t)

			a, err := accessor(conn, regionA)
			if err != nil {
				t.Fatalf("%s(%q): %v", name, regionA, err)
			}
			b, err := accessor(conn, regionB)
			if err != nil {
				t.Fatalf("%s(%q): %v", name, regionB, err)
			}

			endpointA, endpointB := a.Endpoint(), b.Endpoint()

			if !strings.Contains(endpointA, regionA) {
				t.Errorf("%s(%q) endpoint %q does not name the region", name, regionA, endpointA)
			}
			if !strings.Contains(endpointB, regionB) {
				t.Errorf("%s(%q) endpoint %q does not name the region", name, regionB, endpointB)
			}
			if endpointA == endpointB {
				t.Errorf("%s: both regions resolved to the same endpoint %q", name, endpointA)
			}
			if a == b {
				t.Errorf("%s: both regions returned the same cached client; the cache key is missing the region", name)
			}

			// Same region, second call: must be the identical client, or the
			// fan-out is still paying for a new connection pool per job.
			again, err := accessor(conn, regionA)
			if err != nil {
				t.Fatalf("%s(%q) on the second call: %v", name, regionA, err)
			}
			if again != a {
				t.Errorf("%s(%q) built a second client instead of reusing the cached one", name, regionA)
			}
		})
	}
}

// TestEveryRegionalAccessorIsCovered fails when clients.go grows a regional
// accessor that regionalAccessors above does not list, so the exhaustiveness
// this file claims stays true instead of decaying silently.
func TestEveryRegionalAccessorIsCovered(t *testing.T) {
	// Accessors that are deliberately not region-addressed.
	exempt := map[string]string{
		"IdentityClient":        "global within a realm; uses the config provider's region",
		"IdentityDomainsClient": "addressed by the domain's own endpoint",
		"KmsManagementClient":   "addressed by the vault's management endpoint",
	}

	discovered := clientAccessorNames(t)

	// Without this the test passes vacuously if the reflection above ever stops
	// matching - a renamed Endpoint(), a changed return shape - and the
	// exhaustiveness claim would quietly become worthless.
	if want := len(regionalAccessors) + len(exempt); len(discovered) != want {
		t.Errorf("reflection found %d client accessors, expected %d (%d regional + %d exempt); "+
			"if an accessor was added or removed, update regionalAccessors or exempt",
			len(discovered), want, len(regionalAccessors), len(exempt))
	}

	for _, name := range discovered {
		if _, ok := regionalAccessors[name]; ok {
			continue
		}
		if _, ok := exempt[name]; ok {
			continue
		}
		t.Errorf("%s is declared on OciConnection but is neither in regionalAccessors nor exempt; "+
			"add it to one of the two so the wiring stays covered", name)
	}
}

// TestClientCacheKeysDoNotCollide is the check the compiler cannot make.
//
// An accessor's constructor is type-checked against its declared return type, so
// a wrong constructor will not build. The cache key is just a string: two
// accessors for differently-typed clients that happen to share one - the three
// apigateway clients, the two ons planes, the two keymanagement clients - would
// hand the second caller the first caller's client. Exercising every accessor
// against one connection and counting the distinct keys catches that.
func TestClientCacheKeysDoNotCollide(t *testing.T) {
	conn := testConnection(t)

	for name, accessor := range regionalAccessors {
		if _, err := accessor(conn, regionA); err != nil {
			t.Fatalf("%s(%q): %v", name, regionA, err)
		}
	}
	if _, err := conn.IdentityClient(); err != nil {
		t.Fatalf("IdentityClient(): %v", err)
	}

	keys := 0
	conn.clients.Range(func(_, _ any) bool {
		keys++
		return true
	})

	// One key per accessor. A collision shows up as a shortfall, and because
	// cachedClient reports a type mismatch as an error rather than panicking,
	// the loop above would already have failed for a same-region collision.
	if want := len(regionalAccessors) + 1; keys != want {
		t.Errorf("cached %d clients for %d accessors; two accessors are sharing a cache key", keys, want)
	}
}

// TestIdentityClientIsShared covers the one accessor that returns its client by
// value. Callers get copies, but they must be copies of a single underlying
// client rather than a fresh construction per call.
func TestIdentityClientIsShared(t *testing.T) {
	conn := testConnection(t)

	first, err := conn.IdentityClient()
	if err != nil {
		t.Fatalf("IdentityClient(): %v", err)
	}
	second, err := conn.IdentityClient()
	if err != nil {
		t.Fatalf("IdentityClient() on the second call: %v", err)
	}

	// The copies share the BaseClient's HTTPClient pointer, which is the thing
	// that owns the connection pool.
	if first.HTTPClient != second.HTTPClient {
		t.Error("IdentityClient() built a second client; the two copies do not share a transport")
	}
}

// TestEndpointAddressedClientsKeyOnTheEndpoint checks the two clients that are
// addressed by endpoint rather than region: distinct endpoints must not collide
// in the shared cache.
func TestEndpointAddressedClientsKeyOnTheEndpoint(t *testing.T) {
	conn := testConnection(t)

	const (
		domainA = "https://idcs-aaaa.identity.oraclecloud.com"
		domainB = "https://idcs-bbbb.identity.oraclecloud.com"
	)

	a, err := conn.IdentityDomainsClient(domainA)
	if err != nil {
		t.Fatalf("IdentityDomainsClient(%q): %v", domainA, err)
	}
	b, err := conn.IdentityDomainsClient(domainB)
	if err != nil {
		t.Fatalf("IdentityDomainsClient(%q): %v", domainB, err)
	}
	if a == b {
		t.Error("two identity domains shared one client; the cache key is missing the endpoint")
	}
	again, err := conn.IdentityDomainsClient(domainA)
	if err != nil {
		t.Fatalf("IdentityDomainsClient(%q) on the second call: %v", domainA, err)
	}
	if again != a {
		t.Error("IdentityDomainsClient did not reuse the cached client for a repeated endpoint")
	}

	vaultA, err := conn.KmsManagementClient("https://aaaa-management.kms.us-ashburn-1.oci.oraclecloud.com")
	if err != nil {
		t.Fatalf("KmsManagementClient: %v", err)
	}
	vaultB, err := conn.KmsManagementClient("https://bbbb-management.kms.us-ashburn-1.oci.oraclecloud.com")
	if err != nil {
		t.Fatalf("KmsManagementClient: %v", err)
	}
	if vaultA == vaultB {
		t.Error("two KMS vaults shared one management client; the cache key is missing the endpoint")
	}
}

// TestIdentityDomainsClientRejectsAnEmptyEndpoint pins the guard that keeps an
// empty endpoint from reaching the SDK, and confirms the failure is not cached
// under the empty key.
func TestIdentityDomainsClientRejectsAnEmptyEndpoint(t *testing.T) {
	conn := testConnection(t)

	if _, err := conn.IdentityDomainsClient(""); err == nil {
		t.Fatal("expected an error for an empty identity domain endpoint")
	}
	if _, cached := conn.clients.Load("identitydomains/"); cached {
		t.Error("a rejected endpoint was cached; a later valid call would receive the failure")
	}
}

// TestCachedClientDoesNotCacheFailures makes the retry-after-failure property
// explicit: a build error must leave the key empty so a transient auth or
// config failure does not poison it for the rest of the scan.
func TestCachedClientDoesNotCacheFailures(t *testing.T) {
	conn := testConnection(t)

	calls := 0
	failing := func() (*int, error) {
		calls++
		return nil, errFailedBuild
	}

	if _, err := cachedClient(conn, "test/failing", failing); err == nil {
		t.Fatal("expected the build error to surface")
	}
	if _, err := cachedClient(conn, "test/failing", failing); err == nil {
		t.Fatal("expected the build error to surface on the second call too")
	}
	if calls != 2 {
		t.Errorf("build ran %d times; a failure must not be cached", calls)
	}

	// Once it succeeds, the result is cached and the build stops running.
	value := 42
	succeeding := func() (*int, error) {
		calls++
		return &value, nil
	}
	first, err := cachedClient(conn, "test/failing", succeeding)
	if err != nil {
		t.Fatalf("unexpected error after recovery: %v", err)
	}
	second, err := cachedClient(conn, "test/failing", succeeding)
	if err != nil {
		t.Fatalf("unexpected error on the cached read: %v", err)
	}
	if first != second {
		t.Error("a successful build was not cached")
	}
	if calls != 3 {
		t.Errorf("build ran %d times; the successful result should have been reused", calls)
	}
}

// TestCachedClientIsSafeUnderConcurrency is the property the fan-out depends on.
// Run under -race it also covers the sync.Map access itself; without the shared
// cache every one of these callers would have built its own client.
func TestCachedClientIsSafeUnderConcurrency(t *testing.T) {
	conn := testConnection(t)

	const goroutines = 32
	results := make([]*int, goroutines)
	value := 7

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() {
			got, err := cachedClient(conn, "test/concurrent", func() (*int, error) {
				// A fresh allocation per build, so a second published client is
				// detectable as a different pointer.
				v := value
				return &v, nil
			})
			if err != nil {
				t.Errorf("cachedClient: %v", err)
				return
			}
			results[i] = got
		})
	}
	wg.Wait()

	for i, got := range results {
		if got == nil {
			t.Fatalf("goroutine %d got no client", i)
		}
		if got != results[0] {
			t.Fatalf("goroutine %d received a different client; exactly one must be published", i)
		}
	}
}

// TestRegionalClientsAreIndependentAcrossConnections guards against the cache
// accidentally becoming process-wide. Two tenancies scanned in one run must not
// share clients, because they do not share credentials.
func TestRegionalClientsAreIndependentAcrossConnections(t *testing.T) {
	first := testConnection(t)
	second := testConnection(t)

	a, err := first.ComputeClient(regionA)
	if err != nil {
		t.Fatalf("ComputeClient on the first connection: %v", err)
	}
	b, err := second.ComputeClient(regionA)
	if err != nil {
		t.Fatalf("ComputeClient on the second connection: %v", err)
	}
	if a == b {
		t.Error("two connections shared a client; the cache must be per-connection")
	}
}
