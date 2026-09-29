// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/aidocument"
	"github.com/oracle/oci-go-sdk/v65/ailanguage"
	"github.com/oracle/oci-go-sdk/v65/aispeech"
	"github.com/oracle/oci-go-sdk/v65/aivision"
	"github.com/oracle/oci-go-sdk/v65/apiaccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/apigateway"
	"github.com/oracle/oci-go-sdk/v65/artifacts"
	"github.com/oracle/oci-go-sdk/v65/audit"
	"github.com/oracle/oci-go-sdk/v65/bastion"
	"github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/oracle/oci-go-sdk/v65/containerinstances"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/oracle/oci-go-sdk/v65/datasafe"
	"github.com/oracle/oci-go-sdk/v65/datascience"
	"github.com/oracle/oci-go-sdk/v65/delegateaccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/dns"
	"github.com/oracle/oci-go-sdk/v65/events"
	"github.com/oracle/oci-go-sdk/v65/filestorage"
	"github.com/oracle/oci-go-sdk/v65/functions"
	"github.com/oracle/oci-go-sdk/v65/generativeai"
	"github.com/oracle/oci-go-sdk/v65/generativeaiagent"
	"github.com/oracle/oci-go-sdk/v65/goldengate"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-go-sdk/v65/lockbox"
	"github.com/oracle/oci-go-sdk/v65/logging"
	"github.com/oracle/oci-go-sdk/v65/managedkafka"
	"github.com/oracle/oci-go-sdk/v65/monitoring"
	"github.com/oracle/oci-go-sdk/v65/mysql"
	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"
	"github.com/oracle/oci-go-sdk/v65/nosql"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"github.com/oracle/oci-go-sdk/v65/ons"
	"github.com/oracle/oci-go-sdk/v65/opensearch"
	"github.com/oracle/oci-go-sdk/v65/operatoraccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/osmanagementhub"
	"github.com/oracle/oci-go-sdk/v65/psql"
	"github.com/oracle/oci-go-sdk/v65/queue"
	"github.com/oracle/oci-go-sdk/v65/redis"
	"github.com/oracle/oci-go-sdk/v65/resourcemanager"
	"github.com/oracle/oci-go-sdk/v65/sch"
	"github.com/oracle/oci-go-sdk/v65/securityattribute"
	"github.com/oracle/oci-go-sdk/v65/streaming"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/oracle/oci-go-sdk/v65/vulnerabilityscanning"
	"github.com/oracle/oci-go-sdk/v65/waf"
	"github.com/oracle/oci-go-sdk/v65/zpr"
)

// Every OCI service client this provider talks to is built here, once per
// (service, region), and shared from then on.
//
// Sharing is the point. A lister fans out over every (region, compartment) pair
// in the tenancy, and each job used to construct its own client. Because
// common.NewClientWithConfig gives each client a fresh OciHTTPTransportWrapper,
// and therefore its own connection pool, a fifty-compartment tenancy across
// five regions built 250 clients that shared no TCP connections and repeated
// the TLS handshake for every one. Reusing a client per region is what lets the
// SDK's transport pool do its job.
//
// The safety condition is narrow and worth stating: a shared client must never
// be mutated after it is published. BaseClient.Call takes a value receiver and
// prepareRequest writes nothing back to the client, so concurrent requests are
// safe - but SetRegion, SetCustomClientConfiguration and the HTTPClient swap in
// failFastOnUnreachableRegion all write to the client. Those happen inside the
// build closure below, before the client is ever visible to another goroutine,
// and nothing outside this file touches a client afterwards.

// cachedClient returns the client stored under key, building it on first use.
//
// A build failure is deliberately not cached: an auth or config error that
// resolves (a refreshed instance-principal token, say) should be retried by the
// next caller rather than poisoning the key for the rest of the scan.
//
// Two goroutines racing on a cold key may both build, but LoadOrStore publishes
// only one and both callers receive it, so "one client per key" holds even
// though "one build per key" does not.
//
// The type assertions are checked rather than bare. The compiler already
// guarantees that an accessor's constructor matches its declared return type,
// but nothing checks the key strings, and two accessors for differently-typed
// clients sharing one key would otherwise panic here. A panic inside a lister
// takes down the whole scan, so a shared key is reported as an error against
// the offending key instead.
func cachedClient[T any](c *OciConnection, key string, build func() (T, error)) (T, error) {
	if cached, ok := c.clients.Load(key); ok {
		client, ok := cached.(T)
		if !ok {
			var zero T
			return zero, fmt.Errorf("oci client cache key %q already holds a %T: two accessors share a key", key, cached)
		}
		return client, nil
	}

	client, err := build()
	if err != nil {
		var zero T
		return zero, err
	}

	shared, _ := c.clients.LoadOrStore(key, client)
	typed, ok := shared.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("oci client cache key %q already holds a %T: two accessors share a key", key, shared)
	}
	return typed, nil
}

// ociClient constrains PT to *T for a client type whose region is set through a
// pointer receiver, which is every regional client in the OCI SDK.
type ociClient[T any] interface {
	*T
	SetRegion(region string)
}

// regionalClient builds, points at a region, and caches a standard OCI service
// client. The SDK constructors return the client by value, so the pointer is
// taken here and the region applied to it before anything else can see it.
func regionalClient[T any, PT ociClient[T]](
	c *OciConnection,
	service string,
	region string,
	build func(common.ConfigurationProvider) (T, error),
) (PT, error) {
	return cachedClient(c, service+"/"+region, func() (PT, error) {
		client, err := build(c.config)
		if err != nil {
			return nil, err
		}
		regioned := PT(&client)
		regioned.SetRegion(region)
		return regioned, nil
	})
}

// aiClient builds a regional client for one of the AI services, which are
// deployed in only a subset of regions and need the fail-fast treatment below.
//
// It exists so that adding an AI service cannot quietly skip that step: the
// only way to reach these constructors is through a helper that applies it. The
// base accessor is passed in because common.BaseClient is an embedded field
// rather than an interface method, so there is no way to reach it generically.
func aiClient[T any, PT ociClient[T]](
	c *OciConnection,
	service string,
	region string,
	build func(common.ConfigurationProvider) (T, error),
	base func(PT) *common.BaseClient,
) (PT, error) {
	return cachedClient(c, service+"/"+region, func() (PT, error) {
		client, err := build(c.config)
		if err != nil {
			return nil, err
		}
		regioned := PT(&client)
		regioned.SetRegion(region)
		failFastOnUnreachableRegion(base(regioned))
		return regioned, nil
	})
}

// endpointClient caches a client addressed by an explicit endpoint rather than
// a region. Identity domains and KMS management both publish per-resource
// endpoints, so the endpoint is the cache key.
func endpointClient[T any](c *OciConnection, service, endpoint string, build func() (T, error)) (T, error) {
	return cachedClient(c, service+"/"+endpoint, build)
}

// --- Identity ---------------------------------------------------------------

// IdentityClient talks to IAM in the region the configuration provider names.
// OCI IAM is global within a realm, so unlike the accessors below this one is
// not addressed by region.
// The key is deliberately not "identity/" + something: IdentityClientWithRegion
// builds "identity/<region>", and an empty region would land on the same key
// with a different client type.
func (c *OciConnection) IdentityClient() (identity.IdentityClient, error) {
	return cachedClient(c, "identity-global", func() (identity.IdentityClient, error) {
		return identity.NewIdentityClientWithConfigurationProvider(c.config)
	})
}

func (c *OciConnection) IdentityClientWithRegion(region string) (*identity.IdentityClient, error) {
	return regionalClient(c, "identity", region, identity.NewIdentityClientWithConfigurationProvider)
}

// IdentityDomainsClient builds a client for one identity domain.
//
// Unlike every other client here this one is not addressed by region. Each
// identity domain publishes its own endpoint, returned as the domain's `url`,
// and the SCIM API is served only from there - which is exactly why the legacy
// IAM client cannot reach past the default domain.
func (c *OciConnection) IdentityDomainsClient(endpoint string) (*identitydomains.IdentityDomainsClient, error) {
	if endpoint == "" {
		return nil, errors.New("an identity domain endpoint is required")
	}
	return endpointClient(c, "identitydomains", endpoint, func() (*identitydomains.IdentityDomainsClient, error) {
		client, err := identitydomains.NewIdentityDomainsClientWithConfigurationProvider(c.config, endpoint)
		if err != nil {
			return nil, err
		}
		client.Interceptor = collapseScimAttributeSets
		return &client, nil
	})
}

// collapseScimAttributeSets rewrites a repeated attributeSets query parameter
// into the single comma-delimited value the SCIM service expects.
//
// The SDK tags the parameter collectionFormat:"multi", so asking for two
// attribute sets goes out as `attributeSets=default&attributeSets=request`. The
// identity domains service honors only the first of those and drops the rest,
// and it reports nothing about having done so: the response is a well-formed
// listing that is simply missing every attribute the second set would have
// carried. Asking for the request set alongside the default one therefore
// returned the default set alone, so a user's last login and MFA enrollment
// date came back null, a group's members came back empty, and a sign-on
// policy's rules came back empty - each reading as a fact about the tenancy
// rather than as an unasked-for attribute.
//
// Joining the values with a comma is the form the service documents, and it
// returns the union: a strict superset of the default listing. This runs as a
// request interceptor because the SDK applies it before signing, so the
// rewritten query is the one that gets signed.
func collapseScimAttributeSets(req *http.Request) error {
	if req == nil || req.URL == nil {
		return nil
	}

	query := req.URL.Query()
	sets := query["attributeSets"]
	if len(sets) < 2 {
		return nil
	}

	query.Set("attributeSets", strings.Join(sets, ","))
	req.URL.RawQuery = query.Encode()
	return nil
}

// --- Core (compute, networking, block storage) ------------------------------

func (c *OciConnection) ComputeClient(region string) (*core.ComputeClient, error) {
	return regionalClient(c, "compute", region, core.NewComputeClientWithConfigurationProvider)
}

func (c *OciConnection) NetworkClient(region string) (*core.VirtualNetworkClient, error) {
	return regionalClient(c, "vcn", region, core.NewVirtualNetworkClientWithConfigurationProvider)
}

func (c *OciConnection) BlockstorageClient(region string) (*core.BlockstorageClient, error) {
	return regionalClient(c, "blockstorage", region, core.NewBlockstorageClientWithConfigurationProvider)
}

// --- Storage ----------------------------------------------------------------

func (c *OciConnection) ArtifactsClient(region string) (*artifacts.ArtifactsClient, error) {
	return regionalClient(c, "artifacts", region, artifacts.NewArtifactsClientWithConfigurationProvider)
}

func (c *OciConnection) ObjectStorageClient(region string) (*objectstorage.ObjectStorageClient, error) {
	return regionalClient(c, "objectstorage", region, objectstorage.NewObjectStorageClientWithConfigurationProvider)
}

func (c *OciConnection) FileStorageClient(region string) (*filestorage.FileStorageClient, error) {
	return regionalClient(c, "filestorage", region, filestorage.NewFileStorageClientWithConfigurationProvider)
}

// --- Databases --------------------------------------------------------------

func (c *OciConnection) DatabaseClient(region string) (*database.DatabaseClient, error) {
	return regionalClient(c, "database", region, database.NewDatabaseClientWithConfigurationProvider)
}

func (c *OciConnection) MysqlDbSystemClient(region string) (*mysql.DbSystemClient, error) {
	return regionalClient(c, "mysql", region, mysql.NewDbSystemClientWithConfigurationProvider)
}

func (c *OciConnection) PostgresqlClient(region string) (*psql.PostgresqlClient, error) {
	return regionalClient(c, "postgresql", region, psql.NewPostgresqlClientWithConfigurationProvider)
}

func (c *OciConnection) NosqlClient(region string) (*nosql.NosqlClient, error) {
	return regionalClient(c, "nosql", region, nosql.NewNosqlClientWithConfigurationProvider)
}

func (c *OciConnection) OpensearchClusterClient(region string) (*opensearch.OpensearchClusterClient, error) {
	return regionalClient(c, "opensearch", region, opensearch.NewOpensearchClusterClientWithConfigurationProvider)
}

func (c *OciConnection) RedisClusterClient(region string) (*redis.RedisClusterClient, error) {
	return regionalClient(c, "redis", region, redis.NewRedisClusterClientWithConfigurationProvider)
}

func (c *OciConnection) GoldenGateClient(region string) (*goldengate.GoldenGateClient, error) {
	return regionalClient(c, "goldengate", region, goldengate.NewGoldenGateClientWithConfigurationProvider)
}

func (c *OciConnection) DataSafeClient(region string) (*datasafe.DataSafeClient, error) {
	return regionalClient(c, "datasafe", region, datasafe.NewDataSafeClientWithConfigurationProvider)
}

// --- Messaging --------------------------------------------------------------

func (c *OciConnection) StreamAdminClient(region string) (*streaming.StreamAdminClient, error) {
	return regionalClient(c, "streaming", region, streaming.NewStreamAdminClientWithConfigurationProvider)
}

func (c *OciConnection) QueueAdminClient(region string) (*queue.QueueAdminClient, error) {
	return regionalClient(c, "queue", region, queue.NewQueueAdminClientWithConfigurationProvider)
}

func (c *OciConnection) KafkaClusterClient(region string) (*managedkafka.KafkaClusterClient, error) {
	return regionalClient(c, "kafka", region, managedkafka.NewKafkaClusterClientWithConfigurationProvider)
}

func (c *OciConnection) EventsClient(region string) (*events.EventsClient, error) {
	return regionalClient(c, "events", region, events.NewEventsClientWithConfigurationProvider)
}

func (c *OciConnection) NotificationControlPlaneClient(region string) (*ons.NotificationControlPlaneClient, error) {
	return regionalClient(c, "ons-controlplane", region, ons.NewNotificationControlPlaneClientWithConfigurationProvider)
}

func (c *OciConnection) NotificationDataPlaneClient(region string) (*ons.NotificationDataPlaneClient, error) {
	return regionalClient(c, "ons-dataplane", region, ons.NewNotificationDataPlaneClientWithConfigurationProvider)
}

func (c *OciConnection) ServiceConnectorClient(region string) (*sch.ServiceConnectorClient, error) {
	return regionalClient(c, "sch", region, sch.NewServiceConnectorClientWithConfigurationProvider)
}

// --- Networking edge --------------------------------------------------------

func (c *OciConnection) LoadBalancerClient(region string) (*loadbalancer.LoadBalancerClient, error) {
	return regionalClient(c, "loadbalancer", region, loadbalancer.NewLoadBalancerClientWithConfigurationProvider)
}

func (c *OciConnection) NetworkLoadBalancerClient(region string) (*networkloadbalancer.NetworkLoadBalancerClient, error) {
	return regionalClient(c, "networkloadbalancer", region, networkloadbalancer.NewNetworkLoadBalancerClientWithConfigurationProvider)
}

func (c *OciConnection) NetworkFirewallClient(region string) (*networkfirewall.NetworkFirewallClient, error) {
	return regionalClient(c, "networkfirewall", region, networkfirewall.NewNetworkFirewallClientWithConfigurationProvider)
}

// ZprClient talks to Zero Trust Packet Routing, whose policies and onboarding
// status are tenancy-wide rather than regional.
func (c *OciConnection) ZprClient(region string) (*zpr.ZprClient, error) {
	return regionalClient(c, "zpr", region, zpr.NewZprClientWithConfigurationProvider)
}

// SecurityAttributeClient talks to the security attribute service, which holds
// the namespaces and attribute definitions Zero Trust Packet Routing policies
// are written against.
func (c *OciConnection) SecurityAttributeClient(region string) (*securityattribute.SecurityAttributeClient, error) {
	return regionalClient(c, "securityattribute", region, securityattribute.NewSecurityAttributeClientWithConfigurationProvider)
}

func (c *OciConnection) WafClient(region string) (*waf.WafClient, error) {
	return regionalClient(c, "waf", region, waf.NewWafClientWithConfigurationProvider)
}

func (c *OciConnection) OsManagementHubManagedInstanceClient(region string) (*osmanagementhub.ManagedInstanceClient, error) {
	return regionalClient(c, "osmanagementhub-managedinstance", region, osmanagementhub.NewManagedInstanceClientWithConfigurationProvider)
}

func (c *OciConnection) DnsClient(region string) (*dns.DnsClient, error) {
	return regionalClient(c, "dns", region, dns.NewDnsClientWithConfigurationProvider)
}

func (c *OciConnection) BastionClient(region string) (*bastion.BastionClient, error) {
	return regionalClient(c, "bastion", region, bastion.NewBastionClientWithConfigurationProvider)
}

// --- API gateway ------------------------------------------------------------

func (c *OciConnection) ApiGatewayClient(region string) (*apigateway.ApiGatewayClient, error) {
	return regionalClient(c, "apigateway", region, apigateway.NewApiGatewayClientWithConfigurationProvider)
}

func (c *OciConnection) ApiGatewayGatewayClient(region string) (*apigateway.GatewayClient, error) {
	return regionalClient(c, "apigateway-gateway", region, apigateway.NewGatewayClientWithConfigurationProvider)
}

func (c *OciConnection) ApiGatewayDeploymentClient(region string) (*apigateway.DeploymentClient, error) {
	return regionalClient(c, "apigateway-deployment", region, apigateway.NewDeploymentClientWithConfigurationProvider)
}

// --- Containers and functions ----------------------------------------------

func (c *OciConnection) ContainerEngineClient(region string) (*containerengine.ContainerEngineClient, error) {
	return regionalClient(c, "containerengine", region, containerengine.NewContainerEngineClientWithConfigurationProvider)
}

func (c *OciConnection) ContainerInstanceClient(region string) (*containerinstances.ContainerInstanceClient, error) {
	return regionalClient(c, "containerinstances", region, containerinstances.NewContainerInstanceClientWithConfigurationProvider)
}

func (c *OciConnection) FunctionsManagementClient(region string) (*functions.FunctionsManagementClient, error) {
	return regionalClient(c, "functions", region, functions.NewFunctionsManagementClientWithConfigurationProvider)
}

// --- Keys, secrets, certificates -------------------------------------------

func (c *OciConnection) KmsVaultClient(region string) (*keymanagement.KmsVaultClient, error) {
	return regionalClient(c, "kms-vault", region, keymanagement.NewKmsVaultClientWithConfigurationProvider)
}

// KmsManagementClient talks to one vault's management endpoint. A KMS vault
// serves key operations only from the endpoint it publishes, so like the
// identity-domains client this one is addressed by endpoint rather than region.
func (c *OciConnection) KmsManagementClient(endpoint string) (*keymanagement.KmsManagementClient, error) {
	return endpointClient(c, "kms-management", endpoint, func() (*keymanagement.KmsManagementClient, error) {
		client, err := keymanagement.NewKmsManagementClientWithConfigurationProvider(c.config, endpoint)
		if err != nil {
			return nil, err
		}
		return &client, nil
	})
}

func (c *OciConnection) VaultsClient(region string) (*vault.VaultsClient, error) {
	return regionalClient(c, "vaults", region, vault.NewVaultsClientWithConfigurationProvider)
}

func (c *OciConnection) CertificatesManagementClient(region string) (*certificatesmanagement.CertificatesManagementClient, error) {
	return regionalClient(c, "certificatesmanagement", region, certificatesmanagement.NewCertificatesManagementClientWithConfigurationProvider)
}

// --- Governance and observability ------------------------------------------

func (c *OciConnection) AuditClient(region string) (*audit.AuditClient, error) {
	return regionalClient(c, "audit", region, audit.NewAuditClientWithConfigurationProvider)
}

func (c *OciConnection) CloudGuardClient(region string) (*cloudguard.CloudGuardClient, error) {
	return regionalClient(c, "cloudguard", region, cloudguard.NewCloudGuardClientWithConfigurationProvider)
}

func (c *OciConnection) LoggingClient(region string) (*logging.LoggingManagementClient, error) {
	return regionalClient(c, "logging", region, logging.NewLoggingManagementClientWithConfigurationProvider)
}

func (c *OciConnection) MonitoringClient(region string) (*monitoring.MonitoringClient, error) {
	return regionalClient(c, "monitoring", region, monitoring.NewMonitoringClientWithConfigurationProvider)
}

func (c *OciConnection) ResourceManagerClient(region string) (*resourcemanager.ResourceManagerClient, error) {
	return regionalClient(c, "resourcemanager", region, resourcemanager.NewResourceManagerClientWithConfigurationProvider)
}

func (c *OciConnection) VulnerabilityScanningClient(region string) (*vulnerabilityscanning.VulnerabilityScanningClient, error) {
	return regionalClient(c, "vulnerabilityscanning", region, vulnerabilityscanning.NewVulnerabilityScanningClientWithConfigurationProvider)
}

// --- Access by parties outside the tenancy ----------------------------------
//
// Four services answering one question, and each publishes its own client
// rather than one per package - operator access control alone has four. The
// cache key is the service string, and it is not compiler-checked, so each of
// these needs a distinct one even though several build from the same package.

func (c *OciConnection) OperatorControlClient(region string) (*operatoraccesscontrol.OperatorControlClient, error) {
	return regionalClient(c, "operatoraccesscontrol-control", region,
		operatoraccesscontrol.NewOperatorControlClientWithConfigurationProvider)
}

func (c *OciConnection) OperatorControlAssignmentClient(region string) (*operatoraccesscontrol.OperatorControlAssignmentClient, error) {
	return regionalClient(c, "operatoraccesscontrol-assignment", region,
		operatoraccesscontrol.NewOperatorControlAssignmentClientWithConfigurationProvider)
}

func (c *OciConnection) OperatorAccessRequestsClient(region string) (*operatoraccesscontrol.AccessRequestsClient, error) {
	return regionalClient(c, "operatoraccesscontrol-accessrequests", region,
		operatoraccesscontrol.NewAccessRequestsClientWithConfigurationProvider)
}

func (c *OciConnection) OperatorActionsClient(region string) (*operatoraccesscontrol.OperatorActionsClient, error) {
	return regionalClient(c, "operatoraccesscontrol-actions", region,
		operatoraccesscontrol.NewOperatorActionsClientWithConfigurationProvider)
}

func (c *OciConnection) DelegateAccessControlClient(region string) (*delegateaccesscontrol.DelegateAccessControlClient, error) {
	return regionalClient(c, "delegateaccesscontrol", region,
		delegateaccesscontrol.NewDelegateAccessControlClientWithConfigurationProvider)
}

func (c *OciConnection) PrivilegedApiControlClient(region string) (*apiaccesscontrol.PrivilegedApiControlClient, error) {
	return regionalClient(c, "apiaccesscontrol-control", region,
		apiaccesscontrol.NewPrivilegedApiControlClientWithConfigurationProvider)
}

func (c *OciConnection) PrivilegedApiRequestsClient(region string) (*apiaccesscontrol.PrivilegedApiRequestsClient, error) {
	return regionalClient(c, "apiaccesscontrol-requests", region,
		apiaccesscontrol.NewPrivilegedApiRequestsClientWithConfigurationProvider)
}

func (c *OciConnection) LockboxClient(region string) (*lockbox.LockboxClient, error) {
	return regionalClient(c, "lockbox", region, lockbox.NewLockboxClientWithConfigurationProvider)
}

// --- AI services ------------------------------------------------------------
//
// These go through aiClient so that failFastOnUnreachableRegion is applied to
// every one of them. See the comment on that function for why.

func (c *OciConnection) GenerativeAiClient(region string) (*generativeai.GenerativeAiClient, error) {
	return aiClient(c, "generativeai", region, generativeai.NewGenerativeAiClientWithConfigurationProvider,
		func(p *generativeai.GenerativeAiClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) GenerativeAiAgentClient(region string) (*generativeaiagent.GenerativeAiAgentClient, error) {
	return aiClient(c, "generativeaiagent", region, generativeaiagent.NewGenerativeAiAgentClientWithConfigurationProvider,
		func(p *generativeaiagent.GenerativeAiAgentClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) DataScienceClient(region string) (*datascience.DataScienceClient, error) {
	return aiClient(c, "datascience", region, datascience.NewDataScienceClientWithConfigurationProvider,
		func(p *datascience.DataScienceClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) AILanguageClient(region string) (*ailanguage.AIServiceLanguageClient, error) {
	return aiClient(c, "ailanguage", region, ailanguage.NewAIServiceLanguageClientWithConfigurationProvider,
		func(p *ailanguage.AIServiceLanguageClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) AIVisionClient(region string) (*aivision.AIServiceVisionClient, error) {
	return aiClient(c, "aivision", region, aivision.NewAIServiceVisionClientWithConfigurationProvider,
		func(p *aivision.AIServiceVisionClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) AISpeechClient(region string) (*aispeech.AIServiceSpeechClient, error) {
	return aiClient(c, "aispeech", region, aispeech.NewAIServiceSpeechClientWithConfigurationProvider,
		func(p *aispeech.AIServiceSpeechClient) *common.BaseClient { return &p.BaseClient })
}

func (c *OciConnection) AIDocumentClient(region string) (*aidocument.AIServiceDocumentClient, error) {
	return aiClient(c, "aidocument", region, aidocument.NewAIServiceDocumentClientWithConfigurationProvider,
		func(p *aidocument.AIServiceDocumentClient) *common.BaseClient { return &p.BaseClient })
}

// failFastOnUnreachableRegion caps the per-request timeout and narrows the
// retry policy on a region-limited AI client. Several AI services publish a
// wildcard DNS record in regions where they are not deployed, so calls there
// resolve but the connection times out; without this the SDK would retry the
// timeout ~8 times with backoff and hang for minutes. With it, unavailable
// regions fail fast and are skipped (see ociRegionServiceUnavailable).
//
// The client is cloned rather than replaced. Replacing it dropped the SDK's
// OciHTTPTransportWrapper, and with it the TLS configuration built from
// OCI_DEFAULT_CERTS_PATH and the client-certificate environment variables - so
// in a custom realm or behind a TLS-inspecting proxy every AI call failed with
// an unknown-authority error while every other service worked.
//
// Retries are bounded rather than disabled: NoRetryPolicy meant a single 429
// from OCI's throttling failed the whole collection, and these calls fan out
// across regions and pages, which is exactly the shape that gets throttled.
func failFastOnUnreachableRegion(bc *common.BaseClient) {
	if hc, ok := bc.HTTPClient.(*http.Client); ok {
		clone := *hc
		clone.Timeout = unreachableRegionTimeout
		bc.HTTPClient = &clone
	} else {
		bc.HTTPClient = &http.Client{Timeout: unreachableRegionTimeout}
	}
	retry := common.NewRetryPolicyWithOptions(
		common.WithMaximumNumberAttempts(2),
		common.WithShouldRetryOperation(common.DefaultShouldRetryOperation),
	)
	bc.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &retry})
}

// unreachableRegionTimeout bounds a single request to a region-limited AI
// service. It has to stay well above a healthy region's slowest page - a
// timeout is classified as an absent endpoint and silently skips the region -
// while staying short enough that an undeployed wildcard-DNS region does not
// stall the scan.
const unreachableRegionTimeout = 45 * time.Second
