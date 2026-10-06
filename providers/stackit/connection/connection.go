// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stackitcloud/stackit-sdk-go/core/config"
	alb "github.com/stackitcloud/stackit-sdk-go/services/alb/v2api"
	albwaf "github.com/stackitcloud/stackit-sdk-go/services/albwaf/v1betaapi"
	authorization "github.com/stackitcloud/stackit-sdk-go/services/authorization/v2api"
	cdn "github.com/stackitcloud/stackit-sdk-go/services/cdn/v1api"
	certificates "github.com/stackitcloud/stackit-sdk-go/services/certificates/v2api"
	dns "github.com/stackitcloud/stackit-sdk-go/services/dns/v1api"
	git "github.com/stackitcloud/stackit-sdk-go/services/git/v1betaapi"
	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
	loadbalancer "github.com/stackitcloud/stackit-sdk-go/services/loadbalancer/v2api"
	logme "github.com/stackitcloud/stackit-sdk-go/services/logme/v2api"
	logs "github.com/stackitcloud/stackit-sdk-go/services/logs/v1api"
	mariadb "github.com/stackitcloud/stackit-sdk-go/services/mariadb/v2api"
	modelserving "github.com/stackitcloud/stackit-sdk-go/services/modelserving/v1api"
	mongodbflex "github.com/stackitcloud/stackit-sdk-go/services/mongodbflex/v2api"
	objectstorage "github.com/stackitcloud/stackit-sdk-go/services/objectstorage/v2api"
	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	opensearch "github.com/stackitcloud/stackit-sdk-go/services/opensearch/v2api"
	postgresflex "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v2api"
	postgresflexv3 "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v3api"
	rabbitmq "github.com/stackitcloud/stackit-sdk-go/services/rabbitmq/v2api"
	redis "github.com/stackitcloud/stackit-sdk-go/services/redis/v2api"
	resourcemanager "github.com/stackitcloud/stackit-sdk-go/services/resourcemanager/v0api"
	secretsmanager "github.com/stackitcloud/stackit-sdk-go/services/secretsmanager/v1api"
	serverbackup "github.com/stackitcloud/stackit-sdk-go/services/serverbackup/v2api"
	serverupdate "github.com/stackitcloud/stackit-sdk-go/services/serverupdate/v2api"
	serviceaccount "github.com/stackitcloud/stackit-sdk-go/services/serviceaccount/v2api"
	serviceenablement "github.com/stackitcloud/stackit-sdk-go/services/serviceenablement/v2api"
	sfs "github.com/stackitcloud/stackit-sdk-go/services/sfs/v1api"
	ske "github.com/stackitcloud/stackit-sdk-go/services/ske/v2api"
	sqlserverflex "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v2api"
	sqlserverflexv3 "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v3api"
	telemetrylink "github.com/stackitcloud/stackit-sdk-go/services/telemetrylink/v1betaapi"
	telemetryrouter "github.com/stackitcloud/stackit-sdk-go/services/telemetryrouter/v1betaapi"
	valkey "github.com/stackitcloud/stackit-sdk-go/services/valkey/v2api"
	vpn "github.com/stackitcloud/stackit-sdk-go/services/vpn/v1api"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

var PlatformIdStackitProject = "//platformid.api.mondoo.app/runtime/stackit/project/"

const DefaultRegion = "eu01"

type StackitConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	projectID string
	region    string

	// project metadata captured during Verify so the provider can enrich the
	// detected asset (real name + labels + parent) the way the gcp and aws
	// providers do, without issuing a second resource-manager call.
	projectName   string
	projectParent string
	projectLabels map[string]string

	// configOpts includes WithRegion(region) — use for region-scoped services
	// (iaas, ske, objectstorage, loadbalancer, postgres-flex, mongodb-flex).
	configOpts []config.ConfigurationOption
	// configOptsGlobal omits WithRegion — use for global / project-only
	// services (resource-manager, dns, the rest of DBaaS, secrets-manager,
	// observability, service-account). Those APIs reject WithRegion.
	configOptsGlobal []config.ConfigurationOption

	// routing tables reachable from the project's network areas, resolved once
	// per connection because every network in a scan asks for the same walk.
	routingTablesOnce sync.Once
	routingTables     map[string]iaas.RoutingTable
	routingTablesErr  error

	securityGroupsOnce sync.Once
	securityGroups     map[string]iaas.SecurityGroup
	securityGroupsErr  error

	cdnOnce                 sync.Once
	cdnClient               *cdn.APIClient
	cdnErr                  error
	gitOnce                 sync.Once
	gitClient               *git.APIClient
	gitErr                  error
	logsOnce                sync.Once
	logsClient              *logs.APIClient
	logsErr                 error
	valkeyOnce              sync.Once
	valkeyClient            *valkey.APIClient
	valkeyErr               error
	serviceEnablementOnce   sync.Once
	serviceEnablementClient *serviceenablement.APIClient
	serviceEnablementErr    error
	postgresFlexV3Once      sync.Once
	postgresFlexV3Client    *postgresflexv3.APIClient
	postgresFlexV3Err       error
	sqlServerFlexV3Once     sync.Once
	sqlServerFlexV3Client   *sqlserverflexv3.APIClient
	sqlServerFlexV3Err      error

	iaasOnce             sync.Once
	iaasClient           *iaas.APIClient
	iaasErr              error
	skeOnce              sync.Once
	skeClient            *ske.APIClient
	skeErr               error
	dnsOnce              sync.Once
	dnsClient            *dns.APIClient
	dnsErr               error
	objectStorageOnce    sync.Once
	objectStorageClient  *objectstorage.APIClient
	objectStorageErr     error
	loadBalancerOnce     sync.Once
	loadBalancerClient   *loadbalancer.APIClient
	loadBalancerErr      error
	resourceManagerOnce  sync.Once
	resourceManagerClnt  *resourcemanager.APIClient
	resourceManagerErr   error
	postgresFlexOnce     sync.Once
	postgresFlexClient   *postgresflex.APIClient
	postgresFlexErr      error
	mongoDbFlexOnce      sync.Once
	mongoDbFlexClient    *mongodbflex.APIClient
	mongoDbFlexErr       error
	openSearchOnce       sync.Once
	openSearchClient     *opensearch.APIClient
	openSearchErr        error
	mariaDbOnce          sync.Once
	mariaDbClient        *mariadb.APIClient
	mariaDbErr           error
	redisOnce            sync.Once
	redisClient          *redis.APIClient
	redisErr             error
	rabbitMqOnce         sync.Once
	rabbitMqClient       *rabbitmq.APIClient
	rabbitMqErr          error
	logMeOnce            sync.Once
	logMeClient          *logme.APIClient
	logMeErr             error
	sqlServerFlexOnce    sync.Once
	sqlServerFlexClient  *sqlserverflex.APIClient
	sqlServerFlexErr     error
	secretsManagerOnce   sync.Once
	secretsManagerClient *secretsmanager.APIClient
	secretsManagerErr    error
	observabilityOnce    sync.Once
	observabilityClient  *observability.APIClient
	observabilityErr     error
	serviceAccountOnce   sync.Once
	serviceAccountClient *serviceaccount.APIClient
	serviceAccountErr    error
	sfsOnce              sync.Once
	sfsClient            *sfs.APIClient
	sfsErr               error
	telemetryRouterOnce  sync.Once
	telemetryRouterClnt  *telemetryrouter.APIClient
	telemetryRouterErr   error
	telemetryLinkOnce    sync.Once
	telemetryLinkClient  *telemetrylink.APIClient
	telemetryLinkErr     error
	modelServingOnce     sync.Once
	modelServingClient   *modelserving.APIClient
	modelServingErr      error
	albOnce              sync.Once
	albClient            *alb.APIClient
	albErr               error
	albWafOnce           sync.Once
	albWafClient         *albwaf.APIClient
	albWafErr            error
	certificatesOnce     sync.Once
	certificatesClient   *certificates.APIClient
	certificatesErr      error
	kmsOnce              sync.Once
	kmsClient            *kms.APIClient
	kmsErr               error
	authorizationOnce    sync.Once
	authorizationClient  *authorization.APIClient
	authorizationErr     error
	serverBackupOnce     sync.Once
	serverBackupClient   *serverbackup.APIClient
	serverBackupErr      error
	serverUpdateOnce     sync.Once
	serverUpdateClient   *serverupdate.APIClient
	serverUpdateErr      error
	vpnOnce              sync.Once
	vpnClient            *vpn.APIClient
	vpnErr               error
}

func NewStackitConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*StackitConnection, error) {
	projectID, _ := getOptionValueFrom(conf.Options, ProjectIDEnvVar, OptionProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("a STACKIT project ID is required; use --%s or set %s",
			OptionProjectID, ProjectIDEnvVar)
	}

	region, _ := getOptionValueFrom(conf.Options, RegionEnvVar, OptionRegion)
	if region == "" {
		region = DefaultRegion
	}

	globalOpts := buildAuthOptions(conf)
	regionalOpts := append([]config.ConfigurationOption{config.WithRegion(region)}, globalOpts...)

	conn := &StackitConnection{
		Connection:       plugin.NewConnection(id, asset),
		Conf:             conf,
		asset:            asset,
		projectID:        projectID,
		region:           region,
		configOpts:       regionalOpts,
		configOptsGlobal: globalOpts,
	}
	return conn, nil
}

// requestTimeout bounds a single STACKIT API request. The SDK's clients have
// no timeout of their own, and the plugin runtime hands resources no context
// to carry a deadline, so without it a request that never answers hangs the
// scan. A var so tests can shrink it.
var requestTimeout = 30 * time.Second

// withRequestTimeout gives each service client its own HTTP client with
// requestTimeout. It must allocate per client rather than share one: the SDK
// replaces the client's Transport with that service's auth round tripper, so a
// shared client would end up carrying whichever service was built last.
// config.WithTimeout cannot be used instead, because the SDK only creates the
// HTTP client after applying the options and that option dereferences it.
func withRequestTimeout() config.ConfigurationOption {
	return func(c *config.Configuration) error {
		c.HTTPClient = &http.Client{Timeout: requestTimeout}
		return nil
	}
}

// buildAuthOptions assembles the auth+endpoint options shared by every
// service client. The caller is responsible for prepending WithRegion when the
// target service is regional.
func buildAuthOptions(conf *inventory.Config) []config.ConfigurationOption {
	opts := []config.ConfigurationOption{withRequestTimeout()}

	if endpoint, ok := getOptionValueFrom(conf.Options, EndpointEnvVar, OptionEndpoint); ok {
		opts = append(opts, config.WithEndpoint(endpoint))
	}

	if key, ok := credentialFor(conf, OptionServiceAccountKey, ServiceAccountKeyEnvVar); ok {
		opts = append(opts, config.WithServiceAccountKey(key))
	} else if path, ok := getOptionValueFrom(conf.Options, ServiceAccountKeyPathEnvVar, OptionServiceAccountKeyPath); ok {
		opts = append(opts, config.WithServiceAccountKeyPath(path))
	}

	if pk, ok := credentialFor(conf, OptionPrivateKey, PrivateKeyEnvVar); ok {
		opts = append(opts, config.WithPrivateKey(pk))
	} else if path, ok := getOptionValueFrom(conf.Options, PrivateKeyPathEnvVar, OptionPrivateKeyPath); ok {
		opts = append(opts, config.WithPrivateKeyPath(path))
	}

	if token, ok := credentialFor(conf, OptionToken, TokenEnvVar); ok {
		opts = append(opts, config.WithToken(token))
	}

	return opts
}

func credentialFor(conf *inventory.Config, option, envVar string) (string, bool) {
	for _, cred := range conf.Credentials {
		if cred.Type != vault.CredentialType_password || len(cred.Secret) == 0 {
			continue
		}
		if cred.User == option {
			return string(cred.Secret), true
		}
	}
	if v, ok := conf.Options[option]; ok && v != "" {
		return v, true
	}
	if v := os.Getenv(envVar); v != "" {
		return v, true
	}
	return "", false
}

func getOptionValueFrom(options map[string]string, envVar, option string) (string, bool) {
	value := os.Getenv(envVar)
	if v, ok := options[option]; ok && v != "" {
		value = v
	}
	return value, value != ""
}

func (c *StackitConnection) ProjectID() string     { return c.projectID }
func (c *StackitConnection) Region() string        { return c.region }
func (c *StackitConnection) ProjectName() string   { return c.projectName }
func (c *StackitConnection) ProjectParent() string { return c.projectParent }

// ProjectLabels returns the labels attached to the STACKIT project, captured
// during Verify. The returned map must not be mutated by callers.
func (c *StackitConnection) ProjectLabels() map[string]string { return c.projectLabels }

func (c *StackitConnection) Verify(ctx context.Context) error {
	client, err := c.ResourceManager()
	if err != nil {
		return err
	}
	resp, err := client.DefaultAPI.GetProject(ctx, c.projectID).Execute()
	if err != nil {
		log.Warn().Err(err).Msg("stackit> verify project lookup failed")
		return fmt.Errorf("failed to verify STACKIT connection for project %s: %w", c.projectID, err)
	}
	c.captureProjectMetadata(resp)
	return nil
}

// captureProjectMetadata records the human-readable project name, parent
// container, and labels from the resource-manager response so detect() can
// enrich the asset without a second API call.
func (c *StackitConnection) captureProjectMetadata(resp *resourcemanager.GetProjectResponse) {
	if resp == nil {
		return
	}
	c.projectName = resp.GetName()
	if labels, ok := resp.GetLabelsOk(); ok && labels != nil {
		// Snapshot the map so a later SDK mutation of its internal copy cannot
		// change our captured labels, honoring the ProjectLabels() contract.
		c.projectLabels = maps.Clone(*labels)
	}
	if parent, ok := resp.GetParentOk(); ok {
		c.projectParent = parent.GetContainerId()
		if c.projectParent == "" {
			c.projectParent = parent.GetId()
		}
	}
}

// SecurityGroups returns every security group in the connected project and
// region, keyed by security group ID.
//
// Resolving a group reference through this map costs one list call for the
// whole connection no matter how many objects point at a group. Going through
// the resource runtime instead would run the security group's init once per
// reference, because a resource's init runs before the runtime cache is
// consulted, turning a single list into one GET per referring object.
//
// Failures are returned rather than flattened into an empty map. A caller
// resolving a group the API named cannot tell an unreadable list from a
// balancer with no group assigned once the error is gone, and those two
// answers carry opposite security meanings.
func (c *StackitConnection) SecurityGroups(ctx context.Context) (map[string]iaas.SecurityGroup, error) {
	c.securityGroupsOnce.Do(func() {
		c.securityGroups, c.securityGroupsErr = c.loadSecurityGroups(ctx)
	})
	return c.securityGroups, c.securityGroupsErr
}

func (c *StackitConnection) loadSecurityGroups(ctx context.Context) (map[string]iaas.SecurityGroup, error) {
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListSecurityGroups(ctx, c.projectID, c.region).Execute()
	if err != nil {
		return nil, err
	}
	out := map[string]iaas.SecurityGroup{}
	for _, sg := range resp.GetItems() {
		if id := sg.GetId(); id != "" {
			out[id] = sg
		}
	}
	return out, nil
}

// NetworkAreaRoutingTables returns the routing tables defined on the network
// areas that hold this project, keyed by routing table ID.
//
// The IaaS API scopes routing tables to an organization and a network area
// rather than to a project, so reaching the table a network points at means
// walking from the project's parent container to that container's areas and
// asking each area which projects it holds. The walk runs once per connection
// and is shared by every network.
//
// A project whose parent container is a folder rather than an organization,
// and a credential without organization-level read access, both leave the walk
// with nowhere to start. Those are ordinary configurations rather than
// failures, so they yield an empty map and networks report no routing table.
func (c *StackitConnection) NetworkAreaRoutingTables(ctx context.Context) (map[string]iaas.RoutingTable, error) {
	c.routingTablesOnce.Do(func() {
		c.routingTables, c.routingTablesErr = c.loadNetworkAreaRoutingTables(ctx)
	})
	return c.routingTables, c.routingTablesErr
}

func (c *StackitConnection) loadNetworkAreaRoutingTables(ctx context.Context) (map[string]iaas.RoutingTable, error) {
	empty := map[string]iaas.RoutingTable{}
	if c.projectParent == "" {
		log.Debug().Msg("stackit> project has no parent container, skipping routing table lookup")
		return empty, nil
	}
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}

	areas, err := client.DefaultAPI.ListNetworkAreas(ctx, c.projectParent).Execute()
	if err != nil {
		log.Debug().Err(err).Str("container", c.projectParent).
			Msg("stackit> network areas unavailable, networks will report no routing table")
		return empty, nil
	}

	out := map[string]iaas.RoutingTable{}
	for _, area := range areas.GetItems() {
		areaID := area.GetId()
		if areaID == "" || !c.areaHoldsProject(ctx, client, areaID) {
			continue
		}
		tables, err := client.DefaultAPI.
			ListRoutingTablesOfArea(ctx, c.projectParent, areaID, c.region).Execute()
		if err != nil {
			log.Debug().Err(err).Str("area", areaID).Msg("stackit> routing tables unavailable for area")
			continue
		}
		for _, table := range tables.GetItems() {
			if id := table.GetId(); id != "" {
				out[id] = table
			}
		}
	}
	return out, nil
}

// areaHoldsProject reports whether the connected project is attached to the
// given network area. A project can belong to more than one area, so callers
// collect from every area that matches rather than stopping at the first.
func (c *StackitConnection) areaHoldsProject(ctx context.Context, client *iaas.APIClient, areaID string) bool {
	projects, err := client.DefaultAPI.ListNetworkAreaProjects(ctx, c.projectParent, areaID).Execute()
	if err != nil {
		log.Debug().Err(err).Str("area", areaID).Msg("stackit> network area project list failed")
		return false
	}
	for _, projectID := range projects.GetItems() {
		if projectID == c.projectID {
			return true
		}
	}
	return false
}

func (c *StackitConnection) IaaS() (*iaas.APIClient, error) {
	c.iaasOnce.Do(func() {
		// The IaaS API rejects WithRegion in the client config and requires the
		// region as a per-call function parameter (which every IaaS resource
		// method supplies), so build the client without a bound region.
		c.iaasClient, c.iaasErr = iaas.NewAPIClient(c.configOptsGlobal...)
	})
	return c.iaasClient, c.iaasErr
}

func (c *StackitConnection) SKE() (*ske.APIClient, error) {
	c.skeOnce.Do(func() {
		// SKE likewise rejects WithRegion in the client config; the region is
		// passed as a per-call function parameter.
		c.skeClient, c.skeErr = ske.NewAPIClient(c.configOptsGlobal...)
	})
	return c.skeClient, c.skeErr
}

func (c *StackitConnection) DNS() (*dns.APIClient, error) {
	c.dnsOnce.Do(func() {
		c.dnsClient, c.dnsErr = dns.NewAPIClient(c.configOptsGlobal...)
	})
	return c.dnsClient, c.dnsErr
}

func (c *StackitConnection) ObjectStorage() (*objectstorage.APIClient, error) {
	c.objectStorageOnce.Do(func() {
		c.objectStorageClient, c.objectStorageErr = objectstorage.NewAPIClient(c.configOpts...)
	})
	return c.objectStorageClient, c.objectStorageErr
}

func (c *StackitConnection) LoadBalancer() (*loadbalancer.APIClient, error) {
	c.loadBalancerOnce.Do(func() {
		c.loadBalancerClient, c.loadBalancerErr = loadbalancer.NewAPIClient(c.configOpts...)
	})
	return c.loadBalancerClient, c.loadBalancerErr
}

func (c *StackitConnection) ResourceManager() (*resourcemanager.APIClient, error) {
	c.resourceManagerOnce.Do(func() {
		c.resourceManagerClnt, c.resourceManagerErr = resourcemanager.NewAPIClient(c.configOptsGlobal...)
	})
	return c.resourceManagerClnt, c.resourceManagerErr
}

func (c *StackitConnection) PostgresFlex() (*postgresflex.APIClient, error) {
	c.postgresFlexOnce.Do(func() {
		c.postgresFlexClient, c.postgresFlexErr = postgresflex.NewAPIClient(c.configOpts...)
	})
	return c.postgresFlexClient, c.postgresFlexErr
}

func (c *StackitConnection) MongoDbFlex() (*mongodbflex.APIClient, error) {
	c.mongoDbFlexOnce.Do(func() {
		// MongoDB Flex rejects WithRegion in the client config; the region is
		// passed as a per-call function parameter.
		c.mongoDbFlexClient, c.mongoDbFlexErr = mongodbflex.NewAPIClient(c.configOptsGlobal...)
	})
	return c.mongoDbFlexClient, c.mongoDbFlexErr
}

func (c *StackitConnection) OpenSearch() (*opensearch.APIClient, error) {
	c.openSearchOnce.Do(func() {
		c.openSearchClient, c.openSearchErr = opensearch.NewAPIClient(c.configOptsGlobal...)
	})
	return c.openSearchClient, c.openSearchErr
}

func (c *StackitConnection) MariaDb() (*mariadb.APIClient, error) {
	c.mariaDbOnce.Do(func() {
		c.mariaDbClient, c.mariaDbErr = mariadb.NewAPIClient(c.configOptsGlobal...)
	})
	return c.mariaDbClient, c.mariaDbErr
}

func (c *StackitConnection) Redis() (*redis.APIClient, error) {
	c.redisOnce.Do(func() {
		c.redisClient, c.redisErr = redis.NewAPIClient(c.configOptsGlobal...)
	})
	return c.redisClient, c.redisErr
}

func (c *StackitConnection) RabbitMq() (*rabbitmq.APIClient, error) {
	c.rabbitMqOnce.Do(func() {
		c.rabbitMqClient, c.rabbitMqErr = rabbitmq.NewAPIClient(c.configOptsGlobal...)
	})
	return c.rabbitMqClient, c.rabbitMqErr
}

func (c *StackitConnection) LogMe() (*logme.APIClient, error) {
	c.logMeOnce.Do(func() {
		c.logMeClient, c.logMeErr = logme.NewAPIClient(c.configOptsGlobal...)
	})
	return c.logMeClient, c.logMeErr
}

func (c *StackitConnection) SqlServerFlex() (*sqlserverflex.APIClient, error) {
	c.sqlServerFlexOnce.Do(func() {
		c.sqlServerFlexClient, c.sqlServerFlexErr = sqlserverflex.NewAPIClient(c.configOpts...)
	})
	return c.sqlServerFlexClient, c.sqlServerFlexErr
}

func (c *StackitConnection) SecretsManager() (*secretsmanager.APIClient, error) {
	c.secretsManagerOnce.Do(func() {
		c.secretsManagerClient, c.secretsManagerErr = secretsmanager.NewAPIClient(c.configOptsGlobal...)
	})
	return c.secretsManagerClient, c.secretsManagerErr
}

func (c *StackitConnection) Observability() (*observability.APIClient, error) {
	c.observabilityOnce.Do(func() {
		c.observabilityClient, c.observabilityErr = observability.NewAPIClient(c.configOptsGlobal...)
	})
	return c.observabilityClient, c.observabilityErr
}

func (c *StackitConnection) ServiceAccount() (*serviceaccount.APIClient, error) {
	c.serviceAccountOnce.Do(func() {
		c.serviceAccountClient, c.serviceAccountErr = serviceaccount.NewAPIClient(c.configOptsGlobal...)
	})
	return c.serviceAccountClient, c.serviceAccountErr
}

func (c *StackitConnection) Sfs() (*sfs.APIClient, error) {
	c.sfsOnce.Do(func() {
		// SFS rejects WithRegion in the client config; every SFS resource method
		// passes the region as a per-call function parameter.
		c.sfsClient, c.sfsErr = sfs.NewAPIClient(c.configOptsGlobal...)
	})
	return c.sfsClient, c.sfsErr
}

func (c *StackitConnection) ModelServing() (*modelserving.APIClient, error) {
	c.modelServingOnce.Do(func() {
		c.modelServingClient, c.modelServingErr = modelserving.NewAPIClient(c.configOptsGlobal...)
	})
	return c.modelServingClient, c.modelServingErr
}

func (c *StackitConnection) TelemetryRouter() (*telemetryrouter.APIClient, error) {
	c.telemetryRouterOnce.Do(func() {
		c.telemetryRouterClnt, c.telemetryRouterErr = telemetryrouter.NewAPIClient(c.configOptsGlobal...)
	})
	return c.telemetryRouterClnt, c.telemetryRouterErr
}

func (c *StackitConnection) TelemetryLink() (*telemetrylink.APIClient, error) {
	c.telemetryLinkOnce.Do(func() {
		c.telemetryLinkClient, c.telemetryLinkErr = telemetrylink.NewAPIClient(c.configOptsGlobal...)
	})
	return c.telemetryLinkClient, c.telemetryLinkErr
}

func (c *StackitConnection) ALB() (*alb.APIClient, error) {
	c.albOnce.Do(func() {
		c.albClient, c.albErr = alb.NewAPIClient(c.configOpts...)
	})
	return c.albClient, c.albErr
}

func (c *StackitConnection) AlbWaf() (*albwaf.APIClient, error) {
	c.albWafOnce.Do(func() {
		// Mirrors ALB (same product family): the WAF API is region-scoped via
		// the client config and also accepts the region as a per-call param.
		c.albWafClient, c.albWafErr = albwaf.NewAPIClient(c.configOpts...)
	})
	return c.albWafClient, c.albWafErr
}

func (c *StackitConnection) Certificates() (*certificates.APIClient, error) {
	c.certificatesOnce.Do(func() {
		c.certificatesClient, c.certificatesErr = certificates.NewAPIClient(c.configOpts...)
	})
	return c.certificatesClient, c.certificatesErr
}

func (c *StackitConnection) KMS() (*kms.APIClient, error) {
	c.kmsOnce.Do(func() {
		c.kmsClient, c.kmsErr = kms.NewAPIClient(c.configOpts...)
	})
	return c.kmsClient, c.kmsErr
}

func (c *StackitConnection) Authorization() (*authorization.APIClient, error) {
	c.authorizationOnce.Do(func() {
		c.authorizationClient, c.authorizationErr = authorization.NewAPIClient(c.configOptsGlobal...)
	})
	return c.authorizationClient, c.authorizationErr
}

func (c *StackitConnection) ServerBackup() (*serverbackup.APIClient, error) {
	c.serverBackupOnce.Do(func() {
		// Server Backup rejects WithRegion in the client config; every method
		// passes the region as a per-call function parameter.
		c.serverBackupClient, c.serverBackupErr = serverbackup.NewAPIClient(c.configOptsGlobal...)
	})
	return c.serverBackupClient, c.serverBackupErr
}

func (c *StackitConnection) ServerUpdate() (*serverupdate.APIClient, error) {
	c.serverUpdateOnce.Do(func() {
		// Server Update rejects WithRegion in the client config; every method
		// passes the region as a per-call function parameter.
		c.serverUpdateClient, c.serverUpdateErr = serverupdate.NewAPIClient(c.configOptsGlobal...)
	})
	return c.serverUpdateClient, c.serverUpdateErr
}

func (c *StackitConnection) Vpn() (*vpn.APIClient, error) {
	c.vpnOnce.Do(func() {
		// VPN rejects WithRegion in the client config; every method passes the
		// region as a per-call function parameter.
		c.vpnClient, c.vpnErr = vpn.NewAPIClient(c.configOptsGlobal...)
	})
	return c.vpnClient, c.vpnErr
}

// The clients below serve global endpoints; every method takes the region
// (where it has one) as a per-call parameter, so they are built without a
// bound region.

func (c *StackitConnection) CDN() (*cdn.APIClient, error) {
	c.cdnOnce.Do(func() {
		c.cdnClient, c.cdnErr = cdn.NewAPIClient(c.configOptsGlobal...)
	})
	return c.cdnClient, c.cdnErr
}

func (c *StackitConnection) Git() (*git.APIClient, error) {
	c.gitOnce.Do(func() {
		c.gitClient, c.gitErr = git.NewAPIClient(c.configOptsGlobal...)
	})
	return c.gitClient, c.gitErr
}

func (c *StackitConnection) Logs() (*logs.APIClient, error) {
	c.logsOnce.Do(func() {
		c.logsClient, c.logsErr = logs.NewAPIClient(c.configOptsGlobal...)
	})
	return c.logsClient, c.logsErr
}

func (c *StackitConnection) Valkey() (*valkey.APIClient, error) {
	c.valkeyOnce.Do(func() {
		c.valkeyClient, c.valkeyErr = valkey.NewAPIClient(c.configOptsGlobal...)
	})
	return c.valkeyClient, c.valkeyErr
}

func (c *StackitConnection) ServiceEnablement() (*serviceenablement.APIClient, error) {
	c.serviceEnablementOnce.Do(func() {
		c.serviceEnablementClient, c.serviceEnablementErr = serviceenablement.NewAPIClient(c.configOptsGlobal...)
	})
	return c.serviceEnablementClient, c.serviceEnablementErr
}

// PostgresFlexV3 is the v3 API of Postgres Flex. The instance record there
// carries the network access scope and customer-managed encryption the v2
// record lacks; the v2 client stays in place for the fields already shipped.
func (c *StackitConnection) PostgresFlexV3() (*postgresflexv3.APIClient, error) {
	c.postgresFlexV3Once.Do(func() {
		c.postgresFlexV3Client, c.postgresFlexV3Err = postgresflexv3.NewAPIClient(c.configOpts...)
	})
	return c.postgresFlexV3Client, c.postgresFlexV3Err
}

// SqlServerFlexV3 is the v3 API of SQLServer Flex, used alongside the v2
// client for the same reason as PostgresFlexV3.
func (c *StackitConnection) SqlServerFlexV3() (*sqlserverflexv3.APIClient, error) {
	c.sqlServerFlexV3Once.Do(func() {
		c.sqlServerFlexV3Client, c.sqlServerFlexV3Err = sqlserverflexv3.NewAPIClient(c.configOpts...)
	})
	return c.sqlServerFlexV3Client, c.sqlServerFlexV3Err
}

func (c *StackitConnection) Asset() *inventory.Asset { return c.asset }
func (c *StackitConnection) Name() string            { return "stackit" }

func (c *StackitConnection) PlatformInfo() *inventory.Platform {
	p := &inventory.Platform{
		// Matches the provider's AssetUrlTrees (technology=stackit -> project),
		// mirroring how gcp emits {"gcp", projectID, ...} and aws emits
		// {"aws", accountID, ...}.
		TechnologyUrlSegments: []string{"stackit", c.projectID},
	}
	PlatformByName("stackit-project").Apply(p)
	if c.projectName != "" {
		p.Title = "STACKIT Project " + c.projectName
	}
	return p
}

func (c *StackitConnection) Identifier() string {
	if c.projectID == "" {
		return ""
	}
	return PlatformIdStackitProject + c.projectID
}

var ErrMissingProjectID = errors.New("missing STACKIT project ID")
