// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var (
	PlatformIdOpenstackProject = "//platformid.api.mondoo.app/runtime/openstack/project/"
	PlatformIdOpenstackDomain  = "//platformid.api.mondoo.app/runtime/openstack/domain/"
	PlatformIdOpenstackSystem  = "//platformid.api.mondoo.app/runtime/openstack/system/"
)

type OpenstackConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	provider  *gophercloud.ProviderClient
	region    string
	authOpts  gophercloud.AuthOptions
	projectID string
	domainID  string

	clientLock       sync.Mutex
	identity         *gophercloud.ServiceClient
	compute          *gophercloud.ServiceClient
	network          *gophercloud.ServiceClient
	blockStorage     *gophercloud.ServiceClient
	image            *gophercloud.ServiceClient
	keyManager       *gophercloud.ServiceClient
	loadBalancer     *gophercloud.ServiceClient
	objectStorage    *gophercloud.ServiceClient
	dns              *gophercloud.ServiceClient
	sharedFileSystem *gophercloud.ServiceClient
	containerInfra   *gophercloud.ServiceClient
	database         *gophercloud.ServiceClient
	bareMetal        *gophercloud.ServiceClient
	orchestration    *gophercloud.ServiceClient
	placement        *gophercloud.ServiceClient

	// Name->ID caches for Nova-reported references that Neutron/Compute
	// expose only by ID. A non-nil map is the "ready" signal so we don't
	// need a separate flag; the lock single-flights the first fetch and
	// concurrent callers wait. Real (non-translated) errors leave the
	// map nil so the next call retries — a transient blip can't poison
	// the cache for the connection's lifetime.
	SGNameCacheLock sync.Mutex
	SGNameCache     map[string]string

	FlavorNameCacheLock sync.Mutex
	FlavorNameCache     map[string]string
}

func NewOpenstackConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OpenstackConnection, error) {
	auth, err := resolveAuth(conf)
	if err != nil {
		return nil, err
	}

	if auth.authOpts.IdentityEndpoint == "" {
		return nil, errors.New("OpenStack auth URL is required (use --auth-url, --cloud, or set OS_AUTH_URL)")
	}

	provider, err := openstack.NewClient(auth.authOpts.IdentityEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OpenStack client: %w", err)
	}
	if conf.Options[OPTION_INSECURE] == "true" {
		provider.HTTPClient = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user-controlled flag for lab/test clouds
			},
		}
	}
	if err := openstack.Authenticate(context.Background(), provider, auth.authOpts); err != nil {
		return nil, fmt.Errorf("failed to authenticate with OpenStack: %w", err)
	}

	// Resolve the actual scoped project (or domain) ID from the auth
	// response. The caller may have authenticated by project_name (rather
	// than project_id), or with a domain-scoped/system-scoped token, in
	// which case authOpts only carries names and we need Keystone's answer
	// for the platform ID.
	projectID := auth.authOpts.TenantID
	if projectID == "" && auth.authOpts.Scope != nil {
		projectID = auth.authOpts.Scope.ProjectID
	}
	domainID := ""
	if auth.authOpts.Scope != nil {
		domainID = auth.authOpts.Scope.DomainID
	}
	if v3Result, ok := provider.GetAuthResult().(tokens.CreateResult); ok {
		if projectID == "" {
			if project, err := v3Result.ExtractProject(); err == nil && project != nil {
				projectID = project.ID
				if domainID == "" && project.Domain.ID != "" {
					domainID = project.Domain.ID
				}
			}
		}
		if domainID == "" {
			if domain, err := v3Result.ExtractDomain(); err == nil && domain != nil {
				domainID = domain.ID
			}
		}
	}

	return &OpenstackConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		provider:   provider,
		region:     auth.region,
		authOpts:   auth.authOpts,
		projectID:  projectID,
		domainID:   domainID,
	}, nil
}

func (c *OpenstackConnection) Name() string                          { return "openstack" }
func (c *OpenstackConnection) Asset() *inventory.Asset               { return c.asset }
func (c *OpenstackConnection) Provider() *gophercloud.ProviderClient { return c.provider }
func (c *OpenstackConnection) Region() string                        { return c.region }

// AuthURL returns the Keystone endpoint without trailing slashes, suitable for
// embedding into platform IDs.
func (c *OpenstackConnection) AuthURL() string {
	return strings.TrimRight(c.authOpts.IdentityEndpoint, "/")
}

// ProjectID returns the scoped project ID. Empty when the token is not
// project-scoped (e.g. domain-scoped or system-scoped). When the caller
// authenticated by project_name, this value is resolved from Keystone's
// auth response rather than the input scope.
func (c *OpenstackConnection) ProjectID() string {
	return c.projectID
}

// DomainID returns the scoped domain ID. Populated for both project-scoped
// tokens (the project's owning domain) and domain-scoped tokens, and empty
// for system-scoped or fully unscoped tokens.
func (c *OpenstackConnection) DomainID() string {
	return c.domainID
}

func (c *OpenstackConnection) endpointOpts() gophercloud.EndpointOpts {
	return gophercloud.EndpointOpts{Region: c.region}
}

func (c *OpenstackConnection) IdentityClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.identity != nil {
		return c.identity, nil
	}
	client, err := openstack.NewIdentityV3(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Keystone client: %w", err)
	}
	c.identity = client
	return client, nil
}

func (c *OpenstackConnection) ComputeClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.compute != nil {
		return c.compute, nil
	}
	client, err := openstack.NewComputeV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Nova client: %w", err)
	}
	c.compute = client
	return client, nil
}

func (c *OpenstackConnection) NetworkClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.network != nil {
		return c.network, nil
	}
	client, err := openstack.NewNetworkV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Neutron client: %w", err)
	}
	c.network = client
	return client, nil
}

func (c *OpenstackConnection) BlockStorageClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.blockStorage != nil {
		return c.blockStorage, nil
	}
	client, err := openstack.NewBlockStorageV3(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Cinder client: %w", err)
	}
	c.blockStorage = client
	return client, nil
}

func (c *OpenstackConnection) ImageClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.image != nil {
		return c.image, nil
	}
	client, err := openstack.NewImageV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Glance client: %w", err)
	}
	c.image = client
	return client, nil
}

func (c *OpenstackConnection) KeyManagerClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.keyManager != nil {
		return c.keyManager, nil
	}
	client, err := openstack.NewKeyManagerV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Barbican client: %w", err)
	}
	c.keyManager = client
	return client, nil
}

func (c *OpenstackConnection) LoadBalancerClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.loadBalancer != nil {
		return c.loadBalancer, nil
	}
	client, err := openstack.NewLoadBalancerV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Octavia client: %w", err)
	}
	c.loadBalancer = client
	return client, nil
}

func (c *OpenstackConnection) ObjectStorageClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.objectStorage != nil {
		return c.objectStorage, nil
	}
	client, err := openstack.NewObjectStorageV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Swift client: %w", err)
	}
	c.objectStorage = client
	return client, nil
}

func (c *OpenstackConnection) DNSClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.dns != nil {
		return c.dns, nil
	}
	client, err := openstack.NewDNSV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Designate client: %w", err)
	}
	c.dns = client
	return client, nil
}

// sharedFileSystemMicroversion pins the Manila API microversion. 2.45 is the
// version that introduced the dedicated share access-rules API and the modern
// share detail fields; it has been available since OpenStack Queens (2018).
// Clouds whose maximum supported microversion is lower will return 406 for
// these calls, which the resource layer treats as "no data".
const sharedFileSystemMicroversion = "2.45"

func (c *OpenstackConnection) SharedFileSystemClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.sharedFileSystem != nil {
		return c.sharedFileSystem, nil
	}
	client, err := openstack.NewSharedFileSystemV2(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Manila client: %w", err)
	}
	client.Microversion = sharedFileSystemMicroversion
	c.sharedFileSystem = client
	return client, nil
}

func (c *OpenstackConnection) ContainerInfraClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.containerInfra != nil {
		return c.containerInfra, nil
	}
	client, err := openstack.NewContainerInfraV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Magnum client: %w", err)
	}
	c.containerInfra = client
	return client, nil
}

func (c *OpenstackConnection) DatabaseClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.database != nil {
		return c.database, nil
	}
	client, err := openstack.NewDBV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Trove client: %w", err)
	}
	c.database = client
	return client, nil
}

// bareMetalMicroversion pins the Ironic API microversion. 1.65 exposes node
// ownership fields (`owner`, `lessee`) along with `protected`, `description`,
// and `fault`; it has been available since OpenStack Ussuri (2020). Clouds
// whose maximum supported microversion is lower return 406, which the resource
// layer treats as "no data".
const bareMetalMicroversion = "1.65"

func (c *OpenstackConnection) BareMetalClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.bareMetal != nil {
		return c.bareMetal, nil
	}
	client, err := openstack.NewBareMetalV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Ironic client: %w", err)
	}
	client.Microversion = bareMetalMicroversion
	c.bareMetal = client
	return client, nil
}

func (c *OpenstackConnection) OrchestrationClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.orchestration != nil {
		return c.orchestration, nil
	}
	client, err := openstack.NewOrchestrationV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Heat client: %w", err)
	}
	c.orchestration = client
	return client, nil
}

// placementMicroversion pins the Placement API microversion. 1.14 exposes the
// nested-provider fields (`parent_provider_uuid`, `root_provider_uuid`) used to
// walk provider trees; it has been available since OpenStack Rocky (2018).
const placementMicroversion = "1.14"

func (c *OpenstackConnection) PlacementClient() (*gophercloud.ServiceClient, error) {
	c.clientLock.Lock()
	defer c.clientLock.Unlock()
	if c.placement != nil {
		return c.placement, nil
	}
	client, err := openstack.NewPlacementV1(c.provider, c.endpointOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Placement client: %w", err)
	}
	client.Microversion = placementMicroversion
	c.placement = client
	return client, nil
}
