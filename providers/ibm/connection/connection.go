// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"github.com/IBM/platform-services-go-sdk/iamaccessgroupsv2"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/go-openapi/runtime"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// requestTimeout bounds a single API request. The SDK clients have no timeout
// of their own and the plugin runtime hands resources no context to carry a
// deadline, so without it a request that never answers hangs the scan. The
// SDK's retry layer issues each retry as its own request, so this bounds an
// attempt rather than the whole retried operation. Vars so tests can shrink
// them.
var (
	requestTimeout = 30 * time.Second
	maxRetries     = 3
	maxRetryWait   = 30 * time.Second
)

const PlatformIdIbmAccount = "//platformid.api.mondoo.app/runtime/ibm/account/"

type IbmConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// auth is shared by every client: it caches the IAM token and refreshes
	// it, so one token serves all services.
	auth      *core.IamAuthenticator
	accountID string
	// regionFilter restricts the VPC regions queried; empty means all.
	regionFilter []string
	// Filters narrows the listed discovery-target resources by tag
	// (--filters), so discovery and queries see the same set.
	Filters DiscoveryFilters

	clientsOnce         sync.Once
	clientsErr          error
	iamIdentity         *iamidentityv1.IamIdentityV1
	iamAccessGroups     *iamaccessgroupsv2.IamAccessGroupsV2
	iamPolicyManagement *iampolicymanagementv1.IamPolicyManagementV1
	resourceController  *resourcecontrollerv2.ResourceControllerV2
	resourceManager     *resourcemanagerv2.ResourceManagerV2
	globalSearch        *globalsearchv2.GlobalSearchV2

	regionsOnce sync.Once
	regions     []vpcv1.Region
	regionsErr  error

	memoMu sync.Mutex
	memo   map[string]*memoEntry
}

type memoEntry struct {
	once sync.Once
	val  any
	err  error
}

func NewIbmConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*IbmConnection, error) {
	key, err := GetAPIKey(conf)
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, fmt.Errorf("an IBM Cloud API key is required. Use the --api-key or --%s flag, or set the %s environment variable",
			OptionAPIKeyFile, APIKeyEnvVar)
	}
	auth, err := core.NewIamAuthenticatorBuilder().SetApiKey(key).Build()
	if err != nil {
		return nil, fmt.Errorf("configuring IBM Cloud IAM authentication: %w", err)
	}
	auth.Client = newHTTPClient()

	return &IbmConnection{
		Connection:   plugin.NewConnection(id, asset),
		Conf:         conf,
		asset:        asset,
		auth:         auth,
		regionFilter: GetRegions(conf),
		Filters:      DiscoveryFiltersFromOpts(conf.Options),
	}, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: requestTimeout}
}

// configure gives a service its own HTTP client with the request timeout and
// turns on the SDK's retries, which retry 429 and 5xx answers and honor
// Retry-After. The retry layer keeps the timed client underneath it.
func configure(svc *core.BaseService) {
	svc.SetHTTPClient(newHTTPClient())
	svc.EnableRetries(maxRetries, maxRetryWait)
}

// Verify confirms the API key and resolves the account it belongs to, which
// every account-scoped API needs and which anchors the asset's platform id.
func (c *IbmConnection) Verify() error {
	if err := c.initClients(); err != nil {
		return err
	}
	key := c.auth.ApiKey
	details, _, err := c.iamIdentity.GetAPIKeysDetails(&iamidentityv1.GetAPIKeysDetailsOptions{IamAPIKey: &key})
	if err != nil {
		var authErr *core.AuthenticationError
		if errors.As(err, &authErr) || StatusCode(err) == http.StatusUnauthorized || StatusCode(err) == http.StatusBadRequest {
			return fmt.Errorf("invalid IBM Cloud API key; verify the key: %w", err)
		}
		return fmt.Errorf("failed to verify the IBM Cloud connection: %w", err)
	}
	if details == nil || details.AccountID == nil || *details.AccountID == "" {
		return errors.New("IBM Cloud did not report the account of this API key")
	}
	c.accountID = *details.AccountID
	return nil
}

func (c *IbmConnection) initClients() error {
	c.clientsOnce.Do(func() {
		var err error
		if c.iamIdentity, err = iamidentityv1.NewIamIdentityV1(&iamidentityv1.IamIdentityV1Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.iamIdentity.Service)
		if c.iamAccessGroups, err = iamaccessgroupsv2.NewIamAccessGroupsV2(&iamaccessgroupsv2.IamAccessGroupsV2Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.iamAccessGroups.Service)
		if c.iamPolicyManagement, err = iampolicymanagementv1.NewIamPolicyManagementV1(&iampolicymanagementv1.IamPolicyManagementV1Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.iamPolicyManagement.Service)
		if c.resourceController, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.resourceController.Service)
		if c.resourceManager, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.resourceManager.Service)
		if c.globalSearch, err = globalsearchv2.NewGlobalSearchV2(&globalsearchv2.GlobalSearchV2Options{Authenticator: c.auth}); err != nil {
			c.clientsErr = err
			return
		}
		configure(c.globalSearch.Service)
	})
	return c.clientsErr
}

func (c *IbmConnection) Name() string            { return "ibm" }
func (c *IbmConnection) Asset() *inventory.Asset { return c.asset }
func (c *IbmConnection) AccountID() string       { return c.accountID }

func (c *IbmConnection) IamIdentity() *iamidentityv1.IamIdentityV1 { return c.iamIdentity }
func (c *IbmConnection) IamAccessGroups() *iamaccessgroupsv2.IamAccessGroupsV2 {
	return c.iamAccessGroups
}
func (c *IbmConnection) IamPolicyManagement() *iampolicymanagementv1.IamPolicyManagementV1 {
	return c.iamPolicyManagement
}
func (c *IbmConnection) ResourceController() *resourcecontrollerv2.ResourceControllerV2 {
	return c.resourceController
}
func (c *IbmConnection) ResourceManager() *resourcemanagerv2.ResourceManagerV2 {
	return c.resourceManager
}
func (c *IbmConnection) GlobalSearch() *globalsearchv2.GlobalSearchV2 { return c.globalSearch }

// VpcRegions lists the VPC regions to query, once per connection, narrowed to
// the --regions filter. A filter naming a region that does not exist is an
// error rather than a silently smaller scan.
func (c *IbmConnection) VpcRegions() ([]vpcv1.Region, error) {
	c.regionsOnce.Do(func() {
		svc, err := c.newVpcClient(vpcv1.DefaultServiceURL)
		if err != nil {
			c.regionsErr = err
			return
		}
		res, _, err := svc.ListRegions(&vpcv1.ListRegionsOptions{})
		if err != nil {
			c.regionsErr = err
			return
		}
		c.regions, c.regionsErr = filterRegions(res.Regions, c.regionFilter)
	})
	return c.regions, c.regionsErr
}

func filterRegions(all []vpcv1.Region, filter []string) ([]vpcv1.Region, error) {
	if len(filter) == 0 {
		return all, nil
	}
	out := make([]vpcv1.Region, 0, len(filter))
	for _, name := range filter {
		idx := slices.IndexFunc(all, func(r vpcv1.Region) bool { return r.Name != nil && *r.Name == name })
		if idx < 0 {
			known := make([]string, 0, len(all))
			for _, r := range all {
				if r.Name != nil {
					known = append(known, *r.Name)
				}
			}
			return nil, fmt.Errorf("unknown IBM Cloud VPC region %q (available: %v)", name, known)
		}
		out = append(out, all[idx])
	}
	return out, nil
}

// VpcClient returns the VPC client for a region, built once per region.
func (c *IbmConnection) VpcClient(region vpcv1.Region) (*vpcv1.VpcV1, error) {
	name := ""
	if region.Name != nil {
		name = *region.Name
	}
	v, err := c.Memo("vpc/"+name, func() (any, error) {
		url, err := vpcv1.GetServiceURLForRegion(name)
		if err != nil {
			if region.Endpoint == nil {
				return nil, err
			}
			url = *region.Endpoint + "/v1"
		}
		return c.newVpcClient(url)
	})
	if err != nil {
		return nil, err
	}
	return v.(*vpcv1.VpcV1), nil
}

func (c *IbmConnection) newVpcClient(url string) (*vpcv1.VpcV1, error) {
	svc, err := vpcv1.NewVpcV1(&vpcv1.VpcV1Options{Authenticator: c.auth, URL: url})
	if err != nil {
		return nil, err
	}
	configure(svc.Service)
	return svc, nil
}

// PowerSession returns the Power Virtual Server session for a zone, such as
// wdc06. A workspace only answers on its own zone's endpoint; the session
// derives that endpoint from the zone.
func (c *IbmConnection) PowerSession(zone string) (*ibmpisession.IBMPISession, error) {
	v, err := c.Memo("power/"+zone, func() (any, error) {
		return ibmpisession.NewIBMPISession(&ibmpisession.IBMPIOptions{
			Authenticator: c.auth,
			UserAccount:   c.accountID,
			Zone:          zone,
		})
	})
	if err != nil {
		return nil, err
	}
	return v.(*ibmpisession.IBMPISession), nil
}

// Memo runs fn once per key for the lifetime of the connection and returns
// its result to every caller.
func (c *IbmConnection) Memo(key string, fn func() (any, error)) (any, error) {
	c.memoMu.Lock()
	if c.memo == nil {
		c.memo = map[string]*memoEntry{}
	}
	e, ok := c.memo[key]
	if !ok {
		e = &memoEntry{}
		c.memo[key] = e
	}
	c.memoMu.Unlock()
	e.once.Do(func() { e.val, e.err = fn() })
	return e.val, e.err
}

// Context is the context API calls run under. The plugin runtime hands
// resources none, so this is a background context; requestTimeout bounds each
// request instead.
func Context() context.Context {
	return context.Background()
}

// StatusCode returns the HTTP status of a failed IBM Cloud SDK call, or 0 when
// the error carries none (a transport failure).
func StatusCode(err error) int {
	if err == nil {
		return 0
	}
	var httpProblem *core.HTTPProblem
	if errors.As(err, &httpProblem) && httpProblem.Response != nil {
		return httpProblem.Response.StatusCode
	}
	var authErr *core.AuthenticationError
	if errors.As(err, &authErr) && authErr.Response != nil {
		return authErr.Response.StatusCode
	}
	// The Power Virtual Server client is generated by go-swagger: its errors
	// are per-status response types that report their status through Code().
	var coder interface{ Code() int }
	if errors.As(err, &coder) {
		return coder.Code()
	}
	// A status the swagger client has no type for arrives as a runtime.APIError.
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	// The Power client turns a 429 into a plain error that keeps no status.
	if strings.Contains(err.Error(), "Rate Limited") {
		return http.StatusTooManyRequests
	}
	return 0
}

func (c *IbmConnection) PlatformInfo() *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"cloud", "ibm", "account"},
	}
	PlatformByName("ibm-account").Apply(p)
	return p
}

// Identifier is the platform id of the account.
func (c *IbmConnection) Identifier() string {
	return PlatformIdIbmAccount + c.accountID
}
