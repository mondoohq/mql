// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/portainer/client-api-go/v2/client"
	apiclient "github.com/portainer/client-api-go/v2/pkg/client"
	"github.com/portainer/client-api-go/v2/pkg/client/edge_jobs"
	"github.com/portainer/client-api-go/v2/pkg/client/registries"
	"github.com/portainer/client-api-go/v2/pkg/client/roles"
	"github.com/portainer/client-api-go/v2/pkg/client/stacks"
	"github.com/portainer/client-api-go/v2/pkg/client/users"
	"github.com/portainer/client-api-go/v2/pkg/client/webhooks"
	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type PortainerConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	client *client.PortainerClient
	// apiClient reaches the endpoints the convenience wrapper does not surface.
	// The wrapper keeps its own generated client in an unexported field with no
	// accessor, so those endpoints need a second client over the same address,
	// token and TLS rules.
	apiClient  *apiclient.PortainerClientAPI
	instanceID string
	version    string
	hostname   string

	// Instance-wide lists are shared by many resources (e.g. user.teams and
	// team.members both walk memberships/users/teams). Cache them on the
	// connection so they are fetched at most once instead of once per instance.
	// Each cachedList owns its mutex, so independent fetches run in parallel.
	users          cachedList[*models.PortainereeUser]
	teams          cachedList[*models.PortainerTeam]
	memberships    cachedList[*models.PortainerTeamMembership]
	tags           cachedList[*models.PortainerTag]
	endpoints      cachedList[*models.PortainereeEndpoint]
	endpointGroups cachedList[*models.PortainerEndpointGroup]
	edgeGroups     cachedList[*models.EdgegroupsDecoratedEdgeGroup]
	registries     cachedList[*models.PortainereeRegistry]
	stacks         cachedList[*models.PortainereeStack]
	webhooks       cachedList[*models.PortainerWebhook]
	edgeJobs       cachedList[*models.PortainerEdgeJob]
	roles          cachedList[*models.PortainereeRole]
}

// cachedList memoizes a single API list call (including its error) so callers
// share one result across resource resolutions.
type cachedList[T any] struct {
	mu      sync.Mutex
	items   []T
	err     error
	fetched bool
}

// get fetches and memoizes the list on first call. Only a successful result is
// cached, so a transient failure is retried on the next call.
func (cl *cachedList[T]) get(fetch func() ([]T, error)) ([]T, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if !cl.fetched {
		cl.items, cl.err = fetch()
		if cl.err == nil {
			cl.fetched = true
		}
	}
	return cl.items, cl.err
}

func NewPortainerConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*PortainerConnection, error) {
	conn := &PortainerConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	address := conf.Options[OptionAddress]
	if address == "" {
		address = os.Getenv("PORTAINER_ADDRESS")
	}
	if address == "" {
		return nil, errors.New("a Portainer address is required, pass --address '<url>' or set PORTAINER_ADDRESS")
	}

	// if a secret was provided, it always overrides the env variable since it has precedence
	accessToken := strings.TrimSpace(os.Getenv("PORTAINER_ACCESS_TOKEN"))
	if len(conf.Credentials) > 0 {
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				// trim trailing whitespace/newlines that file- or vault-backed
				// secrets often carry, which would corrupt the x-api-key header
				accessToken = strings.TrimSpace(string(cred.Secret))
				// the first password credential wins; stop so a later one can't
				// silently override it
				break
			}
			log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Portainer provider")
		}
	}
	if accessToken == "" {
		return nil, errors.New("a Portainer access token is required, pass --access-token '<token>' or set PORTAINER_ACCESS_TOKEN")
	}

	host, scheme, basePath, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	// the bare hostname (no scheme, no port) is used to label the asset
	conn.hostname = host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		conn.hostname = h
	}

	// Honor both the provider --insecure flag and the global --insecure (-k),
	// which the runtime surfaces as conf.Insecure.
	skipTLSVerify := conf.Insecure || conf.Options[OptionInsecure] == "true"

	opts := []client.ClientOption{
		client.WithScheme(scheme),
		client.WithBasePath(basePath),
	}
	if skipTLSVerify {
		opts = append(opts, client.WithSkipTLSVerify(true))
	}

	cli := client.NewPortainerClient(host, accessToken, opts...)
	conn.apiClient = newAPIClient(host, scheme, basePath, accessToken, skipTLSVerify)

	// reach the instance early and capture its metadata for the platform id
	status, err := cli.GetSystemStatus()
	if err != nil {
		return nil, errors.New("failed to connect to Portainer: " + err.Error())
	}

	conn.client = cli
	if status != nil {
		conn.instanceID = status.InstanceID
		conn.version = status.Version
	}

	// The system status endpoint is public, so reaching it proves the address
	// points at a Portainer instance but says nothing about the access token.
	// Make one authenticated call so an invalid or expired token fails here,
	// with a message that names the cause, instead of surfacing later as an
	// unattributed error on every single resource. The result is memoized on
	// the connection, so discovery and portainer.environments reuse it.
	if _, err := conn.Endpoints(); err != nil {
		return nil, errors.New("failed to authenticate against Portainer, check the access token: " + err.Error())
	}
	return conn, nil
}

// parseAddress splits a user-provided address into the host, scheme and base
// path expected by the Portainer client. The client takes a bare host (no
// scheme) plus separate scheme and base-path options.
//
// It is deliberately lenient: both "https://portainer.example.com" and a bare
// "portainer.example.com" are accepted (the scheme defaults to https), as is a
// reverse-proxy path prefix and surrounding whitespace from a pasted value.
func parseAddress(address string) (host, scheme, basePath string, err error) {
	scheme = "https"
	basePath = "/api"

	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", "", errors.New("invalid Portainer address: empty address")
	}

	if !strings.Contains(address, "://") {
		address = scheme + "://" + address
	}
	u, err := url.Parse(address)
	if err != nil {
		return "", "", "", errors.New("invalid Portainer address: " + err.Error())
	}
	if u.Scheme != "" {
		scheme = u.Scheme
	}
	if u.Host == "" {
		return "", "", "", errors.New("invalid Portainer address: missing host")
	}
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		// a path prefix is a reverse-proxy mount point; the Portainer API still
		// lives under <prefix>/api, so append it rather than replace the default
		basePath = p + "/api"
	}
	return u.Host, scheme, basePath, nil
}

func (c *PortainerConnection) Name() string {
	return "portainer"
}

func (c *PortainerConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *PortainerConnection) Client() *client.PortainerClient {
	return c.client
}

// Users returns all Portainer users, fetched once and cached on the connection.
func (c *PortainerConnection) Users() ([]*models.PortainereeUser, error) {
	return c.users.get(c.client.ListUsers)
}

// Teams returns all Portainer teams, fetched once and cached on the connection.
func (c *PortainerConnection) Teams() ([]*models.PortainerTeam, error) {
	return c.teams.get(c.client.ListTeams)
}

// TeamMemberships returns all Portainer team memberships, fetched once and
// cached on the connection.
func (c *PortainerConnection) TeamMemberships() ([]*models.PortainerTeamMembership, error) {
	return c.memberships.get(c.client.ListTeamMemberships)
}

// Tags returns all Portainer tags, fetched once and cached on the connection.
func (c *PortainerConnection) Tags() ([]*models.PortainerTag, error) {
	return c.tags.get(c.client.ListTags)
}

// Endpoints returns all Portainer environments (endpoints), fetched once and
// cached on the connection.
func (c *PortainerConnection) Endpoints() ([]*models.PortainereeEndpoint, error) {
	return c.endpoints.get(c.client.ListEndpoints)
}

// EndpointGroups returns all Portainer environment groups (endpoint groups),
// fetched once and cached on the connection.
func (c *PortainerConnection) EndpointGroups() ([]*models.PortainerEndpointGroup, error) {
	return c.endpointGroups.get(c.client.ListEndpointGroups)
}

// EdgeGroups returns all Portainer edge groups, fetched once and cached on the
// connection.
func (c *PortainerConnection) EdgeGroups() ([]*models.EdgegroupsDecoratedEdgeGroup, error) {
	return c.edgeGroups.get(c.client.ListEdgeGroups)
}

func (c *PortainerConnection) InstanceID() string {
	return c.instanceID
}

// InstanceKey returns the identifier platform ids are built from. It prefers
// the instance id reported by the server and falls back to the hostname, so
// that instances which report no id do not all collapse onto the same platform
// id (and therefore onto the same asset).
func (c *PortainerConnection) InstanceKey() string {
	if c.instanceID != "" {
		return c.instanceID
	}
	if c.hostname != "" {
		return c.hostname
	}
	return "unknown"
}

func (c *PortainerConnection) Version() string {
	return c.version
}

// Hostname returns the bare instance hostname (no scheme, no port), used to
// label the asset.
func (c *PortainerConnection) Hostname() string {
	return c.hostname
}

// newAPIClient builds the generated Portainer API client over the same address
// and token as the convenience wrapper, so both talk to one instance under one
// set of TLS rules. Authentication is attached to the transport rather than
// passed per call, which lets every operation be invoked with a nil authInfo.
func newAPIClient(host, scheme, basePath, accessToken string, skipTLSVerify bool) *apiclient.PortainerClientAPI {
	return apiclient.New(newAPIRuntime(host, scheme, basePath, accessToken, skipTLSVerify), nil)
}

// newAPIRuntime builds the transport newAPIClient runs on. It is separate so
// that the TLS rules it applies can be asserted without reaching an instance.
func newAPIRuntime(host, scheme, basePath, accessToken string, skipTLSVerify bool) *httptransport.Runtime {
	transport := httptransport.New(host, basePath, []string{scheme})
	// Certificate verification is only skipped when the operator asked for it
	// with --insecure/-k, which is how instances behind a self-signed
	// certificate are reached. The convenience wrapper applies the same rule to
	// its own transport, so both clients agree on how this connection is
	// protected; verification stays on by default.
	//
	// go-openapi has already installed http.DefaultTransport here, so the TLS
	// config is patched onto a clone of it rather than onto a bare transport.
	// A bare one would drop the proxy read from the environment along with the
	// dial, handshake and idle timeouts, which is the wrong trade for exactly
	// the self-hosted instances this flag exists for.
	if skipTLSVerify {
		base, ok := transport.Transport.(*http.Transport)
		if !ok {
			base = http.DefaultTransport.(*http.Transport)
		}
		patched := base.Clone()
		patched.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-controlled --insecure flag, for instances behind a self-signed certificate
		transport.Transport = patched
	}
	transport.DefaultAuthentication = runtime.ClientAuthInfoWriterFunc(
		func(r runtime.ClientRequest, _ strfmt.Registry) error {
			return r.SetHeaderParam("x-api-key", accessToken)
		},
	)
	return transport
}

// StatusCode reports the HTTP status an API error carries, which is the only
// way to tell "this feature is switched off" or "this token may not ask" apart
// from "this call failed".
//
// The generated client reports a status two different ways. A response the
// operation declares comes back as a typed value that knows its own code; one
// it does not declare, which is most 403s on this API, comes back as a
// runtime.APIError carrying the code in a field. Both have to be read, or the
// undeclared half looks like an unclassifiable failure.
func StatusCode(err error) (int, bool) {
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		return coded.Code(), true
	}
	if apiErr, ok := errors.AsType[*runtime.APIError](err); ok {
		return apiErr.Code, true
	}
	return 0, false
}

// IsFeatureDisabled reports whether an API error means the instance has the
// feature switched off rather than the call having failed. Portainer answers
// 503 on the Edge endpoints when Edge Compute is disabled, which must not be
// read as "there are none of these".
func IsFeatureDisabled(err error) bool {
	code, ok := StatusCode(err)
	return ok && code == http.StatusServiceUnavailable
}

// IsForbidden reports whether an API error means the token lacks the authority
// for the call. Several endpoints are administrator-only, so a standard-user
// token reaches them with 403 rather than an empty result.
func IsForbidden(err error) bool {
	code, ok := StatusCode(err)
	return ok && (code == http.StatusForbidden || code == http.StatusUnauthorized)
}

// Registries returns the container registries configured on the instance,
// fetched once and cached on the connection.
func (c *PortainerConnection) Registries() ([]*models.PortainereeRegistry, error) {
	return c.registries.get(func() ([]*models.PortainereeRegistry, error) {
		res, err := c.apiClient.Registries.RegistryList(registries.NewRegistryListParams(), nil)
		if err != nil {
			return nil, err
		}
		return res.Payload, nil
	})
}

// Stacks returns the stacks deployed through the instance, fetched once and
// cached on the connection.
func (c *PortainerConnection) Stacks() ([]*models.PortainereeStack, error) {
	return c.stacks.get(func() ([]*models.PortainereeStack, error) {
		// The list operation reports "no stacks" as a 204 rather than an empty
		// body, so an empty second return value is a successful empty result.
		res, _, err := c.apiClient.Stacks.StackList(stacks.NewStackListParams(), nil)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return []*models.PortainereeStack{}, nil
		}
		return res.Payload, nil
	})
}

// Webhooks returns the webhooks defined on the instance, fetched once and
// cached on the connection.
func (c *PortainerConnection) Webhooks() ([]*models.PortainerWebhook, error) {
	return c.webhooks.get(func() ([]*models.PortainerWebhook, error) {
		res, err := c.apiClient.Webhooks.GetWebhooks(webhooks.NewGetWebhooksParams(), nil)
		if err != nil {
			return nil, err
		}
		return res.Payload, nil
	})
}

// EdgeJobs returns the Edge jobs scheduled on the instance, fetched once and
// cached on the connection. The error is returned as-is so the caller can tell
// a disabled Edge Compute feature apart from a failed call.
func (c *PortainerConnection) EdgeJobs() ([]*models.PortainerEdgeJob, error) {
	return c.edgeJobs.get(func() ([]*models.PortainerEdgeJob, error) {
		res, err := c.apiClient.EdgeJobs.EdgeJobList(edge_jobs.NewEdgeJobListParams(), nil)
		if err != nil {
			return nil, err
		}
		return res.Payload, nil
	})
}

// Roles returns the role definitions the instance offers for environment access
// policies, fetched once and cached on the connection.
func (c *PortainerConnection) Roles() ([]*models.PortainereeRole, error) {
	return c.roles.get(func() ([]*models.PortainereeRole, error) {
		res, err := c.apiClient.Roles.RoleList(roles.NewRoleListParams(), nil)
		if err != nil {
			return nil, err
		}
		return res.Payload, nil
	})
}

// APIKeys returns the API keys issued for one user. The keys are held per user
// by the API, so this is not cached instance-wide; it is called at most once per
// user resource.
func (c *PortainerConnection) APIKeys(userID int64) ([]*models.PortainerAPIKey, error) {
	params := users.NewUserGetAPIKeysParams()
	params.ID = userID
	res, err := c.apiClient.Users.UserGetAPIKeys(params, nil)
	if err != nil {
		return nil, err
	}
	return res.Payload, nil
}
