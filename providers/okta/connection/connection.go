// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"github.com/rs/zerolog/log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	goCache "github.com/patrickmn/go-cache"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
)

// Okta accepts two kinds of API credential. An SSWS token belongs to the admin
// who created it and carries that admin's full privileges, which is why many
// orgs prohibit them outright. A service application authenticates with a
// private key JWT instead and holds only the scopes it was granted, so it can
// be given read-only access.

// accessTokenCacheTTL bounds how long a minted access token is reused for the
// requests issued outside the generated SDK. Each entry is also stored under
// the token's own expiry, so this is only an upper bound.
const accessTokenCacheTTL = 55 * time.Minute

const (
	// oktaRateLimitMaxRetries bounds how many times a request that came back
	// 429 is retried before the field reports the failure.
	oktaRateLimitMaxRetries = 3
	// oktaRateLimitMaxBackoffSeconds caps how long a single retry waits, so a
	// far-off X-Rate-Limit-Reset cannot stall a scan for minutes.
	oktaRateLimitMaxBackoffSeconds = 30
)

type OktaConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// custom connection fields
	organization string
	client       *okta.APIClient
	token        string
	// authorize stamps the Authorization header onto requests issued outside
	// the generated SDK, so the raw endpoints in resources/sdk authenticate the
	// same way the SDK-served ones do.
	authorize func(req *http.Request) error
	// orgSettings is the org record, fetched at most once.
	//
	// There is exactly one organization per connection, but initOktaOrganization
	// fetched it unconditionally and NewResource runs an init before it consults
	// the resource cache -- so every query referencing okta.organization spent
	// its own GET /api/v1/org. A scan of a near-empty org made 7 API calls, 5 of
	// them this one. The count follows how many checks mention the organization,
	// so it grows with policy breadth rather than with org size.
	//
	// The resource cache cannot serve this: the org's id comes back in the
	// response, so there is no key to look it up by beforehand.
	orgOnce     sync.Once
	orgSettings *okta.OrgSetting
	orgErr      error
	// apiExtension is the client for the endpoints the generated SDK does not
	// serve correctly. It is immutable once built, so it is shared rather than
	// rebuilt by each caller.
	apiExtension *sdk.ApiExtension
	// roleSubscriptions memoizes the notification subscriptions of each role
	// reference.
	//
	// Subscriptions belong to a role, not to an assignment of it, so every
	// account holding SUPER_ADMIN reports the same set. Read from the role
	// assignments of a directory of admins that is one request per admin for
	// an answer that does not vary, and the count grows with the size of the
	// admin population rather than with the number of distinct roles.
	roleSubscriptionsMu sync.Mutex
	roleSubscriptions   map[string]*roleSubscriptions
}

// roleSubscriptions is one memoized answer of the role-subscription endpoint,
// including the response that came with a failure so the caller can classify
// it the same way it would classify a fresh one.
type roleSubscriptions struct {
	items []okta.Subscription
	resp  *okta.APIResponse
	err   error
}

func NewOktaConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OktaConnection, error) {
	conn := &OktaConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize connection
	if conf.Type != "okta" {
		return nil, errors.New("provider type does not match") // TODO: switch to plugin.ErrProviderTypeDoesNotMatch
	}

	if conf.Options == nil || conf.Options["organization"] == "" {
		return nil, errors.New("okta provider requires an organization id. please set option `organization`")
	}

	org := conf.Options["organization"]

	var token string
	var privateKey string
	if len(conf.Credentials) > 0 {
		log.Debug().Int("credentials", len(conf.Credentials)).Msg("credentials")
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			switch cred.Type {
			case vault.CredentialType_password:
				token = string(cred.Secret)
			case vault.CredentialType_private_key:
				privateKey = string(cred.Secret)
			default:
				log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Okta provider")
			}
		}
	}

	orgURL := "https://" + org
	options := []okta.ConfigSetter{
		okta.WithOrgUrl(orgURL),
		// Okta rate limits per org, and a scan reads many collections in quick
		// succession, so a 429 during a large scan is ordinary rather than
		// exceptional. The SDK honors the X-Rate-Limit-Reset header when it is
		// allowed to retry; left at the default of no retries it surfaces the
		// 429 as a failed field instead.
		okta.WithRateLimitMaxRetries(oktaRateLimitMaxRetries),
		okta.WithRateLimitMaxBackOff(oktaRateLimitMaxBackoffSeconds),
	}
	serviceApp := false

	switch {
	case privateKey != "":
		clientID := conf.Options["client-id"]
		privateKeyID := conf.Options["private-key-id"]
		scopes := splitScopes(conf.Options["scopes"])
		if clientID == "" {
			return nil, errors.New("okta service app authentication requires a client id, pass --client-id or set OKTA_API_CLIENT_ID")
		}
		if privateKeyID == "" {
			return nil, errors.New("okta service app authentication requires the id of the registered public key, pass --private-key-id or set OKTA_API_PRIVATE_KEY_ID")
		}
		if len(scopes) == 0 {
			return nil, errors.New("okta service app authentication requires the scopes to request, pass --scopes or set OKTA_API_SCOPES")
		}

		serviceApp = true
		options = append(options,
			okta.WithAuthorizationMode("PrivateKey"),
			okta.WithClientId(clientID),
			okta.WithScopes(scopes),
			okta.WithPrivateKey(privateKey),
			okta.WithPrivateKeyId(privateKeyID),
		)

	case token != "":
		options = append(options, okta.WithToken(token))

	default:
		return nil, errors.New("okta requires either an API token (--token or OKTA_API_TOKEN) or service app credentials (--client-id, --private-key, --private-key-id and --scopes)")
	}

	config, err := okta.NewConfiguration(options...)
	if err != nil {
		return nil, err
	}
	client := okta.NewAPIClient(config)

	// Build the authorizer from the finished configuration so requests issued
	// outside the generated SDK carry the same user agent and rate-limit
	// settings the SDK-served ones do.
	if serviceApp {
		conn.authorize = privateKeyAuthorizer(config)
	} else {
		conn.authorize = sswsAuthorizer(token)
	}

	conn.organization = org
	conn.client = client
	conn.token = token
	// Neither field changes after this point, so the raw-endpoint client is
	// built once rather than per call.
	conn.apiExtension = &sdk.ApiExtension{Host: org, Authorize: conn.authorize}

	return conn, nil
}

// splitScopes accepts the scopes as a single option value, separated by commas
// or whitespace, since Okta writes them space-separated but a CLI flag reads
// more naturally comma-separated.
func splitScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	scopes := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			scopes = append(scopes, f)
		}
	}
	return scopes
}

func sswsAuthorizer(token string) func(*http.Request) error {
	return func(req *http.Request) error {
		req.Header.Set("Authorization", "SSWS "+token)
		return nil
	}
}

// privateKeyAuthorizer reuses the SDK's private key JWT exchange for requests
// the generated client does not serve. The SDK keeps its minted access token in
// a cache private to its APIClient, so this holds its own; the cost is one
// extra token exchange for the raw path, after which both are cached.
func privateKeyAuthorizer(config *okta.Configuration) func(*http.Request) error {
	tokenCache := goCache.New(accessTokenCacheTTL, accessTokenCacheTTL)
	client := config.Okta.Client
	userAgent := okta.NewUserAgent(config).String()

	return func(req *http.Request) error {
		auth := okta.NewPrivateKeyAuth(okta.PrivateKeyAuthConfig{
			TokenCache:       tokenCache,
			HttpClient:       config.HTTPClient,
			PrivateKeySigner: config.PrivateKeySigner,
			PrivateKey:       client.PrivateKey,
			PrivateKeyId:     client.PrivateKeyId,
			ClientId:         client.ClientId,
			OrgURL:           client.OrgUrl,
			UserAgent:        userAgent,
			Scopes:           client.Scopes,
			MaxRetries:       client.RateLimit.MaxRetries,
			MaxBackoff:       client.RateLimit.MaxBackoff,
			Req:              req,
		})
		// The SDK signs the DPoP proof against the request URL without its
		// query string, so strip it here the same way the generated client does.
		urlWithoutQuery := *req.URL
		urlWithoutQuery.RawQuery = ""
		return auth.Authorize(req.Method, urlWithoutQuery.String())
	}
}

func (c *OktaConnection) Name() string {
	return "okta"
}

func (c *OktaConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *OktaConnection) OrganizationID() string {
	return c.organization
}

func (c *OktaConnection) Client() *okta.APIClient {
	return c.client
}

func (c *OktaConnection) Token() string {
	return c.token
}

// ApiExtension returns the client for the Okta endpoints the generated SDK does
// not serve correctly. It carries this connection's authorization, so the raw
// path works under service app credentials as well as an API token.
func (c *OktaConnection) ApiExtension() *sdk.ApiExtension {
	return c.apiExtension
}

func (c *OktaConnection) Identifier() (string, error) {
	// Through the memoized accessor: this and initOktaOrganization are the only
	// two readers of the org record, and both used to fetch their own.
	settings, err := c.OrgSettings(context.Background())
	if err != nil {
		return "", errors.Join(errors.New("failed to get Okta org ID"), err)
	}
	if settings == nil || settings.Id == nil {
		return "", errors.New("failed to get Okta org ID: empty response")
	}

	return *settings.Id, nil
}

// OrgSettings returns the organization record, fetching it at most once per
// connection. See the orgSettings field for why this is memoized here rather
// than through the resource cache.
func (c *OktaConnection) OrgSettings(ctx context.Context) (*okta.OrgSetting, error) {
	c.orgOnce.Do(func() {
		settings, _, err := c.Client().OrgSettingGeneralAPI.GetOrgSettings(ctx).Execute()
		c.orgSettings, c.orgErr = settings, err
	})
	return c.orgSettings, c.orgErr
}

// RoleSubscriptions lists the administrator notifications a role reference is
// subscribed to, fetching each reference at most once per connection.
//
// roleRef is a standard role type (SUPER_ADMIN) or a custom role id. The
// *okta.APIResponse that accompanied a failure is returned alongside the
// error, so a caller can tell an org that does not answer for subscriptions
// from a request that failed.
func (c *OktaConnection) RoleSubscriptions(ctx context.Context, roleRef string) ([]okta.Subscription, *okta.APIResponse, error) {
	c.roleSubscriptionsMu.Lock()
	defer c.roleSubscriptionsMu.Unlock()

	if cached, ok := c.roleSubscriptions[roleRef]; ok {
		return cached.items, cached.resp, cached.err
	}

	result := &roleSubscriptions{}
	ref := roleRef
	items, resp, err := c.Client().SubscriptionAPI.
		ListSubscriptionsRole(ctx, okta.ListSubscriptionsRoleRoleRefParameter{String: &ref}).
		Execute()
	result.resp, result.err = resp, err
	if err == nil {
		result.items = items
		for resp != nil && resp.HasNextPage() {
			var page []okta.Subscription
			resp, err = resp.Next(&page)
			if err != nil {
				result.items, result.err = nil, err
				break
			}
			result.items = append(result.items, page...)
		}
	}

	if c.roleSubscriptions == nil {
		c.roleSubscriptions = map[string]*roleSubscriptions{}
	}
	c.roleSubscriptions[roleRef] = result
	return result.items, result.resp, result.err
}
