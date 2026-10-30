// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	tsclient "tailscale.com/client/tailscale/v2"
)

const (
	DiscoveryAll     = "all"
	DiscoveryAuto    = "auto"
	DiscoveryDevices = "devices"
	DiscoveryUsers   = "users"
)

var (
	PlatformIdTailscaleTailnet = "//platformid.api.mondoo.app/runtime/tailscale/tailnet/"
	PlatformIdTailscaleDevice  = "//platformid.api.mondoo.app/runtime/tailscale/device/"
	PlatformIdTailscaleUser    = "//platformid.api.mondoo.app/runtime/tailscale/user/"
)

// Flag Options
const (
	OPTION_TOKEN         = "token"
	OPTION_BASE_URL      = "base-url"
	OPTION_CLIENT_ID     = "client-id"
	OPTION_CLIENT_SECRET = "client-secret"
	OPTION_TAILNET       = "tailnet" // from argument in `ParseCLIReq`
)

// Tailscale environment variables
const (
	TAILSCALE_API_KEY_VAR             = "TAILSCALE_API_KEY"
	TAILSCALE_OAUTH_CLIENT_ID_VAR     = "TAILSCALE_OAUTH_CLIENT_ID"
	TAILSCALE_OAUTH_CLIENT_SECRET_VAR = "TAILSCALE_OAUTH_CLIENT_SECRET"
	TAILSCALE_TAILNET_VAR             = "TAILSCALE_TAILNET"
	TAILSCALE_BASE_URL_VAR            = "TAILSCALE_BASE_URL"
)

// defaultTailnetPlaceholder is the fallback tailnet label used when the user
// did not name a tailnet and we could not derive it from the API.
const defaultTailnetPlaceholder = "default"

type TailscaleConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *tsclient.Client

	tailnetOnce sync.Once
	tailnet     string
}

func NewTailscaleConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*TailscaleConnection, error) {
	conn := &TailscaleConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     &tsclient.Client{Tailnet: "-"}, // a dash represents the default tailnet
	}

	// Detect authentication method
	switch AuthenticationMethod(conf) {
	case OAuthMethod:
		// OAuth client (id and secret)
		clientID, set := GetClientID(conf)
		if !set {
			return nil, fmt.Errorf("missing client id for OAuth authentication. "+
				"Use the --%s flag or via environment variables %s.",
				OPTION_CLIENT_ID,
				TAILSCALE_OAUTH_CLIENT_ID_VAR,
			)
		}

		clientSecret, set := GetClientSecret(conf)
		if !set {
			return nil, fmt.Errorf("missing client secret for OAuth authentication. "+
				"Use the --%s flag or via environment variables %s.",
				OPTION_CLIENT_SECRET,
				TAILSCALE_OAUTH_CLIENT_SECRET_VAR,
			)
		}
		// Scopes are deliberately left empty. Tailscale scopes access per
		// resource (policy_file:read, auth_keys, webhooks:read, dns:read,
		// log_streaming:read, feature_settings:read, devices:routes:read, ...),
		// and a client-credentials token is narrowed to whatever scopes the
		// token request names. Requesting a fixed subset here would cap every
		// OAuth user at that subset no matter what their client was granted,
		// while requesting the full set would break clients that were granted
		// less. Omitting the scope parameter issues a token carrying exactly
		// the scopes the OAuth client itself holds, so the grant made in the
		// Tailscale admin console is what decides access.
		conn.client.Auth = &tsclient.OAuth{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}
		log.Info().Str("method", "OAuth").Msg("tailscale> authentication configured")

	case TokenAuthMethod:
		// API access token
		token, set := GetToken(conf)
		if set {
			conn.client.APIKey = token
			log.Info().Str("method", "token").Msg("tailscale> authentication configured")
			break
		}
		// this should never happen since AuthenticationMethod() already check the token exists
		// but just in case the code there changes without considering this switch, we check
		fallthrough
	case NoAuthMethod:
		return nil, fmt.Errorf("a valid authentication method is required. "+
			"Use a Tailscale access token using the --token flag or an OAuth client passing --client-id and --client-secret. "+
			"Optionally, pass these credentials via environment variables. (%s %s %s %s)",
			TAILSCALE_OAUTH_CLIENT_ID_VAR,
			TAILSCALE_OAUTH_CLIENT_SECRET_VAR,
			TAILSCALE_TAILNET_VAR,
			TAILSCALE_API_KEY_VAR,
		)
	}

	// Configure the base url if set
	if value, set := GetBaseURL(conf); set {
		baseURL, err := url.Parse(value)
		if err != nil {
			return nil, errors.Wrap(err, "unable to configure base url")
		}
		conn.client.BaseURL = baseURL
		log.Info().Str("url", value).Msg("tailscale> base url configured")
	}

	// Configure a tailnet if set
	if value, set := GetTailnet(conf); set {
		conn.client.Tailnet = value
		log.Info().Str("tailnet", value).Msg("tailscale> connecting to custom tailnet")
	}

	return conn, nil
}

func (t *TailscaleConnection) Verify() error {
	// @afiune this is the cheapest API call I could find to verify the tailscale connection,
	// essentially we try to fetch information about a device and expect to have a 401 code.
	//
	// API specifications https://tailscale.com/api
	_, err := t.client.Devices().Get(context.Background(), "m0nd00")
	if err == nil {
		return nil
	}

	switch APIStatusCode(err) {
	case 401:
		return errors.New("invalid authentication provided, verify the provided credentials, use --help for more details")
	case 403:
		// The credential is valid but cannot read devices. For an OAuth client
		// that means the devices:core:read scope was never granted, which we
		// report now rather than letting every device query fail later.
		return errors.New("the provided credentials are not authorized to read devices. " +
			"When using an OAuth client, grant it the scopes for the resources you intend to query " +
			"(at minimum devices:core:read), then try again")
	}

	// Any other failure (a 404 for the probe device, a transient network error)
	// is not evidence of bad credentials, so we let the scan proceed.
	return nil
}

// ResolveTailnet returns the tailnet this connection targets.
//
// When the user named a tailnet we use it verbatim. Otherwise the client talks
// to the default tailnet of the credential ("-"), and Tailscale offers no
// endpoint that names it directly. We recover it from the tailnet's own users,
// so that two tailnets scanned without an explicit name do not collapse onto a
// single asset identity. Shared users belong to the tailnet they were shared
// from, not this one, so they are skipped.
//
// The lookup runs at most once per connection and falls back to a placeholder
// when it cannot be performed, which keeps a credential without users:read
// working exactly as it did before.
func (t *TailscaleConnection) ResolveTailnet() string {
	t.tailnetOnce.Do(func() {
		if value, set := GetTailnet(t.Conf); set {
			t.tailnet = value
			return
		}

		t.tailnet = defaultTailnetPlaceholder

		users, err := t.client.Users().List(context.Background(), nil, nil)
		if err != nil {
			log.Debug().Err(err).
				Msg("tailscale> unable to resolve the tailnet, falling back to the default identifier")
			return
		}

		for i := range users {
			if users[i].Type == tsclient.UserTypeShared {
				continue
			}
			if users[i].TailnetID != "" {
				t.tailnet = users[i].TailnetID
				log.Debug().Str("tailnet", t.tailnet).Msg("tailscale> resolved tailnet")
				return
			}
		}
	})
	return t.tailnet
}

func (t *TailscaleConnection) Asset() *inventory.Asset {
	return t.asset
}
func (t *TailscaleConnection) Name() string {
	return "tailscale"
}
func (t *TailscaleConnection) Client() *tsclient.Client {
	return t.client
}

func (t *TailscaleConnection) PlatformInfo() (*inventory.Platform, error) {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "tailscale", "org"},
	}
	PlatformByName("tailscale-org").Apply(p)
	return p, nil
}

func (t *TailscaleConnection) Identifier() string {
	return PlatformIdTailscaleTailnet + t.ResolveTailnet()
}

func NewTailscaleDeviceIdentifier(deviceId string) string {
	return PlatformIdTailscaleDevice + deviceId
}
func NewTailscaleDevicePlatform(deviceId string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "tailscale", "device", deviceId},
	}
	PlatformByName("tailscale-device").Apply(p)
	return p
}

// DeviceIdFromAsset returns the Tailscale device id carried by the asset's
// platform ids, or an empty string when the asset is not a discovered device.
// Resources use it so that a bare `tailscale.device` resolves to the device the
// asset represents instead of requiring an explicit id argument.
func DeviceIdFromAsset(asset *inventory.Asset) string {
	return platformIdSuffix(asset, PlatformIdTailscaleDevice)
}

// UserIdFromAsset returns the Tailscale user id carried by the asset's platform
// ids, or an empty string when the asset is not a discovered user.
func UserIdFromAsset(asset *inventory.Asset) string {
	return platformIdSuffix(asset, PlatformIdTailscaleUser)
}

func platformIdSuffix(asset *inventory.Asset, prefix string) string {
	if asset == nil {
		return ""
	}
	for _, platformId := range asset.PlatformIds {
		if suffix, found := strings.CutPrefix(platformId, prefix); found && suffix != "" {
			return suffix
		}
	}
	return ""
}

func NewTailscaleUserIdentifier(userId string) string {
	return PlatformIdTailscaleUser + userId
}
func NewTailscaleUserPlatform(userId string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"network", "tailscale", "user", userId},
	}
	PlatformByName("tailscale-user").Apply(p)
	return p
}
