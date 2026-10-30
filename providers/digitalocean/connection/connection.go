// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"golang.org/x/oauth2"
)

type DigitaloceanConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	// Filters narrows which objects the listers return, and therefore which
	// objects discovery turns into assets.
	Filters         DiscoveryFilters
	client          *godo.Client
	spacesKey       string
	spacesSecret    string
	spacesRegion    string // optional — when set, restricts bucket listing to one region
	spacesClients   map[string]*s3.Client
	spacesClientsMu sync.Mutex

	accountUUID     string
	accountUUIDOnce sync.Once
}

// AccountUUID returns the owning account's UUID, fetching it once and
// caching the result. It anchors both the account platform id and the
// discovered child platform ids, so detect() and Discover() share a
// single Account.Get round-trip. Returns "" when the token can't read
// the account.
func (c *DigitaloceanConnection) AccountUUID() string {
	c.accountUUIDOnce.Do(func() {
		acct, _, err := c.client.Account.Get(context.Background())
		if err == nil && acct != nil {
			c.accountUUID = acct.UUID
		}
	})
	return c.accountUUID
}

func NewDigitaloceanConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DigitaloceanConnection, error) {
	conn := &DigitaloceanConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	token := os.Getenv("DIGITALOCEAN_TOKEN")
	if len(conf.Credentials) > 0 {
		for _, cred := range conf.Credentials {
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
			}
		}
	}
	if token == "" {
		return nil, errors.New("a valid DigitalOcean token is required (set DIGITALOCEAN_TOKEN or use --token)")
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	conn.client = godo.NewClient(oauthClient)

	conn.Filters = DiscoveryFiltersFromOpts(conf.Options)

	conn.spacesKey = os.Getenv("DIGITALOCEAN_SPACES_KEY")
	conn.spacesSecret = os.Getenv("DIGITALOCEAN_SPACES_SECRET")
	conn.spacesRegion = os.Getenv("DIGITALOCEAN_SPACES_REGION")
	conn.spacesClients = map[string]*s3.Client{}

	return conn, nil
}

// SpacesCredentials reports whether the optional Spaces access key /
// secret were provided through environment variables. Resources that
// need S3-compatible API access (e.g., bucket auditing) should bail
// out early with an empty list when this returns false.
func (c *DigitaloceanConnection) SpacesCredentials() (key, secret string, ok bool) {
	if c.spacesKey == "" || c.spacesSecret == "" {
		return "", "", false
	}
	return c.spacesKey, c.spacesSecret, true
}

// SpacesRegion returns the region the user pinned auditing to via
// DIGITALOCEAN_SPACES_REGION, or "" when the caller should iterate
// the known Spaces regions.
func (c *DigitaloceanConnection) SpacesRegion() string {
	return c.spacesRegion
}

// SpacesClient returns (and caches) an S3 client pointed at the
// requested Spaces region. Returns an error when no Spaces
// credentials were supplied.
func (c *DigitaloceanConnection) SpacesClient(region string) (*s3.Client, error) {
	key, secret, ok := c.SpacesCredentials()
	if !ok {
		return nil, errors.New("DIGITALOCEAN_SPACES_KEY and DIGITALOCEAN_SPACES_SECRET must be set to audit Spaces buckets")
	}
	if region == "" {
		return nil, errors.New("region is required to build a Spaces S3 client")
	}

	c.spacesClientsMu.Lock()
	defer c.spacesClientsMu.Unlock()
	if client, ok := c.spacesClients[region]; ok {
		return client, nil
	}

	endpoint := fmt.Sprintf("https://%s.digitaloceanspaces.com", region)
	client := s3.New(s3.Options{
		Region:       region,
		BaseEndpoint: awsv2.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider(key, secret, ""),
		UsePathStyle: false,
	})
	c.spacesClients[region] = client
	return client, nil
}

func (c *DigitaloceanConnection) Name() string {
	return "digitalocean"
}

func (c *DigitaloceanConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *DigitaloceanConnection) Client() *godo.Client {
	return c.client
}
