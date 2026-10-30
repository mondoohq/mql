// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type OciConnection struct {
	plugin.Connection
	Conf        *inventory.Config
	asset       *inventory.Asset
	config      common.ConfigurationProvider
	tenancyOcid string

	// Filters narrows what the scan looks at. Region and compartment filters
	// are applied where the region x compartment fan-out is built, so they
	// affect every lister; tag filters are applied per-lister. See filters.go.
	Filters DiscoveryFilters

	// The compartment tree, resolved once per connection. Every
	// compartment-scoped lister needs the full list to fan out over, and there
	// are a dozen of them, so without this a scan re-walked the paginated
	// ListCompartments for each one. The tree does not change mid-scan, and on
	// a large tenancy those repeats are both slow and a good way to run into
	// Identity rate limits.
	// compartmentIndex is that same list keyed by OCID, built on first use.
	// Nearly every resource in the provider reports the compartment it lives
	// in, so the lookup runs once per resource rather than once per scan; a
	// walk of the list per lookup would be O(resources x compartments).
	// compartmentFetchErr holds the last tree fetch failure, honoured for
	// compartmentFetchRetryAfter so a throttled Identity API is retried a
	// handful of times per scan rather than once per resource. See
	// GetCompartments for why the failure is held briefly instead of forever.
	compartmentLock     sync.Mutex
	compartmentList     []identity.Compartment
	compartmentIndex    map[string]identity.Compartment
	compartmentsDone    bool
	compartmentFetchErr error
	compartmentFetchAt  time.Time

	// The subset of the tree the caller holds INSPECT on, resolved once per
	// connection and only when something asks. It cannot come from the walk
	// above: ListCompartments fills in isAccessible only when it is asked for
	// the accessible subset, and asking for that subset also truncates the
	// listing to it - so a scan cannot both enumerate the whole tree and read
	// the flag from the same call. See AccessibleCompartmentIDs.
	accessibleLock sync.Mutex
	accessibleIDs  map[string]struct{}
	accessibleDone bool

	// Service clients, keyed by "<service>/<region-or-endpoint>". See
	// cachedClient in clients.go for why they are shared rather than rebuilt.
	clients sync.Map
}

func NewOciConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OciConnection, error) {
	conn := &OciConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		Filters:    DiscoveryFiltersFromOpts(conf.Options),
	}

	// initialize your connection here
	var (
		configProvider common.ConfigurationProvider
		err            error
	)
	// if we have passed in credentials, assume we want to pass in all values explicitly.
	if len(conf.Credentials) > 0 {
		fingerprint := conf.Options["fingerprint"]
		if fingerprint == "" {
			return nil, errors.New("OCI provider fingerprint value cannot be empty")
		}
		tenancyOcid := conf.Options["tenancy"]
		if tenancyOcid == "" {
			return nil, errors.New("OCI provider tenancy value cannot be empty")
		}
		userOcid := conf.Options["user"]
		if userOcid == "" {
			return nil, errors.New("OCI provider user value cannot be empty")
		}
		region := conf.Options["region"]
		if region == "" {
			return nil, errors.New("OCI provider region value cannot be empty")
		}

		pkey := conf.Credentials[0]
		if pkey.Type != vault.CredentialType_private_key {
			return nil, errors.New("OCI provider does not support credential type: " + pkey.Type.String())
		}
		// --key-secret is collected by ParseCLI as the credential password and
		// is the passphrase for an encrypted private key. Passing nil here made
		// the documented flag inert, so an encrypted API key failed at connect
		// with an opaque PEM decryption error no matter what the user supplied.
		var passphrase *string
		if pkey.Password != "" {
			passphrase = &pkey.Password
		}
		configProvider = common.NewRawConfigurationProvider(tenancyOcid, userOcid, region, fingerprint, string(pkey.Secret), passphrase)
	} else if authMethod := conf.Options["auth-method"]; usesPrincipalAuth(authMethod) {
		configProvider, err = principalConfigProvider(authMethod, conf.Options["profile"])
		if err != nil {
			return nil, err
		}
	} else {
		profile := conf.Options["profile"]
		configFile := conf.Options["config-file"]
		if profile != "" || configFile != "" {
			if configFile == "" {
				// ConfigurationProviderFromFileWithProfile rejects an empty
				// path outright, so --profile on its own used to fail with
				// "config file path can not be empty" - naming a flag the user
				// never set. Fall back to the SDK's own default location.
				configFile, err = defaultOciConfigPath()
				if err != nil {
					return nil, err
				}
			}
			if profile == "" {
				profile = "DEFAULT"
			}
			configProvider, err = common.ConfigurationProviderFromFileWithProfile(configFile, profile, "")
			if err != nil {
				return nil, err
			}
		} else {
			configProvider = common.DefaultConfigProvider()
		}
	}
	tenancyOcid, err := configProvider.TenancyOCID()
	if err != nil {
		return nil, err
	}

	conn.config = configProvider
	conn.tenancyOcid = tenancyOcid

	return conn, nil
}

func (s *OciConnection) Name() string {
	return "oci"
}

func (s *OciConnection) Asset() *inventory.Asset {
	return s.asset
}
