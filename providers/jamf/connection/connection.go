// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type JamfConnection struct {
	plugin.Connection
	Conf   *inventory.Config
	asset  *inventory.Asset
	Client *jamfpro.Client

	// localUserAccounts caches per-computer local user accounts from the
	// initial inventory fetch, keyed by computer ID. This avoids N+1 API
	// calls when iterating computerInventory then accessing localUserAccounts.
	localUserAccountsMu sync.RWMutex
	localUserAccounts   map[string][]jamfpro.ComputerInventorySubsetLocalUserAccount
}

func NewJamfConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*JamfConnection, error) {
	conn := &JamfConnection{
		Connection:        plugin.NewConnection(id, asset),
		Conf:              conf,
		asset:             asset,
		localUserAccounts: make(map[string][]jamfpro.ComputerInventorySubsetLocalUserAccount),
	}

	// Extract credentials and options from conf
	var clientID, clientSecret, instanceDomain string
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			clientID = cred.User
			clientSecret = string(cred.Secret)
		}
	}
	if domain, ok := conf.Options["instance_domain"]; ok {
		instanceDomain = domain
	}

	// Validate that all necessary credentials are provided
	var missing []string
	if instanceDomain == "" {
		missing = append(missing, "instance_domain")
	}
	if clientID == "" {
		missing = append(missing, "client_id")
	}
	if clientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if len(missing) > 0 {
		return nil, errors.New("missing required Jamf credentials: " + strings.Join(missing, ", "))
	}

	// Create the configuration container
	config := &jamfpro.ConfigContainer{
		LogLevel:       "warn",
		InstanceDomain: instanceDomain,
		AuthMethod:     "oauth2",
		ClientID:       clientID,
		ClientSecret:   clientSecret,
	}

	// Initialize the Jamf Pro client with the given configuration
	client, err := jamfpro.BuildClient(config)
	if err != nil {
		return nil, err
	}
	conn.Client = client
	log.Debug().Msg("jamf> client initialized")

	return conn, nil
}

func (j *JamfConnection) Name() string {
	return "jamf"
}

func (j *JamfConnection) Asset() *inventory.Asset {
	return j.asset
}

func (j *JamfConnection) PlatformInfo() (*inventory.Platform, error) {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"api", "jamf"},
	}
	PlatformByName("jamf").Apply(p)
	return p, nil
}

func (j *JamfConnection) Identifier() string {
	domain := j.Conf.Options["instance_domain"]
	if i := strings.Index(domain, "://"); i >= 0 {
		domain = domain[i+3:]
	}
	if i := strings.IndexAny(domain, "/?#"); i >= 0 {
		domain = domain[:i]
	}
	return "//platformid.api.mondoo.app/runtime/jamf/" + strings.ToLower(domain)
}

// CacheLocalUserAccounts stores local user accounts for a computer ID,
// populated during the initial inventory fetch.
func (j *JamfConnection) CacheLocalUserAccounts(computerID string, accounts []jamfpro.ComputerInventorySubsetLocalUserAccount) {
	j.localUserAccountsMu.Lock()
	defer j.localUserAccountsMu.Unlock()
	j.localUserAccounts[computerID] = accounts
}

// GetCachedLocalUserAccounts retrieves cached local user accounts for a
// computer ID. Returns nil, false if no cache entry exists.
func (j *JamfConnection) GetCachedLocalUserAccounts(computerID string) ([]jamfpro.ComputerInventorySubsetLocalUserAccount, bool) {
	j.localUserAccountsMu.RLock()
	defer j.localUserAccountsMu.RUnlock()
	accounts, ok := j.localUserAccounts[computerID]
	return accounts, ok
}
