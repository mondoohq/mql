// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shadowscatcher/shodan"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	DiscoveryAll   = "all"
	DiscoveryAuto  = "auto"
	DiscoveryHosts = "hosts"
)

type ShodanConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *shodan.Client
}

func NewShodanConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*ShodanConnection, error) {
	conn := &ShodanConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// if a secret was provided, it always overrides the env variable since it has precedence
	token := os.Getenv("SHODAN_TOKEN")
	if len(conf.Credentials) > 0 {
		for i := range conf.Credentials {
			cred := conf.Credentials[i]
			if cred.Type == vault.CredentialType_password {
				token = string(cred.Secret)
			} else {
				log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Shodan provider")
			}
		}
	}

	if token == "" {
		return nil, errors.New("a valid Shodan token is required, pass --token '<yourtoken>' or set SHODAN_TOKEN environment variable")
	}

	client, err := shodan.GetClient(token, http.DefaultClient, true)
	if err != nil {
		return nil, err
	}
	conn.client = client

	return conn, nil
}

func (c *ShodanConnection) Name() string {
	return "shodan"
}

func (c *ShodanConnection) Asset() *inventory.Asset {
	return c.asset
}

func (s *ShodanConnection) Client() *shodan.Client {
	return s.client
}

func shodanHostPlatform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "shodan-host",
		Title:                 "Shodan Host",
		Family:                []string{"shodan"},
		Kind:                  "api",
		Runtime:               "shodan",
		TechnologyUrlSegments: []string{"network", "shodan", "host"},
	}
}

func shodanDomainPlatform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "shodan-domain",
		Title:                 "Shodan Domain",
		Family:                []string{"shodan"},
		Kind:                  "api",
		Runtime:               "shodan",
		TechnologyUrlSegments: []string{"network", "shodan", "domain"},
	}
}

func shodanOrgPlatform() *inventory.Platform {
	return &inventory.Platform{
		Name:                  "shodan-org",
		Title:                 "Shodan",
		Family:                []string{"shodan"},
		Kind:                  "api",
		Runtime:               "shodan",
		TechnologyUrlSegments: []string{"network", "shodan", "org"},
	}
}

func (c *ShodanConnection) PlatformInfo() (*inventory.Platform, error) {
	conf := c.asset.Connections[0]

	if conf.Options != nil && conf.Options["search"] != "" {
		search := conf.Options["search"]
		switch search {
		case "host":
			return shodanHostPlatform(), nil
		case "domain":
			return shodanDomainPlatform(), nil
		}
	}
	return shodanOrgPlatform(), nil
}

func (c *ShodanConnection) Identifier() string {
	baseId := "//platformid.api.mondoo.app/runtime/shodan"

	conf := c.asset.Connections[0]
	if conf.Options != nil && conf.Options["search"] != "" {
		search := conf.Options["search"]
		switch search {
		case "host":
			return baseId + "/host/" + strings.ToLower(conf.Host)
		case "domain":
			return baseId + "/domain/" + strings.ToLower(conf.Host)
		}
	}

	// NOTE: the api returns no unique identifier, so if multiple shodan accounts are used, the same id will be returned
	return baseId
}
