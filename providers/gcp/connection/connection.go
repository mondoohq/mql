// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"sync"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/gcp/connection/shared"
)

const (
	Gcp shared.ConnectionType = "gcp"
)

type ResourceType int

const (
	Unknown ResourceType = iota
	Project
	Organization
	Folder
	Gcr
	Snapshot
	Instance
)

type GcpConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// Filters narrow discovery to a subset of resources (e.g. specific storage
	// bucket names). Populated from the --filters flag on the connection config.
	Filters DiscoveryFilters

	opts gcpConnectionOptions

	// clientCache and credsCache memoize the HTTP client / credentials per
	// sorted scope set so that the per-asset auth stack (credential parse,
	// token source, HTTP transport) is built once rather than on every API
	// call. Keyed by scopeCacheKey.
	clientCache sync.Map
	credsCache  sync.Map
}

type gcpConnectionOptions struct {
	// custom connection fields
	resourceType ResourceType
	resourceID   string
	// serviceAccountSubject subject is used to impersonate a subject
	serviceAccountSubject string
	cred                  *vault.Credential
	platformOverride      string
}

func NewGcpConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*GcpConnection, error) {
	conn := &GcpConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		opts:       gcpConnectionOptions{},
		Filters:    DiscoveryFiltersFromOpts(conf.GetDiscover().GetFilter()),
	}

	// initialize connection

	var cred *vault.Credential
	if len(conf.Credentials) != 0 {
		cred = conf.Credentials[0]
	}
	if conf.Type == "gcp" {
		if conf.Options == nil ||
			(conf.Options["project-id"] == "" && conf.Options["organization-id"] == "" && conf.Options["folder-id"] == "") {
			return nil, errors.New(
				"google provider requires a gcp organization id, gcp project id or google workspace customer id. " +
					"Please set option `project-id` or `organization-id` or `customer-id` or `folder-id`")
		}
	} else {
		return nil, plugin.ErrProviderTypeDoesNotMatch
	}

	var resourceType ResourceType
	var resourceID string
	if _, ok := conf.Options["repository"]; ok {
		resourceType = Gcr
		resourceID = conf.Options["project-id"]
	} else if conf.Options["organization-id"] != "" {
		resourceType = Organization
		resourceID = conf.Options["organization-id"]
	} else if conf.Options["folder-id"] != "" {
		resourceType = Folder
		resourceID = conf.Options["folder-id"]
	} else if conf.Options["project-id"] != "" {
		resourceType = Project
		resourceID = conf.Options["project-id"]
	} else if conf.Options["snapshot-name"] != "" {
		resourceType = Snapshot
		resourceID = conf.Options["snapshot-name"]
	} else if conf.Options["instance-name"] != "" {
		resourceType = Instance
		resourceID = conf.Options["instance-name"]
	}

	var override string
	if conf.Options != nil {
		override = conf.Options["platform-override"]
	}

	conn.opts.resourceID = resourceID
	conn.opts.resourceType = resourceType
	conn.opts.cred = cred
	conn.opts.platformOverride = override

	return conn, nil
}

func (c *GcpConnection) Hash() uint64 {
	// generate hash of the config options used to generate this connection
	// used to avoid verifying a client with the same options more than once
	hash, err := hashstructure.Hash(c.opts, hashstructure.FormatV2, nil)
	if err != nil {
		log.Error().Err(err).Msg("unable to hash connection")
	}
	return hash
}

func (c *GcpConnection) Verify() error {
	// verify that we have access to the organization or project
	switch c.ResourceType() {
	case Organization:
		_, err := c.GetOrganization(c.ResourceID())
		if err != nil {
			log.Error().Err(err).
				Str("organization", c.ResourceID()).
				Msg("could not find, or have no access to organization")
			return err
		}
	case Project, Gcr:
		_, err := c.GetProject(c.ResourceID())
		if err != nil {
			log.Error().Err(err).
				Str("project", c.ResourceID()).
				Msg("could not find, or have no access to project")
			return err
		}
	}
	return nil
}

func (c *GcpConnection) Name() string {
	return "gcp"
}

func (c *GcpConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *GcpConnection) Type() shared.ConnectionType {
	return Gcp
}

func (c *GcpConnection) Config() *inventory.Config {
	return c.Conf
}
