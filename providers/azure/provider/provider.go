// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/providers/azure/connection/azureinstancesnapshot"
	"go.mondoo.com/mql/providers/azure/connection/shared"
	"go.mondoo.com/mql/providers/azure/resources"
)

const (
	ConnectionType = "azure"
)

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

// flagBytes safely reads a flag's raw value. Unset flags (including keys the
// CLI never registers, such as the legacy singular "subscription") are absent
// from the map and therefore nil pointers, so a direct .Value dereference
// panics. Returning an empty slice for those keeps ParseCLI robust.
func flagBytes(flags map[string]*llx.Primitive, key string) []byte {
	if p, ok := flags[key]; ok && p != nil {
		return p.Value
	}
	return nil
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.GetFlags()

	tenantId := flagBytes(flags, "tenant-id")
	clientId := flagBytes(flags, "client-id")
	clientSecret := flagBytes(flags, "client-secret")
	certificatePath := flagBytes(flags, "certificate-path")
	certificateSecret := flagBytes(flags, "certificate-secret")
	federatedTokenFile := flagBytes(flags, "federated-token-file")
	authMethod := flagBytes(flags, "auth-method")
	opts := map[string]string{}
	creds := []*vault.Credential{}

	opts["tenant-id"] = string(tenantId)
	opts["client-id"] = string(clientId)
	if len(federatedTokenFile) > 0 {
		opts[connection.OptionFederatedTokenFile] = string(federatedTokenFile)
	}
	if len(authMethod) > 0 {
		opts[connection.OptionAuthMethod] = string(authMethod)
	}
	if len(clientSecret) > 0 {
		creds = append(creds, &vault.Credential{
			Type:   vault.CredentialType_password,
			Secret: clientSecret,
		})
	} else if len(certificatePath) > 0 {
		creds = append(creds, &vault.Credential{
			Type:           vault.CredentialType_pkcs12,
			PrivateKeyPath: string(certificatePath),
			Password:       string(certificateSecret),
		})
	}
	filterOpts := parseFlagsToFiltersOpts(flags)

	// A caller who named exactly one subscription is scoping the whole run to it,
	// so the root asset has to carry it as well.
	//
	// Only discovery ever set subscription-id (getSubConfig, per discovered
	// subscription). The root asset therefore connected with no subscription at
	// all, and every azure.subscription.* query against it failed with the SDK's
	// "parameter subscriptionID cannot be empty" -- one guaranteed broken asset on
	// every scan, whose empty PlatformId ("...:/subscriptions/") is also not
	// unique. Naming several subscriptions stays a discovery-only filter: there is
	// no single subscription to scope the root asset to.
	if id, ok := singleSubscriptionFilter(filterOpts); ok {
		opts[connection.OptionSubscriptionID] = id
	}

	config := &inventory.Config{
		Type:        "azure",
		Discover:    parseDiscover(flags, filterOpts),
		Credentials: creds,
		Options:     opts,
	}

	// handle azure subcommands
	if len(req.Args) >= 3 && req.Args[0] == "compute" {
		err := handleAzureComputeSubcommands(req.Args, config)
		if err != nil {
			return nil, err
		}
	}

	asset := inventory.Asset{
		Connections: []*inventory.Config{config},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

// singleSubscriptionFilter returns the subscription id when the caller scoped the
// run to exactly one, so the root asset can be scoped to it too. A list of
// subscriptions has no single answer and stays a discovery-only filter.
func singleSubscriptionFilter(filterOpts map[string]string) (string, bool) {
	raw, ok := filterOpts["subscriptions"]
	if !ok {
		return "", false
	}
	var ids []string
	for part := range strings.SplitSeq(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) != 1 {
		return "", false
	}
	return ids[0], true
}

func parseDiscover(flags map[string]*llx.Primitive, filterOpts map[string]string) *inventory.Discovery {
	var targets []string
	if x, ok := flags["discover"]; ok && len(x.Array) != 0 {
		targets = make([]string, 0, len(x.Array))
		for i := range x.Array {
			entry := string(x.Array[i].Value)
			targets = append(targets, entry)
		}
	} else {
		targets = []string{resources.DiscoveryAuto}
	}
	return &inventory.Discovery{Targets: targets, Filter: filterOpts}
}

// parseFlagsToFiltersOpts builds the discovery filter options map from both the
// --filters key/value flag and the dedicated --subscription* flags, then stores
// it on inventory.Discovery.Filter (mirroring the AWS provider). The dedicated
// flags take precedence over their --filters counterparts, and the plural
// --subscriptions overrides the singular --subscription (preserving the
// historical precedence). Keys are matched exactly, not by prefix, because
// "subscriptions" is a prefix of "subscriptions-exclude".
func parseFlagsToFiltersOpts(flags map[string]*llx.Primitive) map[string]string {
	o := map[string]string{}

	// base: the --filters key/value flag (allowlisted keys only)
	if x, ok := flags["filters"]; ok && len(x.Map) != 0 {
		for k, v := range x.Map {
			switch {
			case k == "subscriptions" || k == "subscriptions-exclude" || k == "propagate-subscription-tags":
				o[k] = string(v.Value)
			case strings.HasPrefix(k, "subscription-tag:"):
				o[k] = string(v.Value)
			// "tag:" and "exclude:tag:" do not overlap with each other or with
			// "subscription-tag:", so prefix order here does not matter.
			case strings.HasPrefix(k, "tag:") || strings.HasPrefix(k, "exclude:tag:"):
				o[k] = string(v.Value)
			}
		}
	}

	// overlay: dedicated flags win over their --filters counterparts
	if v := flagBytes(flags, "subscription"); len(v) > 0 {
		o["subscriptions"] = string(v)
	}
	if v := flagBytes(flags, "subscriptions"); len(v) > 0 {
		o["subscriptions"] = string(v)
	}
	if v := flagBytes(flags, "subscriptions-exclude"); len(v) > 0 {
		o["subscriptions-exclude"] = string(v)
	}

	return o
}

func handleAzureComputeSubcommands(args []string, config *inventory.Config) error {
	switch args[1] {
	case "instance":
		config.Type = string(azureinstancesnapshot.SnapshotConnectionType)
		config.Discover = nil
		config.Options["type"] = azureinstancesnapshot.InstanceTargetType
		config.Options["target"] = args[2]
		return nil
	case "snapshot":
		config.Type = string(azureinstancesnapshot.SnapshotConnectionType)
		config.Options["type"] = azureinstancesnapshot.SnapshotTargetType
		config.Options["target"] = args[2]
		config.Discover = nil
		return nil
	case "disk":
		config.Type = string(azureinstancesnapshot.SnapshotConnectionType)
		config.Options["type"] = azureinstancesnapshot.DiskTargetType
		config.Options["target"] = args[2]
		config.Discover = nil
		return nil
	default:
		return errors.New("unknown subcommand " + args[1])
	}
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	// We only need to run the detection step when we don't have any asset information yet.
	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	// discovery assets for further scanning
	inventory, err := s.discover(conn)
	if err != nil {
		return nil, err
	}

	return &plugin.ConnectRes{
		Id:        uint32(conn.ID()),
		Name:      conn.Name(),
		Asset:     req.Asset,
		Inventory: inventory,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (shared.AzureConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]

	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		var conn shared.AzureConnection
		var err error

		switch conf.Type {
		case string(azureinstancesnapshot.SnapshotConnectionType):
			// An AzureSnapshotConnection is a wrapper around a FilesystemConnection
			// To make sure the connection is later handled by the os provider, override the type
			conf.Type = "filesystem"
			conn, err = azureinstancesnapshot.NewAzureSnapshotConnection(connId, conf, asset)
		default:
			conn, err = connection.NewAzureConnection(connId, asset, conf)
		}
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				return nil, err
			}
		}

		asset.Connections[0].Id = conn.ID()
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(shared.AzureConnection), nil
}

// detect gives the root asset -- the one the caller connected as, before any
// discovery -- the identity a discovered subscription gets from subToAsset.
//
// It used to be a bare `return nil`, so that asset reached the client with no
// platform, no name, and no platform id: every Azure scan carried one blank
// entry, and `--discover none` produced nothing but the blank entry. The
// resources were queryable the whole time, because the connection knows which
// subscription it is on; only the asset's own identity was missing.
//
// A connection with no subscription is left alone deliberately. That is the
// caller who named several subscriptions or none, where discovery enumerates
// them and there is no single subscription for the root asset to be.
func (s *Service) detect(asset *inventory.Asset, conn shared.AzureConnection) error {
	azureConn, ok := conn.(*connection.AzureConnection)
	if !ok {
		// A snapshot connection is handed to the os provider, which detects it.
		return nil
	}

	subID := azureConn.SubId()
	if subID == "" {
		return nil
	}

	var tenantID string
	if conf := azureConn.Config(); conf != nil {
		tenantID = conf.Options[connection.OptionTenantID]
	}

	// The record is cached on the connection, so discovery and the
	// azure.subscription resource reuse this fetch rather than paying their
	// own GET. Logged rather than returned on failure: ARM omits parts of the
	// record for deleted, disabled, and cross-tenant subscriptions, and a scan
	// must not fail because the asset could only be named by its id.
	var displayName string
	if sub, err := azureConn.Subscription(); err == nil {
		if sub.DisplayName != nil {
			displayName = *sub.DisplayName
		}
		if tenantID == "" && sub.TenantID != nil {
			tenantID = *sub.TenantID
		}
	} else {
		log.Debug().Err(err).Msg("could not read the subscription to name the asset")
	}

	applyAzureSubscriptionIdentity(asset, subID, tenantID, azureConn.PlatformId(), displayName)
	return nil
}

// applyAzureSubscriptionIdentity stamps a subscription's identity onto an asset,
// in the shape subToAsset gives a discovered subscription, so the same
// subscription reads the same whichever way it arrived.
//
// displayName may be empty, in which case the id names the asset. That is also
// what subToAsset does for a subscription whose displayName ARM omits, and it is
// the right outcome here too: a scan should not fail because the asset could only
// be named by its id.
func applyAzureSubscriptionIdentity(asset *inventory.Asset, subID, tenantID, platformID, displayName string) {
	if tenantID == "" {
		tenantID = "unknown"
	}

	platform := &inventory.Platform{
		TechnologyUrlSegments: []string{"azure", tenantID, subID, "account"},
	}
	resources.PlatformByName("azure").Apply(platform)

	asset.Platform = platform
	// Platform ids that arrived with the asset came from whoever built it,
	// often the key an integration resolves the asset by, so they are kept.
	// The connection's own id still has to be present for the client to
	// recognize the discovered duplicate of this subscription.
	if !slices.Contains(asset.PlatformIds, platformID) {
		asset.PlatformIds = append(asset.PlatformIds, platformID)
	}
	if asset.Id == "" {
		asset.Id = platformID
	}
	if asset.Labels == nil {
		asset.Labels = map[string]string{}
	}
	if _, ok := asset.Labels[resources.SubscriptionLabel]; !ok {
		asset.Labels[resources.SubscriptionLabel] = subID
	}

	// Only name an asset that has no name. A caller who passed --asset-name
	// has already named this asset, and detect running afterwards must not
	// take that back; the sibling fields above guard for the same reason.
	if asset.Name == "" {
		if displayName == "" {
			displayName = subID
		}
		asset.Name = "Azure subscription " + displayName
	}
}

func (s *Service) discover(conn shared.AzureConnection) (*inventory.Inventory, error) {
	if conn.Config().Discover == nil {
		return nil, nil
	}

	if len(conn.Config().Discover.Targets) == 0 {
		return nil, nil
	}

	runtime, err := s.GetRuntime(conn.ID())
	if err != nil {
		return nil, err
	}

	return resources.Discover(runtime, conn.Config())
}
