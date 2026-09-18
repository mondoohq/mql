// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armresources "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v4"
	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/utils/stringx"
)

const (
	SubscriptionLabel  = "azure.mondoo.com/subscription"
	ResourceGroupLabel = "azure.mondoo.com/resourcegroup"

	LocationLabel = "mondoo.com/location"
	InstanceLabel = "mondoo.com/instance"

	DiscoveryAuto          = "auto"
	DiscoveryAll           = "all"
	DiscoverySubscriptions = "subscriptions"
	DiscoveryInstances     = "instances"
	// TODO: this probably needs some more work on the linking to its OS counterpart side
	DiscoveryInstancesApi            = "instances-api"
	DiscoverySqlServers              = "sql-servers"
	DiscoveryPostgresFlexibleServers = "postgres-flexible-servers"
	DiscoveryMySqlFlexibleServers    = "mysql-flexible-servers"
	DiscoveryAksClusters             = "aks-clusters"
	DiscoveryAppServiceApps          = "app-service-webapps"
	DiscoveryCacheRedis              = "cache-redis-instances"
	DiscoveryBatchAccounts           = "batch-accounts"
	DiscoveryStorageAccounts         = "storage-accounts"
	DiscoveryStorageContainers       = "storage-containers"
	DiscoveryKeyVaults               = "keyvaults-vaults"
	DiscoveryManagedHsms             = "keyvaults-managed-hsms"
	DiscoveryIotHubs                 = "iot-hubs"
	DiscoverySecurityGroups          = "security-groups"
	DiscoveryCosmosDb                = "cosmosdb"
	DiscoveryVirtualNetworks         = "virtual-networks"
	DiscoveryContainerRegistries     = "container-registries"
	DiscoveryRecoveryServicesVaults  = "recovery-services-vaults"
	DiscoverySynapseWorkspaces       = "synapse-workspaces"
	DiscoveryDataFactories           = "data-factories"
	DiscoveryFunctionApps            = "function-apps"
	DiscoveryApplicationGateways     = "application-gateways"
	DiscoveryFirewalls               = "firewalls"
	DiscoveryContainerApps           = "container-apps"
	DiscoveryCognitiveServices       = "cognitiveservices-accounts"

	// optionBuiltByTenantStage marks a connection config that stage 1 of staged
	// discovery built for a subscription, meaning stage 1 has already read that
	// subscription's record and acted on it.
	//
	// Stage 2 runs from two places: a subscription asset stage 1 emitted, and a
	// root connection the caller scoped to one subscription on the command
	// line. Two things follow from which of the two it is. Stage 1 emits the
	// subscription asset, so stage 2 has to emit it itself when stage 1 never
	// ran, or the run silently loses it -- the legacy path emits it either way.
	// And stage 1 resolves the subscription's tags from the listing it already
	// paid for, so when it ran, whatever it did not hand over genuinely is not
	// there and stage 2 has no reason to ask ARM again.
	optionBuiltByTenantStage = "azure-tenant-stage"
)

// Auto includes all API resources except storage containers (which require
// additional permissions and can be very numerous) and virtual machines, which
// have to be asked for explicitly. Defined in terms of AllAPIResources so the
// two lists don't drift apart.
var Auto = append(
	[]string{DiscoverySubscriptions},
	slices.DeleteFunc(slices.Clone(AllAPIResources), func(s string) bool {
		return s == DiscoveryStorageContainers || s == DiscoveryInstancesApi
	})...,
)

// All includes every discovery target: Auto plus OS-level instance discovery,
// virtual machines and storage containers.
var All = append(
	slices.Clone(Auto),
	// DiscoveryInstances, note: we disable this for now since we dont support policies for this. we support the API version (DiscoveryInstancesApi)
	DiscoveryInstancesApi,
	DiscoveryStorageContainers,
)

var AllAPIResources = []string{
	DiscoveryInstancesApi,
	DiscoverySqlServers,
	DiscoveryPostgresFlexibleServers,
	DiscoveryMySqlFlexibleServers,
	DiscoveryAksClusters,
	DiscoveryAppServiceApps,
	DiscoveryCacheRedis,
	DiscoveryBatchAccounts,
	DiscoveryStorageAccounts,
	DiscoveryStorageContainers,
	DiscoveryKeyVaults,
	DiscoveryManagedHsms,
	DiscoveryIotHubs,
	DiscoverySecurityGroups,
	DiscoveryCosmosDb,
	DiscoveryVirtualNetworks,
	DiscoveryContainerRegistries,
	DiscoveryRecoveryServicesVaults,
	DiscoverySynapseWorkspaces,
	DiscoveryDataFactories,
	DiscoveryFunctionApps,
	DiscoveryApplicationGateways,
	DiscoveryFirewalls,
	DiscoveryContainerApps,
	DiscoveryCognitiveServices,
}

// genericDiscoverySpec maps an ARM resource type to the discovery metadata
// needed to build an inventory asset. Resources listed here are discovered via
// a single armresources.Client.NewListPager call per subscription instead of
// individual service-specific API calls.
//
// When multiple specs share the same `armType` (e.g. function apps and web
// apps both live under "Microsoft.Web/sites"), `matchKind` distinguishes
// between them based on the resource's `kind` value returned by ARM.
type genericDiscoverySpec struct {
	armType                string                 // ARM resource type, e.g. "Microsoft.Sql/servers"
	discoveryTarget        string                 // discovery constant, e.g. DiscoverySqlServers
	service                string                 // service label for azureObject
	objectType             string                 // objectType label for azureObject
	includeObjectTypeInUrl bool                   // passed to mqlObjectToAsset
	matchKind              func(kind string) bool // optional: only match resources whose kind matches
}

// isFunctionAppKind reports whether an ARM "Microsoft.Web/sites" resource is
// a Function App. Function app kinds are "functionapp", "functionapp,linux",
// "functionapp,linux,container", "functionapp,workflowapp", etc.
func isFunctionAppKind(kind string) bool {
	return strings.Contains(strings.ToLower(kind), "functionapp")
}

// isWebAppKind reports whether an ARM "Microsoft.Web/sites" resource is a
// regular web/API app (i.e., not a function app). Web app kinds include
// "app", "app,linux", "api", etc. Anything containing "functionapp" is
// routed to function-app discovery instead.
func isWebAppKind(kind string) bool {
	return !isFunctionAppKind(kind)
}

var genericDiscoverySpecs = []genericDiscoverySpec{
	{armType: "Microsoft.Sql/servers", discoveryTarget: DiscoverySqlServers, service: "sql", objectType: "server"},
	{armType: "Microsoft.DBforMySQL/flexibleServers", discoveryTarget: DiscoveryMySqlFlexibleServers, service: "mysql", objectType: "flexible-server"},
	{armType: "Microsoft.DBforPostgreSQL/flexibleServers", discoveryTarget: DiscoveryPostgresFlexibleServers, service: "postgresql", objectType: "flexible-server"},
	{armType: "Microsoft.ContainerService/managedClusters", discoveryTarget: DiscoveryAksClusters, service: "aks", objectType: "cluster"},
	// Microsoft.Web/sites is shared by web apps and function apps; disambiguate by kind.
	{armType: "Microsoft.Web/sites", discoveryTarget: DiscoveryAppServiceApps, service: "app-service", objectType: "app", matchKind: isWebAppKind},
	{armType: "Microsoft.Web/sites", discoveryTarget: DiscoveryFunctionApps, service: "functions", objectType: "app", matchKind: isFunctionAppKind},
	{armType: "Microsoft.Cache/Redis", discoveryTarget: DiscoveryCacheRedis, service: "cache", objectType: "redis"},
	{armType: "Microsoft.Batch/batchAccounts", discoveryTarget: DiscoveryBatchAccounts, service: "batch", objectType: "account"},
	{armType: "Microsoft.Storage/storageAccounts", discoveryTarget: DiscoveryStorageAccounts, service: "storage", objectType: "account", includeObjectTypeInUrl: true},
	{armType: "Microsoft.Network/networkSecurityGroups", discoveryTarget: DiscoverySecurityGroups, service: "network", objectType: "security-group", includeObjectTypeInUrl: true},
	{armType: "Microsoft.Network/applicationGateways", discoveryTarget: DiscoveryApplicationGateways, service: "network", objectType: "application-gateway", includeObjectTypeInUrl: true},
	{armType: "Microsoft.Network/azureFirewalls", discoveryTarget: DiscoveryFirewalls, service: "network", objectType: "firewall", includeObjectTypeInUrl: true},
	{armType: "Microsoft.KeyVault/vaults", discoveryTarget: DiscoveryKeyVaults, service: "keyvault", objectType: "vault"},
	{armType: "Microsoft.KeyVault/managedHSMs", discoveryTarget: DiscoveryManagedHsms, service: "keyvault", objectType: "managed-hsm"},
	{armType: "Microsoft.Devices/IotHubs", discoveryTarget: DiscoveryIotHubs, service: "iot", objectType: "iothub"},
	{armType: "Microsoft.DocumentDB/databaseAccounts", discoveryTarget: DiscoveryCosmosDb, service: "cosmosdb", objectType: "account"},
	{armType: "Microsoft.Network/virtualNetworks", discoveryTarget: DiscoveryVirtualNetworks, service: "network", objectType: "virtual-network", includeObjectTypeInUrl: true},
	{armType: "Microsoft.ContainerRegistry/registries", discoveryTarget: DiscoveryContainerRegistries, service: "containerregistry", objectType: "registry"},
	{armType: "Microsoft.RecoveryServices/vaults", discoveryTarget: DiscoveryRecoveryServicesVaults, service: "recoveryservices", objectType: "vault"},
	{armType: "Microsoft.Synapse/workspaces", discoveryTarget: DiscoverySynapseWorkspaces, service: "synapse", objectType: "workspace"},
	{armType: "Microsoft.DataFactory/factories", discoveryTarget: DiscoveryDataFactories, service: "datafactory", objectType: "factory"},
	{armType: "Microsoft.App/containerApps", discoveryTarget: DiscoveryContainerApps, service: "containerapps", objectType: "app"},
	{armType: "Microsoft.CognitiveServices/accounts", discoveryTarget: DiscoveryCognitiveServices, service: "cognitiveservices", objectType: "account"},
}

type azureObject struct {
	subscription string
	tenant       *string
	id           string
	location     string
	service      string
	objectType   string
}

type azureObjectPlatformInfo struct {
	title    string
	platform string
}

type mqlObject struct {
	name        string
	labels      map[string]string
	azureObject azureObject
}

type subWithConfig struct {
	sub  subscriptions.Subscription
	conf *inventory.Config
	// assetOpts are applied when conf is cloned for each asset discovered
	// inside this subscription. Stage 2 of staged discovery uses it to point
	// every one of them at the subscription's connection, so they share a
	// single MQL resource cache instead of each rebuilding their own.
	assetOpts []inventory.CloneOption
}

func MondooAzureInstanceID(instanceID string) string {
	return "//platformid.api.mondoo.app/runtime/azure" + strings.ToLower(instanceID)
}

// retiredDiscoveryTargets maps a discovery target for an Azure service that is
// past retirement to the target that replaces it. Azure retired MySQL Single
// Server on 2024-09-16 and PostgreSQL Single Server on 2025-03-28, so no
// subscription holds one any more and nothing is left to discover. The names
// stay accepted so an inventory that still lists them keeps working, but they
// match no resource, and a target that matches nothing looks exactly like a
// successful scan of an empty estate. Warn instead of discovering silently.
//
// FIXME: DEPRECATED, remove in v15.0 vv
var retiredDiscoveryTargets = map[string]string{
	"mysql-servers":    DiscoveryMySqlFlexibleServers,
	"postgres-servers": DiscoveryPostgresFlexibleServers,
}

func warnRetiredDiscoveryTargets(targets []string) {
	for _, t := range targets {
		if replacement, ok := retiredDiscoveryTargets[t]; ok {
			log.Warn().
				Str("target", t).
				Str("replacement", replacement).
				Msg("this Azure service is retired and no longer discoverable, nothing will be discovered for this target")
		}
	}
}

// ^^

func getDiscoveryTargets(config *inventory.Config) []string {
	targets := config.Discover.Targets
	warnRetiredDiscoveryTargets(targets)
	if len(targets) == 0 {
		return Auto
	}
	if stringx.ContainsAnyOf(targets, DiscoveryAll) {
		// return all discovery targets
		return All
	}
	if stringx.ContainsAnyOf(targets, DiscoveryAuto) {
		// Cloned first: DeleteFunc edits the backing array in place, so
		// operating on config.Discover.Targets directly rewrites the caller's
		// config. That was invisible while this was read once per scan, but
		// staged discovery reads it at the tenant level and then clones the
		// same config for every subscription, so the damage propagated: the
		// root's targets came back as [""], every subscription inherited that,
		// and stage 2 matched no target and discovered nothing. A tenant scan
		// found its subscriptions and not one resource under them.
		//
		// (DeleteFunc handles every occurrence; mutating the slice inside a
		// range loop would skip elements after a deletion.)
		rest := slices.DeleteFunc(slices.Clone(targets), func(s string) bool { return s == DiscoveryAuto })
		// add in the required discovery targets
		return append(rest, Auto...)
	}
	// random assortment of targets
	return targets
}

// Discover routes to the appropriate discovery path based on whether the client
// has opted in to staged discovery via plugin.OptionStagedDiscovery.
//
// TODO(v15): remove discoverLegacy and the OptionStagedDiscovery toggle. Staged
// discovery should be the only path.
func Discover(runtime *plugin.Runtime, rootConf *inventory.Config) (*inventory.Inventory, error) {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	switch stage, subId := discoveryStageFor(rootConf); stage {
	case stageSubscription:
		return discoverSubscriptionStage(runtime, conn, rootConf, subId)
	case stageTenant:
		return discoverTenantStage(conn, rootConf)
	default:
		return discoverLegacy(runtime, conn, rootConf)
	}
}

// discoveryStage names the discovery path a connection takes.
type discoveryStage int

const (
	// stageLegacy is the single-pass path taken by clients that have not opted
	// in to staged discovery.
	stageLegacy discoveryStage = iota
	// stageTenant is stage 1: discover the subscriptions, nothing inside them.
	stageTenant
	// stageSubscription is stage 2: discover the resources of one subscription.
	stageSubscription
)

// discoveryStageFor decides which discovery path a connection config takes, and
// for stage 2 returns the subscription it is scoped to.
//
// A staged connection that already names a subscription has no tenant level
// left to walk, so it goes straight to stage 2. That covers both the
// subscription assets stage 1 emits and a caller who scoped the whole run to
// one subscription on the command line.
func discoveryStageFor(cfg *inventory.Config) (discoveryStage, string) {
	if _, staged := cfg.GetOptions()[plugin.OptionStagedDiscovery]; !staged {
		return stageLegacy, ""
	}
	if subId := cfg.GetOptions()[connection.OptionSubscriptionID]; subId != "" {
		return stageSubscription, subId
	}
	return stageTenant, ""
}

// discoverLegacy is the original single-pass discovery: every subscription and
// every resource inside all of them, enumerated in one call and attached to the
// connection that started the scan. Kept for clients that do not set
// plugin.OptionStagedDiscovery.
//
// TODO(v15): remove once all supported clients set the flag.
func discoverLegacy(runtime *plugin.Runtime, conn *connection.AzureConnection, rootConf *inventory.Config) (*inventory.Inventory, error) {
	assets := []*inventory.Asset{}
	filter := conn.Filters.Subscriptions
	// note: we always need the subscriptions, either to return them as assets or discover resources inside the subs
	subs, err := discoverSubscriptions(conn, filter)
	if err != nil {
		return nil, err
	}

	subsWithConfigs := make([]subWithConfig, len(subs))
	for i := range subs {
		sub := subs[i]
		subsWithConfigs[i] = subWithConfig{
			sub:  sub,
			conf: getSubConfig(conn.Conf, sub, inventory.WithoutDiscovery()),
			// No parent connection: on this path every discovered asset gets a
			// runtime and a resource cache of its own, and re-fetches whatever
			// it needs. That is the cost staged discovery exists to remove.
			assetOpts: []inventory.CloneOption{inventory.WithoutDiscovery()},
		}
	}

	targets := getDiscoveryTargets(rootConf)
	log.Debug().
		Int("subscriptions", len(subsWithConfigs)).
		Strs("targets", targets).
		Msg("azure.discovery> starting discovery")

	if stringx.ContainsAnyOf(targets, DiscoverySubscriptions) {
		// we've already discovered those, simply add them as assets
		for _, s := range subsWithConfigs {
			assets = append(assets, subToAsset(s, inventory.WithoutDiscovery()))
		}
	}

	assets = append(assets, discoverResources(runtime, conn, subsWithConfigs, targets)...)

	if conn.Filters.PropagateSubscriptionTags {
		applySubscriptionTags(conn.Filters.SubscriptionTags, subsWithConfigs, assets)
	}

	log.Debug().Int("assets", len(assets)).Msg("azure.discovery> discovery complete")
	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: assets,
		},
	}, nil
}

// discoverTenantStage is stage 1 of staged discovery: it discovers the
// subscriptions this credential can see and emits one asset per subscription,
// each carrying the connection config that runs stage 2 when the client
// connects to it. No resources are listed here.
//
// The subscription configs deliberately do not name a parent connection. Each
// subscription gets its own runtime and its own MQL resource cache, so closing
// a subscription releases everything discovered beneath it -- and, just as
// importantly, one subscription's cached azure.subscription.* resources can
// never be handed to an asset in another subscription. Several azure resources
// read the subscription from the connection rather than from their own id
// (azure.subscription itself among them), so a cache shared across
// subscriptions would answer with the wrong one rather than fail.
func discoverTenantStage(conn *connection.AzureConnection, rootConf *inventory.Config) (*inventory.Inventory, error) {
	subs, err := discoverSubscriptions(conn, conn.Filters.Subscriptions)
	if err != nil {
		return nil, err
	}

	targets := getDiscoveryTargets(rootConf)
	log.Debug().
		Int("subscriptions", len(subs)).
		Strs("targets", targets).
		Msg("azure.discovery> stage 1: discovering subscriptions")

	subsWithConfigs, assets := tenantStageAssets(rootConf, subs, targets, conn.Filters)

	if conn.Filters.PropagateSubscriptionTags {
		applySubscriptionTags(conn.Filters.SubscriptionTags, subsWithConfigs, assets)
	}

	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: assets,
		},
	}, nil
}

// tenantStageAssets turns the subscriptions stage 1 discovered into the assets
// it emits, along with the carriers the tag propagation needs.
//
// Each subscription's config is cloned without WithoutDiscovery on purpose: the
// discovery targets it carries are what make stage 2 run when the client
// connects to it. A subscription is only worth scanning in its own right when
// the caller asked for subscriptions -- when it is not a target it is still
// emitted, so that the client connects to it and stage 2 runs, but stripping
// its platform ids keeps the scanner from treating it as an asset to scan.
func tenantStageAssets(rootConf *inventory.Config, subs []subscriptions.Subscription, targets []string, filters connection.DiscoveryFilters) ([]subWithConfig, []*inventory.Asset) {
	scannable := stringx.ContainsAnyOf(targets, DiscoverySubscriptions)
	// The subscription list already returned each subscription's tags. Hand
	// them to stage 2 through the config rather than leaving it to ask ARM for
	// a record it would only read the tags off -- that would be one GET per
	// subscription for data this stage is holding. A caller-supplied override
	// means the tags are not ours to decide, so it is left alone.
	carryTags := filters.PropagateSubscriptionTags && len(filters.SubscriptionTags) == 0

	subsWithConfigs := make([]subWithConfig, len(subs))
	assets := make([]*inventory.Asset, 0, len(subs))
	for i := range subs {
		conf := getSubConfig(rootConf, subs[i])
		conf.Options[optionBuiltByTenantStage] = "true"
		if carryTags {
			carrySubscriptionTags(conf, subs[i])
		}
		subsWithConfigs[i] = subWithConfig{sub: subs[i], conf: conf}
		asset := subToAsset(subsWithConfigs[i])
		if !scannable {
			asset.PlatformIds = nil
		}
		assets = append(assets, asset)
	}
	return subsWithConfigs, assets
}

// builtByTenantStage reports whether stage 1 built this connection config, and
// so has already emitted the subscription as an asset and resolved its tags.
func builtByTenantStage(cfg *inventory.Config) bool {
	_, ok := cfg.GetOptions()[optionBuiltByTenantStage]
	return ok
}

// carrySubscriptionTags writes a subscription's ARM tags onto the config stage 2
// will connect with, in the same form the --filters flag uses, so stage 2 reads
// them off conn.Filters.SubscriptionTags like any other override.
func carrySubscriptionTags(cfg *inventory.Config, sub subscriptions.Subscription) {
	if len(sub.Tags) == 0 {
		return
	}
	if cfg.Discover == nil {
		cfg.Discover = &inventory.Discovery{}
	}
	if cfg.Discover.Filter == nil {
		cfg.Discover.Filter = map[string]string{}
	}
	for k, v := range sub.Tags {
		if k == "" || v == nil || *v == "" {
			continue
		}
		cfg.Discover.Filter[connection.SubscriptionTagFilterPrefix+k] = *v
	}
}

// discoverSubscriptionStage is stage 2 of staged discovery: it lists the
// resources inside one subscription. It runs when the client connects to a
// subscription asset emitted by stage 1, or when the caller scoped the whole
// run to a single subscription.
//
// Every asset it emits names this connection as its parent, so the plugin
// service hands them all the subscription runtime's resource cache. That is
// what stops a subscription-wide read -- the app service list, a web app's
// slots and site config, a VM's instance view -- from being re-fetched once per
// asset: the first asset to ask pays for it and the rest read the cached
// resource. All of it is released when the subscription is closed.
func discoverSubscriptionStage(runtime *plugin.Runtime, conn *connection.AzureConnection, invConfig *inventory.Config, subId string) (*inventory.Inventory, error) {
	targets := getDiscoveryTargets(invConfig)
	log.Debug().
		Str("subscription", subId).
		Strs("targets", targets).
		Msg("azure.discovery> stage 2: discovering resources in subscription")

	// When the caller scoped the run to one subscription there was no stage 1,
	// so nothing has emitted the subscription itself yet and this stage has to.
	// That needs its display name, which the connection options do not carry.
	fromTenantStage := builtByTenantStage(invConfig)
	emitSubscription := !fromTenantStage && stringx.ContainsAnyOf(targets, DiscoverySubscriptions)
	// Stage 1 hands over the tags it read from the subscription listing, so
	// after it ran an empty set means the subscription has no tags -- not that
	// they are still to be fetched. Asking ARM here would be one GET per
	// subscription for something already known.
	needsTags := !fromTenantStage &&
		conn.Filters.PropagateSubscriptionTags && len(conn.Filters.SubscriptionTags) == 0

	swc := subWithConfig{
		sub:  subscriptionRecord(conn, invConfig, subId, emitSubscription || needsTags),
		conf: invConfig,
		assetOpts: []inventory.CloneOption{
			// These are leaves: nothing below them to discover.
			inventory.WithoutDiscovery(),
			inventory.WithParentConnectionId(invConfig.Id),
		},
	}
	subsWithConfigs := []subWithConfig{swc}

	assets := []*inventory.Asset{}
	if emitSubscription {
		assets = append(assets, subToAsset(swc, inventory.WithoutDiscovery()))
	}
	assets = append(assets, discoverResources(runtime, conn, subsWithConfigs, targets)...)

	if conn.Filters.PropagateSubscriptionTags {
		applySubscriptionTags(conn.Filters.SubscriptionTags, subsWithConfigs, assets)
	}

	log.Debug().
		Str("subscription", subId).
		Int("assets", len(assets)).
		Msg("azure.discovery> stage 2 complete")
	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: assets,
		},
	}, nil
}

// subscriptionRecord rebuilds the subscription a stage-2 connection is scoped
// to. The ids come from the connection options stage 1 wrote, which is all the
// resource listing needs, so the common case costs no API call.
//
// full asks ARM for the rest of the record, for the two callers that need a
// field the options do not carry: the display name of a subscription asset this
// stage has to emit itself, and the tags when they are being propagated and no
// override supplied them. A failure there costs those fields, not the
// discovery.
func subscriptionRecord(conn *connection.AzureConnection, invConfig *inventory.Config, subId string, full bool) subscriptions.Subscription {
	sub := subscriptions.Subscription{SubscriptionID: &subId}
	if tenantId := invConfig.Options[connection.OptionTenantID]; tenantId != "" {
		sub.TenantID = &tenantId
	}
	if !full {
		return sub
	}

	record, err := fetchSubscriptionRecord(conn, subId)
	if err != nil {
		log.Warn().Err(err).Str("subscription", subId).
			Msg("could not read the subscription record, discovering without its name and tags")
		return sub
	}
	return record
}

// fetchSubscriptionRecord reads one subscription's ARM record, through the
// connection's cache when the connection is scoped to that same subscription --
// which is every stage-2 call today, so asset detection's fetch is reused
// rather than repeated.
func fetchSubscriptionRecord(conn *connection.AzureConnection, subId string) (subscriptions.Subscription, error) {
	if conn.SubId() == subId {
		return conn.Subscription()
	}
	return connection.NewSubscriptionsClient(conn.Token(), conn.ClientOptions()).GetSubscription(subId)
}

// discoverResources lists the assets inside the given subscriptions for every
// active discovery target. Shared by the legacy single-pass path, which passes
// every subscription in the tenant, and by stage 2 of staged discovery, which
// passes exactly one.
func discoverResources(runtime *plugin.Runtime, conn *connection.AzureConnection, subsWithConfigs []subWithConfig, targets []string) []*inventory.Asset {
	assets := []*inventory.Asset{}

	// A failure in one discovery target must not zero the whole inventory. The
	// compute path in particular has no access-denied degrade of its own, so a
	// subscription the caller cannot read VMs in would otherwise take down
	// discovery of every other resource type with it.
	discover := func(target string, fn func() ([]*inventory.Asset, error)) {
		found, err := fn()
		if err != nil {
			log.Warn().Err(err).Str("target", target).Msg("could not discover azure assets for target, skipping")
			return
		}
		assets = append(assets, found...)
	}

	// FIXME: do not discover instances as OSes right now, only discover as API representations.
	if stringx.ContainsAnyOf(targets, DiscoveryInstances) {
		discover(DiscoveryInstances, func() ([]*inventory.Asset, error) {
			return discoverInstances(runtime, subsWithConfigs, conn.Filters.General)
		})
	}
	if stringx.ContainsAnyOf(targets, DiscoveryInstancesApi) {
		discover(DiscoveryInstancesApi, func() ([]*inventory.Asset, error) {
			return discoverInstancesApi(runtime, subsWithConfigs, conn.Filters.General)
		})
	}
	// FIXME: bring back the storage containers as as part of FF scanning once we can do parallel scanning
	if stringx.ContainsAnyOf(targets, DiscoveryStorageContainers) {
		discover(DiscoveryStorageContainers, func() ([]*inventory.Asset, error) {
			return discoverStorageAccountsContainers(runtime, subsWithConfigs, conn.Filters.General)
		})
	}

	// Discover all other resource types via a single ARM generic list call per
	// subscription, replacing 13 individual service-specific API calls.
	discover("generic", func() ([]*inventory.Asset, error) {
		return discoverGeneric(conn, subsWithConfigs, targets)
	})

	return assets
}

func discoverInstancesApi(runtime *plugin.Runtime, subsWithConfigs []subWithConfig, filters connection.GeneralDiscoveryFilters) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.computeService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		computeSvc := svc.(*mqlAzureSubscriptionComputeService)
		vms := computeSvc.GetVms()
		if vms.Error != nil {
			return nil, vms.Error
		}
		for _, v := range vms.Data {
			vm := v.(*mqlAzureSubscriptionComputeServiceVm)
			props := vm.GetProperties()
			if props.Error != nil {
				return nil, props.Error
			}
			tags := interfaceMapToStr(vm.Tags.Data)
			if filters.IsFilteredOutByTags(tags) {
				continue
			}
			asset := mqlObjectToAsset(mqlObject{
				name:   vm.Name.Data,
				labels: tags,
				azureObject: azureObject{
					id:           vm.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     vm.Location.Data,
					service:      "compute",
					objectType:   "vm-api",
				},
			}, subWithConfig.conf, false, subWithConfig.assetOpts...)
			labels, err := getInstancesLabels(vm)
			if err != nil {
				return nil, err
			}
			enrichWithLabels(asset, labels)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverInstances(runtime *plugin.Runtime, subsWithConfigs []subWithConfig, filters connection.GeneralDiscoveryFilters) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.computeService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		computeSvc := svc.(*mqlAzureSubscriptionComputeService)
		vms := computeSvc.GetVms()
		if vms.Error != nil {
			return nil, vms.Error
		}
		for _, v := range vms.Data {
			vm := v.(*mqlAzureSubscriptionComputeServiceVm)
			props := vm.GetProperties()
			if props.Error != nil {
				return nil, props.Error
			}

			tags := interfaceMapToStr(vm.Tags.Data)
			if filters.IsFilteredOutByTags(tags) {
				continue
			}

			ipAddresses := vm.GetPublicIpAddresses()
			if ipAddresses.Error != nil {
				return nil, ipAddresses.Error
			}
			asset := mqlObjectToAsset(mqlObject{
				name:   vm.Name.Data,
				labels: tags,
				azureObject: azureObject{
					id:           vm.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     vm.Location.Data,
					service:      "compute",
					objectType:   "vm",
				},
			}, subWithConfig.conf, false, subWithConfig.assetOpts...)
			for _, ip := range ipAddresses.Data {
				ipAddress := ip.(*mqlAzureSubscriptionNetworkServiceIpAddress)
				// TODO: we need to make this work via another provider maybe?
				// this is the OS representation of the VM itself
				asset.Connections = append(asset.Connections, &inventory.Config{
					Type:     "ssh",
					Host:     ipAddress.IpAddress.Data,
					Insecure: true,
				})
			}
			labels, err := getInstancesLabels(vm)
			if err != nil {
				return nil, err
			}
			enrichWithLabels(asset, labels)
			asset.PlatformIds = []string{MondooAzureInstanceID(vm.Id.Data)}
			asset.Platform.Runtime = "azure"
			asset.Platform.Kind = inventory.AssetKindCloudVM
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

// discoverGeneric uses a single ARM resource list call per subscription to
// discover all resource types that only need name/id/location/tags. This
// replaces 13 individual service-specific API calls.
func discoverGeneric(conn *connection.AzureConnection, subsWithConfigs []subWithConfig, targets []string) ([]*inventory.Asset, error) {
	// Filter to only specs whose discovery target is active.
	var activeSpecs []genericDiscoverySpec
	for _, spec := range genericDiscoverySpecs {
		if stringx.ContainsAnyOf(targets, spec.discoveryTarget) {
			activeSpecs = append(activeSpecs, spec)
		}
	}
	if len(activeSpecs) == 0 {
		return nil, nil
	}

	// Build OR filter on the de-duplicated set of ARM types (multiple specs may
	// share an armType when disambiguated by `kind`).
	seenTypes := make(map[string]struct{}, len(activeSpecs))
	clauses := make([]string, 0, len(activeSpecs))
	for _, s := range activeSpecs {
		key := strings.ToLower(s.armType)
		if _, ok := seenTypes[key]; ok {
			continue
		}
		seenTypes[key] = struct{}{}
		clauses = append(clauses, fmt.Sprintf("resourceType eq '%s'", s.armType))
	}
	filter := strings.Join(clauses, " or ")

	// Group specs by lowercase ARM type to allow kind-based dispatch.
	specsByType := make(map[string][]genericDiscoverySpec, len(activeSpecs))
	for _, s := range activeSpecs {
		key := strings.ToLower(s.armType)
		specsByType[key] = append(specsByType[key], s)
	}

	var assets []*inventory.Asset
	for _, swc := range subsWithConfigs {
		subId := *swc.sub.SubscriptionID
		log.Debug().Str("subscription", subId).Str("filter", filter).Msg("azure.discovery> listing resources in subscription")
		client, err := armresources.NewClient(subId, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			return nil, err
		}

		pager := client.NewListPager(&armresources.ClientListOptions{
			Filter: &filter,
		})
		for pager.More() {
			page, err := pager.NextPage(context.Background())
			if err != nil {
				// One inaccessible or disabled subscription must not zero the
				// inventory for every other subscription in the tenant.
				log.Warn().Err(err).Str("subscription", subId).Msg("could not list azure resources in subscription, skipping")
				break
			}
			for _, resource := range page.Value {
				if resource == nil {
					continue
				}
				resType := strings.ToLower(derefStr(resource.Type))
				kind := derefStr(resource.Kind)
				spec, ok := matchSpec(specsByType[resType], kind)
				if !ok {
					continue
				}
				tags := convert.PtrMapStrToStr(resource.Tags)
				if conn.Filters.General.IsFilteredOutByTags(tags) {
					continue
				}
				asset := mqlObjectToAsset(mqlObject{
					name:   derefStr(resource.Name),
					labels: tags,
					azureObject: azureObject{
						id:           derefStr(resource.ID),
						subscription: subId,
						tenant:       swc.sub.TenantID,
						location:     derefStr(resource.Location),
						service:      spec.service,
						objectType:   spec.objectType,
					},
				}, swc.conf, spec.includeObjectTypeInUrl, swc.assetOpts...)
				if asset != nil {
					assets = append(assets, asset)
				}
			}
		}
	}
	return assets, nil
}

// matchSpec picks the first spec from the candidates list whose matchKind
// accepts the given resource kind. Specs without a matchKind match anything.
func matchSpec(candidates []genericDiscoverySpec, kind string) (genericDiscoverySpec, bool) {
	for _, s := range candidates {
		if s.matchKind == nil || s.matchKind(kind) {
			return s, true
		}
	}
	return genericDiscoverySpec{}, false
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func discoverStorageAccountsContainers(runtime *plugin.Runtime, subsWithConfig []subWithConfig, filters connection.GeneralDiscoveryFilters) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfig {
		svc, err := NewResource(runtime, "azure.subscription.storageService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		storageSvc := svc.(*mqlAzureSubscriptionStorageService)
		accounts := storageSvc.GetAccounts()
		if accounts.Error != nil {
			return nil, accounts.Error
		}
		for _, account := range accounts.Data {
			a := account.(*mqlAzureSubscriptionStorageServiceAccount)
			// Blob containers carry no ARM tags of their own, so the tag filter
			// is applied to the storage account they live in. Skipping the
			// account also skips the container listing it would have cost.
			if filters.IsFilteredOutByTags(interfaceMapToStr(a.Tags.Data)) {
				continue
			}
			containers := a.GetContainers()
			if containers.Error != nil {
				return nil, containers.Error
			}
			for _, container := range containers.Data {
				c := container.(*mqlAzureSubscriptionStorageServiceAccountContainer)
				asset := mqlObjectToAsset(mqlObject{
					name:   c.Name.Data,
					labels: map[string]string{},
					azureObject: azureObject{
						id:           c.Id.Data,
						subscription: *subWithConfig.sub.SubscriptionID,
						tenant:       subWithConfig.sub.TenantID,
						location:     a.Location.Data,
						service:      "storage",
						objectType:   "container",
					},
				}, subWithConfig.conf, true, subWithConfig.assetOpts...)
				assets = append(assets, asset)
			}
		}
	}
	return assets, nil
}

func AzureObjectPlatformId(id string) string {
	// the azure resources have an unique id (even throughout multiple subscriptions), e.g.
	// /subscriptions/f1a2873a-6b27-4097-aa7c-3df51f103e96/resourceGroups/MS365-CIS/providers/Microsoft.Compute/virtualMachines/ms365-windows
	// that should be enough for an unique platform id
	return "//platformid.api.mondoo.app/runtime/azure/v1" + id
}

func enrichWithLabels(a *inventory.Asset, labels map[string]string) {
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	for k, v := range labels {
		a.Labels[k] = v
	}
}

func getInstancesLabels(vm *mqlAzureSubscriptionComputeServiceVm) (map[string]string, error) {
	labels := map[string]string{}
	props := vm.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}

	propsDict, ok := props.Data.(map[string]any)
	if !ok {
		propsDict = map[string]any{}
	}
	if osProfile, ok := propsDict["osProfile"]; ok {
		if osProfileDict, ok := osProfile.(map[string]any); ok {
			if computerName, ok := osProfileDict["computerName"]; ok {
				if name, ok := computerName.(string); ok {
					labels["azure.mondoo.com/computername"] = name
				}
			}
		}
	}
	if storageProfile, ok := propsDict["storageProfile"]; ok {
		if storageProfile, ok := storageProfile.(map[string]any); ok {
			if osDisk, ok := storageProfile["osDisk"]; ok {
				if osDisk, ok := osDisk.(map[string]any); ok {
					if osType, ok := osDisk["osType"]; ok {
						if t, ok := osType.(string); ok {
							labels["azure.mondoo.com/ostype"] = t
						}
					}
				}
			}
		}
	}
	if vmId, ok := propsDict["vmId"]; ok {
		if id, ok := vmId.(string); ok {
			labels["mondoo.com/instance"] = id
		}
	}

	res, err := ParseResourceID(vm.Id.Data)
	if err != nil {
		return nil, err
	}
	labels["azure.mondoo.com/resourcegroup"] = res.ResourceGroup

	return labels, nil
}

func discoverSubscriptions(conn *connection.AzureConnection, filter connection.SubscriptionsFilter) ([]subscriptions.Subscription, error) {
	subsClient := connection.NewSubscriptionsClient(conn.Token(), conn.ClientOptions())
	subs, err := subsClient.GetSubscriptions(filter)
	if err != nil {
		return nil, err
	}
	if len(subs) == 0 {
		return nil, errors.New("cannot find an azure subscription with the provided credentials or the provided filters")
	}

	return subs, nil
}

// subToAsset builds the asset for a subscription. cloneOpts are passed to
// Clone: the legacy path strips discovery from the result, while stage 1 of
// staged discovery keeps it, because the targets on a subscription's config are
// what make stage 2 run when the client connects to it.
func subToAsset(subWithConfig subWithConfig, cloneOpts ...inventory.CloneOption) *inventory.Asset {
	sub := subWithConfig.sub
	conf := subWithConfig.conf
	copyConf := conf.Clone(cloneOpts...)
	platformId := "//platformid.api.mondoo.app/runtime/azure/subscriptions/" + convert.ToValue(sub.SubscriptionID)
	tenantId := "unknown"
	if sub.TenantID != nil {
		tenantId = *sub.TenantID
	}
	// ARM omits displayName for subscriptions in some states -- deleted,
	// disabled, and cross-tenant entries projected in by Lighthouse. The
	// neighbouring TenantID is guarded for the same reason; this one was not, so
	// one such subscription in a tenant panicked the whole scan before any asset
	// was returned. Fall back to the id, which is always present here.
	subID := convert.ToValue(sub.SubscriptionID)
	displayName := subID
	if sub.DisplayName != nil {
		displayName = *sub.DisplayName
	}
	platform := &inventory.Platform{
		TechnologyUrlSegments: []string{"azure", tenantId, subID, "account"},
	}
	PlatformByName("azure").Apply(platform)
	return &inventory.Asset{
		Id:          platformId,
		Platform:    platform,
		Name:        fmt.Sprintf("Azure subscription %s", displayName),
		Connections: []*inventory.Config{copyConf},
		PlatformIds: []string{platformId},
		Labels:      map[string]string{SubscriptionLabel: subID},
	}
}

// propagateSubscriptionTagsToAssets merges subscriptionTags into every asset in
// the slice. An asset's own labels take precedence, so subscription tags only
// fill in keys the asset doesn't already define. Mirrors GCP's
// propagateProjectLabelsToAssets.
func propagateSubscriptionTagsToAssets(assets []*inventory.Asset, subscriptionTags map[string]string) {
	if len(subscriptionTags) == 0 {
		return
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		for k, v := range subscriptionTags {
			if _, exists := a.Labels[k]; !exists {
				a.Labels[k] = v
			}
		}
	}
}

// assetsForSubscription returns the assets whose SubscriptionLabel matches subID.
func assetsForSubscription(assets []*inventory.Asset, subID string) []*inventory.Asset {
	res := []*inventory.Asset{}
	for _, a := range assets {
		if a != nil && a.Labels[SubscriptionLabel] == subID {
			res = append(res, a)
		}
	}
	return res
}

// applySubscriptionTags merges each subscription's tags into the assets
// discovered within it. Tags come from the injected override when provided,
// otherwise from the subscription record returned by the list pager — which
// already includes the tags, so no per-subscription API call is needed.
func applySubscriptionTags(override map[string]string, subs []subWithConfig, assets []*inventory.Asset) {
	for _, s := range subs {
		if s.sub.SubscriptionID == nil {
			continue
		}
		subID := *s.sub.SubscriptionID

		tags := override
		if len(tags) == 0 {
			tags = convert.PtrMapStrToStr(s.sub.Tags)
		}
		if len(tags) == 0 {
			continue
		}

		propagateSubscriptionTagsToAssets(assetsForSubscription(assets, subID), tags)
	}
}

// creates a config with filled in subscription and tenant id, this config can be used by the subscription asset
// or any assets that are discovered within that subscription.
//
// cloneOpts are passed straight to Clone. Stage 1 of staged discovery passes
// none, keeping the discovery targets that make stage 2 run; the legacy path
// passes WithoutDiscovery, because nothing below a subscription discovers
// anything further on that path.
func getSubConfig(rootConf *inventory.Config, sub subscriptions.Subscription, cloneOpts ...inventory.CloneOption) *inventory.Config {
	cfg := rootConf.Clone(cloneOpts...)
	if cfg.Options == nil {
		cfg.Options = map[string]string{}
	}
	cfg.Options[connection.OptionSubscriptionID] = *sub.SubscriptionID
	if sub.TenantID != nil {
		cfg.Options[connection.OptionTenantID] = *sub.TenantID
	}
	return cfg
}

func getTitleFamily(azureObject azureObject) (azureObjectPlatformInfo, error) {
	switch azureObject.service {
	case "compute":
		if azureObject.objectType == "vm" {
			return azureObjectPlatformInfo{title: "Azure Compute VM", platform: "azure-compute-vm"}, nil
		}
		if azureObject.objectType == "vm-api" {
			return azureObjectPlatformInfo{title: "Azure Compute VM", platform: "azure-compute-vm-api"}, nil
		}
	case "sql":
		if azureObject.objectType == "server" {
			return azureObjectPlatformInfo{title: "Azure SQL Database Server", platform: "azure-sql-server"}, nil
		}
	case "postgresql":
		if azureObject.objectType == "flexible-server" {
			return azureObjectPlatformInfo{title: "Azure PostgreSQL Flexible Server", platform: "azure-postgresql-flexible-server"}, nil
		}
	case "mysql":
		if azureObject.objectType == "flexible-server" {
			return azureObjectPlatformInfo{title: "Azure MySQL Flexible Server", platform: "azure-mysql-flexible-server"}, nil
		}
	case "aks":
		if azureObject.objectType == "cluster" {
			return azureObjectPlatformInfo{title: "Azure AKS Cluster", platform: "azure-aks-cluster"}, nil
		}
	case "app-service":
		if azureObject.objectType == "app" {
			return azureObjectPlatformInfo{title: "Azure App Service App", platform: "azure-app-service-webapp"}, nil
		}
	case "cache":
		if azureObject.objectType == "redis" {
			return azureObjectPlatformInfo{title: "Azure Cache for Redis Instance", platform: "azure-cache-redis-instance"}, nil
		}
	case "batch":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Batch Account", platform: "azure-batch-account"}, nil
		}
	case "storage":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Storage Account", platform: "azure-storage-account"}, nil
		}
		if azureObject.objectType == "container" {
			return azureObjectPlatformInfo{title: "Azure Storage Account Container", platform: "azure-storage-container"}, nil
		}
	case "network":
		if azureObject.objectType == "security-group" {
			return azureObjectPlatformInfo{title: "Azure Network Security Group", platform: "azure-network-security-group"}, nil
		}
		if azureObject.objectType == "virtual-network" {
			return azureObjectPlatformInfo{title: "Azure Virtual Network", platform: "azure-virtual-network"}, nil
		}
		if azureObject.objectType == "application-gateway" {
			return azureObjectPlatformInfo{title: "Azure Application Gateway", platform: "azure-application-gateway"}, nil
		}
		if azureObject.objectType == "firewall" {
			return azureObjectPlatformInfo{title: "Azure Firewall", platform: "azure-firewall"}, nil
		}
	case "functions":
		if azureObject.objectType == "app" {
			return azureObjectPlatformInfo{title: "Azure Function App", platform: "azure-function-app"}, nil
		}
	case "containerapps":
		if azureObject.objectType == "app" {
			return azureObjectPlatformInfo{title: "Azure Container App", platform: "azure-container-app"}, nil
		}
	case "keyvault":
		if azureObject.objectType == "vault" {
			return azureObjectPlatformInfo{title: "Azure Key Vault", platform: "azure-keyvault-vault"}, nil
		}
		if azureObject.objectType == "managed-hsm" {
			return azureObjectPlatformInfo{title: "Azure Key Vault Managed HSM", platform: "azure-keyvault-managedhsm"}, nil
		}
	case "iot":
		if azureObject.objectType == "iothub" {
			return azureObjectPlatformInfo{title: "Azure IoT Hub", platform: "azure-iot-iothub"}, nil
		}
	case "cosmosdb":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Cosmos DB Account", platform: "azure-cosmosdb"}, nil
		}
	case "containerregistry":
		if azureObject.objectType == "registry" {
			return azureObjectPlatformInfo{title: "Azure Container Registry", platform: "azure-container-registry"}, nil
		}
	case "recoveryservices":
		if azureObject.objectType == "vault" {
			return azureObjectPlatformInfo{title: "Azure Recovery Services Vault", platform: "azure-recovery-services-vault"}, nil
		}
	case "synapse":
		if azureObject.objectType == "workspace" {
			return azureObjectPlatformInfo{title: "Azure Synapse Analytics Workspace", platform: "azure-synapse-workspace"}, nil
		}
	case "datafactory":
		if azureObject.objectType == "factory" {
			return azureObjectPlatformInfo{title: "Azure Data Factory", platform: "azure-datafactory"}, nil
		}
	case "cognitiveservices":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure AI Services Account", platform: "azure-cognitiveservices-account"}, nil
		}
	}
	return azureObjectPlatformInfo{}, fmt.Errorf("missing runtime info for azure object service %s type %s", azureObject.service, azureObject.objectType)
}

// mqlObjectToAsset builds the asset for a single discovered azure resource.
// cloneOpts are passed to Clone; callers hand it the owning subscription's
// assetOpts, which always strip discovery and, under staged discovery, also
// name the subscription connection as the parent so the asset shares its
// resource cache.
func mqlObjectToAsset(mqlObject mqlObject, parentConf *inventory.Config, includeObjectTypeInUrl bool, cloneOpts ...inventory.CloneOption) *inventory.Asset {
	if mqlObject.name == "" {
		mqlObject.name = mqlObject.azureObject.id
	}
	info, err := getTitleFamily(mqlObject.azureObject)
	if err != nil {
		return nil
	}
	platformid := AzureObjectPlatformId(mqlObject.azureObject.id)
	cfg := parentConf.Clone(cloneOpts...)
	cfg.PlatformId = platformid

	tenantId := "unknown"
	if mqlObject.azureObject.tenant != nil {
		tenantId = *mqlObject.azureObject.tenant
	}

	assetUrl := []string{
		"azure", tenantId, mqlObject.azureObject.subscription,
		mqlObject.azureObject.service,
	}
	if includeObjectTypeInUrl {
		assetUrl = append(assetUrl, mqlObject.azureObject.objectType)
	}
	platform := &inventory.Platform{
		TechnologyUrlSegments: assetUrl,
	}
	PlatformByName(info.platform).Apply(platform)
	return &inventory.Asset{
		PlatformIds: []string{platformid, mqlObject.azureObject.id},
		Name:        mqlObject.name,
		Platform:    platform,
		State:       inventory.State_STATE_ONLINE,
		Labels:      addInformationalLabels(mqlObject.labels, mqlObject),
		Connections: []*inventory.Config{cfg},
	}
}

func addInformationalLabels(l map[string]string, o mqlObject) map[string]string {
	if l == nil {
		l = make(map[string]string)
	}
	l[LocationLabel] = o.azureObject.location
	l[SubscriptionLabel] = o.azureObject.subscription
	resourceID, err := ParseResourceID(o.azureObject.id)
	if err == nil {
		l[ResourceGroupLabel] = resourceID.ResourceGroup
	}
	return l
}

func interfaceMapToStr(m map[string]any) map[string]string {
	res := make(map[string]string)
	for k, v := range m {
		if str, ok := v.(string); ok {
			res[k] = str
		}
	}
	return res
}
