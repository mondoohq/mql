// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/azauth"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/azure/connection/shared"
)

const (
	OptionTenantID           = "tenant-id"
	OptionClientID           = "client-id"
	OptionDataReport         = "mondoo-ms365-datareport"
	OptionSubscriptionID     = "subscription-id"
	OptionPlatformOverride   = "platform-override"
	OptionFederatedTokenFile = "azure-federated-token-file"
	// OptionAuthMethod names the sign-in method(s) to use when no client secret
	// or certificate is supplied, as a comma-separated list of
	// azauth.CredentialMethod values. Unset means try all of them.
	OptionAuthMethod = "auth-method"
)

type AzureConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset
	token azcore.TokenCredential
	// note: in the future, we might make this optional if we have a tenant-level asset.
	subscriptionId string
	clientOptions  policy.ClientOptions
	// Filters holds the parsed discovery filters (from inventory.Discovery.Filter).
	Filters DiscoveryFilters

	// The ARM record of the subscription this connection is scoped to, fetched
	// once and shared through Subscription.
	subMu     sync.Mutex
	subRecord *subscriptions.Subscription
}

// The credentials this process has built, by the identity each signs in as.
//
// Each discovered asset gets its own connection, and a credential built per
// connection carries its own token cache, so a scan asked Entra for a fresh
// token once per asset for an identity that already had a perfectly good one.
// Discovery found these assets with this credential; it can scan them with it
// too.
//
// Keyed by identity rather than shared outright because an inventory can hold
// Azure assets under several tenants, and handing tenant A's token to tenant B's
// asset would not fail cleanly -- it would scan as the wrong principal. Every
// identity gets the same reuse, so an inventory spanning tenants is one
// credential per tenant rather than one per asset.
//
// The map is bounded by the number of identities a process scans, which is the
// number of Azure assets in its inventory, not the number of assets discovered
// beneath them.
var (
	credentialMu    sync.Mutex
	credentialCache = map[string]azcore.TokenCredential{}
)

// selectAzureCredential chooses the appropriate Azure token credential based on
// the connection configuration. When a federated token file is provided (via
// option or env var) and no explicit vault credential is present, it returns a
// WorkloadIdentityCredential for keyless auth. Otherwise it falls through to
// the standard cert/secret/default-chain path.
//
// The default chain is the expensive branch: it probes every sign-in method in
// turn. A caller that knows how it authenticates can say so with
// OptionAuthMethod and skip straight to the method that works.
func selectAzureCredential(conf *inventory.Config) (azcore.TokenCredential, error) {
	tenantId := conf.Options[OptionTenantID]
	clientId := conf.Options[OptionClientID]

	// parsed before the cache is consulted: an unusable auth-method is an error
	// for the connection that names it, whether or not this identity already has
	// a credential someone else built
	methods, err := azauth.ParseCredentialMethods(conf.Options[OptionAuthMethod])
	if err != nil {
		return nil, err
	}

	var cred *vault.Credential
	if len(conf.Credentials) > 0 {
		cred = conf.Credentials[0]
	}

	// held across the build, which is local -- constructing a credential
	// contacts nothing -- so concurrent connects queue briefly rather than
	// each building a chain of their own
	//
	// The Azure CLI signs in with the account and tenant that hold the
	// connection's subscription (azauth.ChainedTokenOptions.Subscription).
	// Under a tenant option every subscription is in that tenant, so they share
	// a credential; without one, each subscription can be in another tenant,
	// so it is part of the identity.
	subscriptionId := conf.Options[OptionSubscriptionID]
	identity := tenantId + "/" + clientId
	if tenantId == "" {
		identity += "/" + subscriptionId
	}
	credentialMu.Lock()
	defer credentialMu.Unlock()
	if cached, ok := credentialCache[identity]; ok {
		log.Debug().
			Str("tenant-id", tenantId).
			Str("client-id", clientId).
			Msg("azure: reusing cached credential")
		return cached, nil
	}

	federatedTokenFile := conf.Options[OptionFederatedTokenFile]
	if federatedTokenFile == "" {
		federatedTokenFile = os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	}

	// A token file with no method selection used to shortcut straight to a bare
	// workload identity credential here, on the grounds that there was nothing
	// left to probe. It cost more than it saved: the shortcut logged nothing, so
	// a connection that authenticated this way was invisible and the only
	// sign-ins in the logs were the ones configured some other way -- and the
	// credential it returned had no chain behind it, so a stale token file was
	// the end of the road rather than a fall back to the remaining methods.
	//
	// The chain is cheap to walk now that the managed identity probe sits at the
	// end of it (see azauth.DefaultCredentialMethods), so there is nothing left
	// to shortcut past.
	token, err := azauth.GetTokenFromCredential(cred, &azauth.ChainedTokenOptions{
		TenantID:           tenantId,
		ClientID:           clientId,
		Subscription:       subscriptionId,
		FederatedTokenFile: federatedTokenFile,
		Methods:            methods,
		Source:             "azure-connection",
	})
	if err != nil {
		// a failed build is not worth remembering: the next connection may be
		// configured differently, and caching the failure would deny it its own try
		return nil, err
	}

	credentialCache[identity] = token
	return token, nil
}

func NewAzureConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AzureConnection, error) {
	subId := conf.Options[OptionSubscriptionID]

	token, err := selectAzureCredential(conf)
	if err != nil {
		return nil, errors.Wrap(err, "cannot fetch credentials for microsoft provider")
	}
	return &AzureConnection{
		Connection:     plugin.NewConnection(id, asset),
		Conf:           conf,
		asset:          asset,
		token:          token,
		subscriptionId: subId,
		clientOptions: policy.ClientOptions{
			PerCallPolicies: []policy.Policy{&apiTracePolicy{}},
		},
		Filters: DiscoveryFiltersFromOpts(conf.GetDiscover().GetFilter()),
	}, nil
}

func (h *AzureConnection) Name() string {
	return "azure"
}

func (p *AzureConnection) Asset() *inventory.Asset {
	return p.asset
}

func (p *AzureConnection) SubId() string {
	return p.subscriptionId
}

// Subscription returns the ARM record of the subscription this connection is
// scoped to, fetched once and cached for the connection's lifetime. Asset
// detection, discovery, and the azure.subscription resource all read the same
// record; without the cache each of them pays its own GET.
//
// A failed fetch is not cached: the next caller gets its own try, the same way
// credentialCache treats a failed credential build.
func (p *AzureConnection) Subscription() (subscriptions.Subscription, error) {
	if p.subscriptionId == "" {
		return subscriptions.Subscription{}, errors.New("connection is not scoped to a subscription")
	}

	p.subMu.Lock()
	defer p.subMu.Unlock()
	if p.subRecord != nil {
		return *p.subRecord, nil
	}

	record, err := NewSubscriptionsClient(p.token, p.clientOptions).GetSubscription(p.subscriptionId)
	if err != nil {
		return subscriptions.Subscription{}, err
	}
	p.subRecord = &record
	return record, nil
}

func (p *AzureConnection) Token() azcore.TokenCredential {
	return p.token
}

func (p *AzureConnection) PlatformId() string {
	return "//platformid.api.mondoo.app/runtime/azure/subscriptions/" + p.subscriptionId
}

func (p *AzureConnection) ClientOptions() policy.ClientOptions {
	return p.clientOptions
}

func (p *AzureConnection) Config() *inventory.Config {
	return p.Conf
}

func (p *AzureConnection) Type() shared.ConnectionType {
	return "azure"
}

// apiTracePolicy is an Azure SDK pipeline policy that logs every HTTP request
// with its method, URL, status code, and duration at Debug level.
type apiTracePolicy struct{}

func (p *apiTracePolicy) Do(req *policy.Request) (*http.Response, error) {
	start := time.Now()
	rawReq := req.Raw()

	resp, err := req.Next()

	elapsed := time.Since(start)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	log.Debug().
		Str("method", rawReq.Method).
		// host+path only: the query string can carry SAS tokens or other
		// signed-URL credentials that must not leak into debug logs.
		Str("url", rawReq.URL.Host+rawReq.URL.Path).
		Int("status", status).
		Dur("duration", elapsed).
		Err(err).
		Msg("azure api call")

	return resp, err
}
