// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// wifPoolHostsProviders reports whether a pool's Mode lets it host
// user-defined providers. Per the GCP IAM API, an unspecified mode is treated
// as FEDERATION_ONLY; TRUST_DOMAIN and SYSTEM_TRUST_DOMAIN pools (e.g. GKE's
// `*.svc.id.goog` pool) reject ListWorkloadIdentityPoolProviders.
func wifPoolHostsProviders(mode string) bool {
	return mode == "" || mode == "MODE_UNSPECIFIED" || mode == "FEDERATION_ONLY"
}

func (g *mqlGcpProjectIamService) workloadIdentityPools() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	// iam.CloudPlatformScope, not the cloud-platform.read-only variant the rest
	// of this provider defaults to: the IAM API lists cloud-platform as the only
	// accepted scope for the workload-identity and workforce pool methods, and a
	// read-only token is rejected with ACCESS_TOKEN_SCOPE_INSUFFICIENT before
	// any IAM permission is consulted -- so no amount of role granting fixes it.
	client, err := conn.Client(iam.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iamSvc, err := iam.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("projects/%s/locations/global", projectId)
	var pools []any
	err = iamSvc.Projects.Locations.WorkloadIdentityPools.List(parent).
		ShowDeleted(true).
		Pages(ctx, func(resp *iam.ListWorkloadIdentityPoolsResponse) error {
			for _, p := range resp.WorkloadIdentityPools {
				trust := wifPoolTrustConfig(p.InlineTrustConfig)
				issuance := wifPoolCertIssuance(p.InlineCertificateIssuanceConfig)
				mqlPool, err := CreateResource(g.MqlRuntime, "gcp.project.iamService.workloadIdentityPool",
					map[string]*llx.RawData{
						"projectId":   llx.StringData(projectId),
						"name":        llx.StringData(p.Name),
						"poolId":      llx.StringData(lastSegment(p.Name)),
						"displayName": llx.StringData(p.DisplayName),
						"description": llx.StringData(p.Description),
						"state":       llx.StringData(p.State),
						"disabled":    llx.BoolData(p.Disabled),
						"expireTime":  llx.TimeDataPtr(parseTime(p.ExpireTime)),
						"mode":        llx.StringData(p.Mode),

						"additionalTrustDomains":                 llx.ArrayData(trust.domains, types.String),
						"additionalTrustAnchorCount":             llx.IntData(trust.anchorCount),
						"certificateIssuanceCaPools":             llx.MapData(issuance.caPools, types.String),
						"certificateIssuanceUsesDefaultSharedCa": llx.BoolData(issuance.usesDefaultSharedCa),
					})
				if err != nil {
					return err
				}
				pools = append(pools, mqlPool)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return pools, nil
}

// wifPoolTrust is the flattened additional-trust configuration of a pool.
type wifPoolTrust struct {
	domains     []any
	anchorCount int64
}

// wifPoolTrustConfig flattens the additional trust bundles a pool configures on
// top of its own trust domain.
//
// Domains are sorted because the API returns them in a map, and an unordered
// field would compare unequal to itself between two reads of the same pool.
//
// Only TrustAnchors are counted. A trust anchor is what a presented chain is
// validated up to, and the API documents its own IntermediateCas set as
// material for building a chain to an anchor, so an intermediate is unusable
// unless some anchor already covers it. Counting both would overstate how many
// independent authorities the pool trusts. Note the anchor list itself may hold
// an intermediate certificate being used as an anchor, which is still one
// independent authority and is counted as one.
//
// A nil config means no additional bundle is configured, which is genuinely an
// empty set rather than an unread value, so it yields an empty list and 0.
func wifPoolTrustConfig(cfg *iam.InlineTrustConfig) wifPoolTrust {
	out := wifPoolTrust{domains: []any{}}
	if cfg == nil {
		return out
	}
	names := make([]string, 0, len(cfg.AdditionalTrustBundles))
	for domain, store := range cfg.AdditionalTrustBundles {
		if domain == "" {
			continue
		}
		names = append(names, domain)
		out.anchorCount += int64(len(store.TrustAnchors))
	}
	sort.Strings(names)
	for _, n := range names {
		out.domains = append(out.domains, n)
	}
	return out
}

// wifPoolCertIssuance is the flattened mTLS workload-certificate issuance
// configuration of a pool.
type wifPoolCertIssuanceConfig struct {
	caPools             map[string]any
	usesDefaultSharedCa bool
}

// wifPoolCertIssuance flattens which certificate authorities may mint mTLS
// workload certificates for the pool.
//
// A nil config means the pool issues no workload certificates, so it names no
// authorities and does not use the shared one.
func wifPoolCertIssuance(cfg *iam.InlineCertificateIssuanceConfig) wifPoolCertIssuanceConfig {
	if cfg == nil {
		return wifPoolCertIssuanceConfig{caPools: map[string]any{}}
	}
	return wifPoolCertIssuanceConfig{
		caPools:             convert.MapToInterfaceMap(cfg.CaPools),
		usesDefaultSharedCa: cfg.UseDefaultSharedCa,
	}
}

func (g *mqlGcpProjectIamServiceWorkloadIdentityPool) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectIamServiceWorkloadIdentityPool) providers() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	poolName := g.Name.Data
	if poolName == "" {
		return nil, errors.New("workload identity pool has no name")
	}
	if g.Mode.Error != nil {
		return nil, g.Mode.Error
	}
	if g.State.Error != nil {
		return nil, g.State.Error
	}
	// Skip the list call for pools the API will reject anyway:
	// - non-ACTIVE pools (DELETED pools 404 on the providers list);
	// - TRUST_DOMAIN / SYSTEM_TRUST_DOMAIN pools (e.g. GKE's `*.svc.id.goog`
	//   pool), which 400 with "RPC Method ... is not supported on resource".
	if g.State.Data != "" && g.State.Data != "ACTIVE" {
		g.Providers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if !wifPoolHostsProviders(g.Mode.Data) {
		g.Providers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.PoolId.Error != nil {
		return nil, g.PoolId.Error
	}
	poolId := g.PoolId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	// iam.CloudPlatformScope, not the cloud-platform.read-only variant the rest
	// of this provider defaults to: the IAM API lists cloud-platform as the only
	// accepted scope for the workload-identity and workforce pool methods, and a
	// read-only token is rejected with ACCESS_TOKEN_SCOPE_INSUFFICIENT before
	// any IAM permission is consulted -- so no amount of role granting fixes it.
	client, err := conn.Client(iam.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	iamSvc, err := iam.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var providers []any
	byName := map[string]*mqlGcpProjectIamServiceWorkloadIdentityPoolProvider{}
	err = iamSvc.Projects.Locations.WorkloadIdentityPools.Providers.List(poolName).
		ShowDeleted(true).
		Pages(ctx, func(resp *iam.ListWorkloadIdentityPoolProvidersResponse) error {
			for _, p := range resp.WorkloadIdentityPoolProviders {
				providerType, awsAccountId, oidcIssuer, oidcAudiences, samlMetadata, x509TrustAnchorCount := flattenWifProviderConfig(p)
				var oidcDiscoveryUri string
				if p.Oidc != nil {
					oidcDiscoveryUri = p.Oidc.DiscoveryUri
				}

				mqlProvider, err := CreateResource(g.MqlRuntime, "gcp.project.iamService.workloadIdentityPool.provider",
					map[string]*llx.RawData{
						"projectId":            llx.StringData(projectId),
						"name":                 llx.StringData(p.Name),
						"providerId":           llx.StringData(lastSegment(p.Name)),
						"poolId":               llx.StringData(poolId),
						"displayName":          llx.StringData(p.DisplayName),
						"description":          llx.StringData(p.Description),
						"state":                llx.StringData(p.State),
						"disabled":             llx.BoolData(p.Disabled),
						"expireTime":           llx.TimeDataPtr(parseTime(p.ExpireTime)),
						"attributeMapping":     llx.MapData(convert.MapToInterfaceMap(p.AttributeMapping), types.String),
						"attributeCondition":   llx.StringData(p.AttributeCondition),
						"providerType":         llx.StringData(providerType),
						"awsAccountId":         llx.StringData(awsAccountId),
						"oidcIssuerUri":        llx.StringData(oidcIssuer),
						"oidcAllowedAudiences": llx.ArrayData(oidcAudiences, types.String),
						"oidcDiscoveryUri":     llx.StringData(oidcDiscoveryUri),
						"samlIdpMetadataXml":   llx.StringData(samlMetadata),
						"x509TrustAnchorCount": llx.IntData(int64(x509TrustAnchorCount)),
					})
				if err != nil {
					return err
				}
				provider := mqlProvider.(*mqlGcpProjectIamServiceWorkloadIdentityPoolProvider)
				provider.cacheActorProviderNames = p.ActorProviders
				byName[p.Name] = provider
				providers = append(providers, mqlProvider)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	// Actor providers live in the same pool, so they resolve against the list
	// just fetched instead of one Get per reference.
	for _, provider := range byName {
		provider.cachePoolProviders = byName
	}
	return providers, nil
}

type mqlGcpProjectIamServiceWorkloadIdentityPoolProviderInternal struct {
	// cacheActorProviderNames holds the raw ActorProviders resource names.
	cacheActorProviderNames []string
	// cachePoolProviders maps every provider of the parent pool by resource name.
	cachePoolProviders map[string]*mqlGcpProjectIamServiceWorkloadIdentityPoolProvider
}

func (g *mqlGcpProjectIamServiceWorkloadIdentityPoolProvider) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectIamServiceWorkloadIdentityPoolProvider) actorProviders() ([]any, error) {
	resolved, unresolved := resolveWifActorProviders(g.cacheActorProviderNames, g.cachePoolProviders)
	for _, name := range unresolved {
		log.Debug().Str("provider", g.Name.Data).Str("actorProvider", name).
			Msg("gcp> actor provider is not in the pool's provider list, skipping")
	}
	res := make([]any, 0, len(resolved))
	for _, p := range resolved {
		res = append(res, p)
	}
	return res, nil
}

// wifProviderPathSuffix returns the pool-relative part of a workload identity
// pool provider resource name: "workloadIdentityPools/{pool}/providers/{id}".
// The project segment is dropped because the API may spell it as a project ID
// in one place and a project number in another, while actor providers always
// live in the same pool and so share the same project.
func wifProviderPathSuffix(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for i := len(parts) - 4; i >= 0; i-- {
		if parts[i] == "workloadIdentityPools" && i+3 < len(parts) && parts[i+2] == "providers" {
			return strings.Join(parts[i:i+4], "/")
		}
	}
	return ""
}

// resolveWifActorProviders matches ActorProviders resource names against the
// providers of the same pool. A name is matched exactly first, then by its
// pool-relative suffix. Names that match nothing (a provider purged after it
// was referenced) are returned in unresolved, in their original order.
func resolveWifActorProviders[T any](names []string, pool map[string]T) (resolved []T, unresolved []string) {
	resolved = []T{}
	var bySuffix map[string]T
	for _, name := range names {
		if name == "" {
			continue
		}
		if p, ok := pool[name]; ok {
			resolved = append(resolved, p)
			continue
		}
		if bySuffix == nil {
			bySuffix = make(map[string]T, len(pool))
			for k, v := range pool {
				if s := wifProviderPathSuffix(k); s != "" {
					bySuffix[s] = v
				}
			}
		}
		if s := wifProviderPathSuffix(name); s != "" {
			if p, ok := bySuffix[s]; ok {
				resolved = append(resolved, p)
				continue
			}
		}
		unresolved = append(unresolved, name)
	}
	return resolved, unresolved
}

func (g *mqlGcpProjectIamServiceWorkloadIdentityPoolProvider) hasAttributeCondition() (bool, error) {
	if g.AttributeCondition.Error != nil {
		return false, g.AttributeCondition.Error
	}
	return g.AttributeCondition.Data != "", nil
}

// flattenWifProviderConfig extracts the credential-family discriminator and
// the per-family fields from a WorkloadIdentityPoolProvider. Exactly one of
// Aws, Oidc, Saml, or X509 should be set; the rest return zero values. For
// X.509 providers, x509TrustAnchorCount reports how many trust anchors are
// configured in the provider's trust store.
func flattenWifProviderConfig(p *iam.WorkloadIdentityPoolProvider) (providerType, awsAccountId, oidcIssuer string, oidcAudiences []any, samlMetadata string, x509TrustAnchorCount int) {
	oidcAudiences = []any{}
	switch {
	case p.Aws != nil:
		providerType = "aws"
		awsAccountId = p.Aws.AccountId
	case p.Oidc != nil:
		providerType = "oidc"
		oidcIssuer = p.Oidc.IssuerUri
		for _, a := range p.Oidc.AllowedAudiences {
			oidcAudiences = append(oidcAudiences, a)
		}
	case p.Saml != nil:
		providerType = "saml"
		samlMetadata = p.Saml.IdpMetadataXml
	case p.X509 != nil:
		providerType = "x509"
		if p.X509.TrustStore != nil {
			x509TrustAnchorCount = len(p.X509.TrustStore.TrustAnchors)
		}
	}
	return
}

// lastSegment returns the substring after the final "/" in a slash-delimited
// resource name, or the original string if no "/" is present.
func lastSegment(name string) string {
	if _, after, ok := strings.CutLast(name, "/"); ok {
		return after
	}
	return name
}
