// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

func (g *mqlGcpOrganization) workforcePools() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	orgId, err := conn.OrganizationID()
	if err != nil {
		return nil, err
	}

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

	var pools []any
	err = iamSvc.Locations.WorkforcePools.List("locations/global").
		Parent("organizations/"+orgId).
		ShowDeleted(true).
		Pages(ctx, func(resp *iam.ListWorkforcePoolsResponse) error {
			for _, p := range resp.WorkforcePools {
				var disableProgrammaticSignin bool
				allowedServices := []any{}
				if p.AccessRestrictions != nil {
					disableProgrammaticSignin = p.AccessRestrictions.DisableProgrammaticSignin
					for _, s := range p.AccessRestrictions.AllowedServices {
						if s != nil && s.Domain != "" {
							allowedServices = append(allowedServices, s.Domain)
						}
					}
				}

				mqlPool, err := CreateResource(g.MqlRuntime, "gcp.organization.workforcePool",
					map[string]*llx.RawData{
						"name":                      llx.StringData(p.Name),
						"poolId":                    llx.StringData(lastSegment(p.Name)),
						"parent":                    llx.StringData(p.Parent),
						"displayName":               llx.StringData(p.DisplayName),
						"description":               llx.StringData(p.Description),
						"state":                     llx.StringData(p.State),
						"disabled":                  llx.BoolData(p.Disabled),
						"sessionDuration":           llx.StringData(p.SessionDuration),
						"expireTime":                llx.TimeDataPtr(parseTime(p.ExpireTime)),
						"disableProgrammaticSignin": llx.BoolData(disableProgrammaticSignin),
						"allowedServices":           llx.ArrayData(allowedServices, types.String),
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

func (g *mqlGcpOrganizationWorkforcePool) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganizationWorkforcePool) providers() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	poolName := g.Name.Data
	if poolName == "" {
		return nil, errors.New("workforce pool has no name")
	}
	if g.State.Error != nil {
		return nil, g.State.Error
	}
	// A deleted pool 404s on its providers list; skip the call.
	if g.State.Data != "" && g.State.Data != "ACTIVE" {
		g.Providers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

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
	err = iamSvc.Locations.WorkforcePools.Providers.List(poolName).
		ShowDeleted(true).
		Pages(ctx, func(resp *iam.ListWorkforcePoolProvidersResponse) error {
			for _, p := range resp.WorkforcePoolProviders {
				cfg := flattenWorkforceProviderConfig(p)

				var extraAttributesType, extraAttributesIssuerUri string
				if p.ExtraAttributesOauth2Client != nil {
					extraAttributesType = p.ExtraAttributesOauth2Client.AttributesType
					extraAttributesIssuerUri = p.ExtraAttributesOauth2Client.IssuerUri
				}

				mqlProvider, err := CreateResource(g.MqlRuntime, "gcp.organization.workforcePool.provider",
					map[string]*llx.RawData{
						"name":                 llx.StringData(p.Name),
						"providerId":           llx.StringData(lastSegment(p.Name)),
						"poolId":               llx.StringData(lastSegment(poolName)),
						"displayName":          llx.StringData(p.DisplayName),
						"description":          llx.StringData(p.Description),
						"state":                llx.StringData(p.State),
						"disabled":             llx.BoolData(p.Disabled),
						"expireTime":           llx.TimeDataPtr(parseTime(p.ExpireTime)),
						"attributeMapping":     llx.MapData(convert.MapToInterfaceMap(p.AttributeMapping), types.String),
						"attributeCondition":   llx.StringData(p.AttributeCondition),
						"detailedAuditLogging": llx.BoolData(p.DetailedAuditLogging),
						"scimUsage":            llx.StringData(p.ScimUsage),
						"vendorType":           llx.StringData(p.VendorType),
						"providerType":         llx.StringData(cfg.providerType),
						"oidcIssuerUri":        llx.StringData(cfg.oidcIssuer),
						"oidcClientId":         llx.StringData(cfg.oidcClientId),
						"samlIdpMetadataXml":   llx.StringData(cfg.samlMetadata),

						"oidcHasClientSecret":               llx.BoolData(cfg.oidcHasClientSecret),
						"oidcWebSsoResponseType":            llx.StringData(cfg.webSsoResponseType),
						"oidcWebSsoAssertionClaimsBehavior": llx.StringData(cfg.webSsoAssertionClaimsBehavior),
						"oidcWebSsoAdditionalScopes":        llx.ArrayData(cfg.webSsoAdditionalScopes, types.String),
						"extraAttributesType":               llx.StringData(extraAttributesType),
						"extraAttributesIssuerUri":          llx.StringData(extraAttributesIssuerUri),
					})
				if err != nil {
					return err
				}
				providers = append(providers, mqlProvider)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return providers, nil
}

func (g *mqlGcpOrganizationWorkforcePoolProvider) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// workforceProviderConfig is the flattened per-protocol trust configuration of
// a workforce pool provider.
type workforceProviderConfig struct {
	providerType                  string
	oidcIssuer                    string
	oidcClientId                  string
	oidcHasClientSecret           bool
	webSsoResponseType            string
	webSsoAssertionClaimsBehavior string
	webSsoAdditionalScopes        []any
	samlMetadata                  string
}

// flattenWorkforceProviderConfig extracts the protocol discriminator and the
// per-protocol trust fields from a WorkforcePoolProvider. Exactly one of Oidc
// or Saml should be set; the other leaves its fields at the zero value.
//
// oidcHasClientSecret reports only whether a secret is registered. The API
// returns the secret as a thumbprint on read and never the plaintext, and
// neither is exposed here: the secret is a credential, and the posture question
// is whether one exists at all, because that is what allows the provider to use
// the Authorization Code flow rather than the implicit flow.
//
// A SAML provider has no web SSO config, so its response type stays empty
// rather than being reported as a value it does not have.
func flattenWorkforceProviderConfig(p *iam.WorkforcePoolProvider) workforceProviderConfig {
	var c workforceProviderConfig
	c.webSsoAdditionalScopes = []any{}
	switch {
	case p.Oidc != nil:
		c.providerType = "oidc"
		c.oidcIssuer = p.Oidc.IssuerUri
		c.oidcClientId = p.Oidc.ClientId
		c.oidcHasClientSecret = p.Oidc.ClientSecret != nil &&
			p.Oidc.ClientSecret.Value != nil &&
			p.Oidc.ClientSecret.Value.Thumbprint != ""
		if ws := p.Oidc.WebSsoConfig; ws != nil {
			c.webSsoResponseType = ws.ResponseType
			c.webSsoAssertionClaimsBehavior = ws.AssertionClaimsBehavior
			c.webSsoAdditionalScopes = convert.SliceAnyToInterface(ws.AdditionalScopes)
		}
	case p.Saml != nil:
		c.providerType = "saml"
		c.samlMetadata = p.Saml.IdpMetadataXml
	}
	return c
}
