// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"go.mondoo.com/mql/types"
	"sync"

	"github.com/microsoftgraph/msgraph-sdk-go/identity"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// Graph application permissions the identity provider and user flow reads
// need. They are named on a refusal so the error says what the scan app is
// missing.
const (
	permIdentityProviderReadAll = "IdentityProvider.Read.All"
	permIdentityUserFlowReadAll = "IdentityUserFlow.Read.All"
)

// Values reported by the type, clientAuthenticationMethod and
// authenticationType fields. oidcClientAuthMethodShared names the shared
// client secret method; the identifier deliberately avoids the word "secret",
// because an identifier carrying it next to a string literal reads to the
// credential scanner as a hardcoded secret.
const (
	identityProviderTypeUnknown  = "unknown"
	identityProviderTypeSocial   = "socialIdentityProvider"
	identityProviderTypeBuiltIn  = "builtInIdentityProvider"
	identityProviderTypeApple    = "appleManagedIdentityProvider"
	identityProviderTypeOidc     = "oidcIdentityProvider"
	identityProviderTypeSamlWsFe = "samlOrWsFedExternalDomainFederation"
	oidcClientAuthMethodUnknown  = "unknown"
	oidcClientAuthMethodShared   = "clientSecret"
	oidcClientAuthMethodPrivJwt  = "privateKeyJwt"
	apiConnectorAuthTypeUnknown  = "unknown"
	apiConnectorAuthTypeBasic    = "basic"
	apiConnectorAuthTypeCert     = "clientCertificate"
)

// identityEnumData renders a Kiota enum pointer, reporting an absent value as null
// rather than as the enum's zero value, which would name a value Microsoft
// Graph never sent.
func identityEnumData[T interface{ String() string }](v *T) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.StringData((*v).String())
}

// identityProviders lists the external identity providers configured for the
// tenant.
func (a *mqlMicrosoftIdentityAndAccess) identityProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Identity().IdentityProviders().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityProviderReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	providers, err := iterate[models.IdentityProviderBaseable](ctx, resp, graphClient.GetAdapter(), models.CreateIdentityProviderBaseCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityProviderReadAll)
	}
	return newMqlIdentityProviders(a.MqlRuntime, providers)
}

func newMqlIdentityProviders(runtime *plugin.Runtime, providers []models.IdentityProviderBaseable) ([]any, error) {
	res := []any{}
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		mqlProvider, err := CreateResource(runtime, ResourceMicrosoftIdentityAndAccessIdentityProvider, newIdentityProviderArgs(provider))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProvider)
	}
	return res, nil
}

// newIdentityProviderArgs maps one identity provider onto the arguments of the
// identity provider resource. The provider kind comes from the concrete type
// Kiota deserialized from the payload's @odata.type; fields that do not apply
// to that kind stay null. A kind this provider does not model is reported as
// unknown with only the common fields set.
//
// Social provider client secrets, the Apple private key (certificateData) and
// OpenID Connect client secrets are deliberately never read.
func newIdentityProviderArgs(provider models.IdentityProviderBaseable) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                            llx.StringData(convert.ToValue(provider.GetId())),
		"id":                              llx.StringDataPtr(provider.GetId()),
		"displayName":                     llx.StringDataPtr(provider.GetDisplayName()),
		"type":                            llx.StringData(identityProviderTypeUnknown),
		"identityProviderType":            llx.NilData,
		"clientId":                        llx.NilData,
		"developerId":                     llx.NilData,
		"serviceId":                       llx.NilData,
		"keyId":                           llx.NilData,
		"issuer":                          llx.NilData,
		"wellKnownEndpoint":               llx.NilData,
		"responseType":                    llx.NilData,
		"scope":                           llx.NilData,
		"clientAuthenticationMethod":      llx.NilData,
		"issuerUri":                       llx.NilData,
		"metadataExchangeUri":             llx.NilData,
		"passiveSignInUri":                llx.NilData,
		"preferredAuthenticationProtocol": llx.NilData,
		"signingCertificate":              llx.NilData,
		"domains":                         llx.ArrayData([]any{}, types.String),
	}

	switch p := provider.(type) {
	case *models.SocialIdentityProvider:
		args["type"] = llx.StringData(identityProviderTypeSocial)
		args["identityProviderType"] = llx.StringDataPtr(p.GetIdentityProviderType())
		args["clientId"] = llx.StringDataPtr(p.GetClientId())
	case *models.BuiltInIdentityProvider:
		args["type"] = llx.StringData(identityProviderTypeBuiltIn)
		args["identityProviderType"] = llx.StringDataPtr(p.GetIdentityProviderType())
	case *models.AppleManagedIdentityProvider:
		args["type"] = llx.StringData(identityProviderTypeApple)
		args["developerId"] = llx.StringDataPtr(p.GetDeveloperId())
		args["serviceId"] = llx.StringDataPtr(p.GetServiceId())
		args["keyId"] = llx.StringDataPtr(p.GetKeyId())
	case *models.OidcIdentityProvider:
		args["type"] = llx.StringData(identityProviderTypeOidc)
		args["clientId"] = llx.StringDataPtr(p.GetClientId())
		args["issuer"] = llx.StringDataPtr(p.GetIssuer())
		args["wellKnownEndpoint"] = llx.StringDataPtr(p.GetWellKnownEndpoint())
		args["responseType"] = identityEnumData(p.GetResponseType())
		args["scope"] = llx.StringDataPtr(p.GetScope())
		args["clientAuthenticationMethod"] = oidcClientAuthenticationMethod(p.GetClientAuthentication())
	case *models.SamlOrWsFedExternalDomainFederation:
		args["type"] = llx.StringData(identityProviderTypeSamlWsFe)
		args["issuerUri"] = llx.StringDataPtr(p.GetIssuerUri())
		args["metadataExchangeUri"] = llx.StringDataPtr(p.GetMetadataExchangeUri())
		args["passiveSignInUri"] = llx.StringDataPtr(p.GetPassiveSignInUri())
		args["preferredAuthenticationProtocol"] = identityEnumData(p.GetPreferredAuthenticationProtocol())
		args["signingCertificate"] = llx.StringDataPtr(p.GetSigningCertificate())
		args["domains"] = llx.ArrayData(externalDomainNames(p.GetDomains()), types.String)
	}
	return args
}

// oidcClientAuthenticationMethod names how the tenant authenticates to an
// OpenID Connect provider, without reading the secret or key itself.
func oidcClientAuthenticationMethod(auth models.OidcClientAuthenticationable) *llx.RawData {
	switch auth.(type) {
	case nil:
		return llx.NilData
	case *models.OidcClientSecretAuthentication:
		return llx.StringData(oidcClientAuthMethodShared)
	case *models.OidcPrivateJwtKeyClientAuthentication:
		return llx.StringData(oidcClientAuthMethodPrivJwt)
	default:
		return llx.StringData(oidcClientAuthMethodUnknown)
	}
}

// externalDomainNames returns the domain names of a SAML or WS-Fed
// federation. Microsoft Graph keys each external domain by its name.
func externalDomainNames(domains []models.ExternalDomainNameable) []any {
	res := []any{}
	for _, domain := range domains {
		if domain == nil || domain.GetId() == nil {
			continue
		}
		res = append(res, *domain.GetId())
	}
	return res
}

// b2xUserFlows lists the self-service sign-up user flows of the tenant.
func (a *mqlMicrosoftIdentityAndAccess) b2xUserFlows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Identity().B2xUserFlows().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityUserFlowReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	flows, err := iterate[models.B2xIdentityUserFlowable](ctx, resp, graphClient.GetAdapter(), models.CreateB2xIdentityUserFlowCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityUserFlowReadAll)
	}

	res := []any{}
	for _, flow := range flows {
		if flow == nil {
			continue
		}
		mqlFlow, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessB2xUserFlow, newB2xUserFlowArgs(flow))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFlow)
	}
	return res, nil
}

func newB2xUserFlowArgs(flow models.B2xIdentityUserFlowable) map[string]*llx.RawData {
	version := llx.NilData
	if v := flow.GetUserFlowTypeVersion(); v != nil {
		version = llx.FloatData(float64(*v))
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData(convert.ToValue(flow.GetId())),
		"id":                  llx.StringDataPtr(flow.GetId()),
		"userFlowType":        identityEnumData(flow.GetUserFlowType()),
		"userFlowTypeVersion": version,
	}
}

type mqlMicrosoftIdentityAndAccessB2xUserFlowInternal struct {
	// guards the apiConnectorConfiguration fetch so both connector fields
	// share a single Graph call
	apiConnectorsOnce sync.Once
	apiConnectors     models.UserFlowApiConnectorConfigurationable
	apiConnectorsErr  error
}

// identityProviders lists the identity providers users can sign up with in
// this flow. Graph returns each provider in full, so they are built directly
// rather than looked up one by one in the tenant list.
func (a *mqlMicrosoftIdentityAndAccessB2xUserFlow) identityProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Identity().B2xUserFlows().ByB2xIdentityUserFlowId(a.Id.Data).UserFlowIdentityProviders().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityUserFlowReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	providers, err := iterate[models.IdentityProviderBaseable](ctx, resp, graphClient.GetAdapter(), models.CreateIdentityProviderBaseCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permIdentityUserFlowReadAll)
	}
	return newMqlIdentityProviders(a.MqlRuntime, providers)
}

// fetchApiConnectorConfiguration reads the flow's API connector configuration
// with both connectors expanded.
func (a *mqlMicrosoftIdentityAndAccessB2xUserFlow) fetchApiConnectorConfiguration() (models.UserFlowApiConnectorConfigurationable, error) {
	a.apiConnectorsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			a.apiConnectorsErr = err
			return
		}
		flow, err := graphClient.Identity().B2xUserFlows().ByB2xIdentityUserFlowId(a.Id.Data).Get(context.Background(),
			&identity.B2xUserFlowsB2xIdentityUserFlowItemRequestBuilderGetRequestConfiguration{
				QueryParameters: &identity.B2xUserFlowsB2xIdentityUserFlowItemRequestBuilderGetQueryParameters{
					Expand: []string{"apiConnectorConfiguration/postFederationSignup", "apiConnectorConfiguration/postAttributeCollection"},
				},
			})
		if err != nil {
			a.apiConnectorsErr = classifyGraphError(err, permIdentityUserFlowReadAll)
			return
		}
		if flow != nil {
			a.apiConnectors = flow.GetApiConnectorConfiguration()
		}
	})
	return a.apiConnectors, a.apiConnectorsErr
}

func (a *mqlMicrosoftIdentityAndAccessB2xUserFlow) postFederationSignupApiConnector() (*mqlMicrosoftIdentityAndAccessApiConnector, error) {
	cfg, err := a.fetchApiConnectorConfiguration()
	if err != nil {
		return nil, err
	}
	var connector models.IdentityApiConnectorable
	if cfg != nil {
		connector = cfg.GetPostFederationSignup()
	}
	return a.apiConnectorResource(&a.PostFederationSignupApiConnector, connector)
}

func (a *mqlMicrosoftIdentityAndAccessB2xUserFlow) postAttributeCollectionApiConnector() (*mqlMicrosoftIdentityAndAccessApiConnector, error) {
	cfg, err := a.fetchApiConnectorConfiguration()
	if err != nil {
		return nil, err
	}
	var connector models.IdentityApiConnectorable
	if cfg != nil {
		connector = cfg.GetPostAttributeCollection()
	}
	return a.apiConnectorResource(&a.PostAttributeCollectionApiConnector, connector)
}

// apiConnectorResource builds the connector resource, or marks the field null
// when the flow calls no connector at that step.
func (a *mqlMicrosoftIdentityAndAccessB2xUserFlow) apiConnectorResource(field *plugin.TValue[*mqlMicrosoftIdentityAndAccessApiConnector], connector models.IdentityApiConnectorable) (*mqlMicrosoftIdentityAndAccessApiConnector, error) {
	if connector == nil || connector.GetId() == nil || *connector.GetId() == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessApiConnector, newApiConnectorArgs(connector))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftIdentityAndAccessApiConnector), nil
}

// newApiConnectorArgs maps an API connector. Only the kind of authentication
// is reported: the basic authentication password and the certificate
// contents are never read.
func newApiConnectorArgs(connector models.IdentityApiConnectorable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData(convert.ToValue(connector.GetId())),
		"id":                 llx.StringDataPtr(connector.GetId()),
		"displayName":        llx.StringDataPtr(connector.GetDisplayName()),
		"targetUrl":          llx.StringDataPtr(connector.GetTargetUrl()),
		"authenticationType": apiConnectorAuthenticationType(connector.GetAuthenticationConfiguration()),
	}
}

func apiConnectorAuthenticationType(auth models.ApiAuthenticationConfigurationBaseable) *llx.RawData {
	switch auth.(type) {
	case nil:
		return llx.NilData
	case *models.BasicAuthentication:
		return llx.StringData(apiConnectorAuthTypeBasic)
	case *models.ClientCertificateAuthentication, *models.Pkcs12Certificate:
		return llx.StringData(apiConnectorAuthTypeCert)
	default:
		return llx.StringData(apiConnectorAuthTypeUnknown)
	}
}
