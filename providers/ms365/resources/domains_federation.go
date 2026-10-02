// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// domainAuthenticationTypeFederated is the authenticationType Microsoft Graph
// reports for a domain whose users authenticate against an external identity
// provider.
const domainAuthenticationTypeFederated = "Federated"

// federatedIdpMfaBehaviorString renders the federated MFA behavior. An absent
// value reads as an empty string rather than as the Kiota enum's zero value,
// which is "acceptIfMfaDoneByFederatedIdp": that is the permissive setting, so
// dereferencing without the nil check would report the federated MFA bypass as
// configured on a domain that reported nothing.
func federatedIdpMfaBehaviorString(behavior *models.FederatedIdpMfaBehavior) string {
	if behavior == nil {
		return ""
	}
	return behavior.String()
}

// promptLoginBehaviorString renders the prompt-login behavior, reading an
// absent value as empty rather than as the enum's zero value.
func promptLoginBehaviorString(behavior *models.PromptLoginBehavior) string {
	if behavior == nil {
		return ""
	}
	return behavior.String()
}

// authenticationProtocolString renders the preferred authentication protocol,
// reading an absent value as empty rather than as the enum's zero value.
func authenticationProtocolString(protocol *models.AuthenticationProtocol) string {
	if protocol == nil {
		return ""
	}
	return protocol.String()
}

// systemBrowserEnabledOnList splits the platform set Microsoft Graph reports as
// one comma-joined string into individual platform names. A nil value and a
// value with no flags set both read as an empty list: the SDK renders an empty
// flag set as "", which a plain Split would turn into a list holding one empty
// string.
func systemBrowserEnabledOnList(enabledOn *models.SystemBrowserEnabledOn) []any {
	res := []any{}
	if enabledOn == nil {
		return res
	}
	for _, platform := range strings.Split(enabledOn.String(), ",") {
		if platform == "" {
			continue
		}
		res = append(res, platform)
	}
	return res
}

// federationConfigurations reads how a federated domain authenticates against
// its external identity provider.
//
// Only a federated domain has one. The call is gated on the domain's
// authentication type so a tenant of managed domains, which is the common case,
// pays no request per domain.
func (a *mqlMicrosoftDomain) federationConfigurations() ([]any, error) {
	if !strings.EqualFold(a.AuthenticationType.Data, domainAuthenticationTypeFederated) {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Domains().ByDomainId(a.Id.Data).FederationConfiguration().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	if resp == nil {
		return []any{}, nil
	}

	configurations, err := iterate[models.InternalDomainFederationable](ctx, resp, graphClient.GetAdapter(), models.CreateInternalDomainFederationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, configuration := range configurations {
		if configuration == nil {
			continue
		}
		mqlConfiguration, err := newMqlDomainFederationConfiguration(a.MqlRuntime, a.Id.Data, configuration)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfiguration)
	}
	return res, nil
}

// newMqlDomainFederationConfiguration maps one federation configuration. The
// configuration is an entity with an identifier of its own, but it is unique
// only within the domain, so the domain is part of the cache key.
func newMqlDomainFederationConfiguration(runtime *plugin.Runtime, domainID string, configuration models.InternalDomainFederationable) (plugin.Resource, error) {
	return CreateResource(runtime, ResourceMicrosoftDomainFederationConfiguration,
		newDomainFederationConfigurationArgs(domainID, configuration))
}

// newDomainFederationConfigurationArgs maps one federation configuration onto
// the arguments of the federation configuration resource.
func newDomainFederationConfigurationArgs(domainID string, configuration models.InternalDomainFederationable) map[string]*llx.RawData {
	certificateUpdateResult := ""
	certificateUpdateLastRun := llx.NilData
	if status := configuration.GetSigningCertificateUpdateStatus(); status != nil {
		certificateUpdateResult = convert.ToValue(status.GetCertificateUpdateResult())
		certificateUpdateLastRun = graphTimeData(status.GetLastRunDateTime())
	}

	return map[string]*llx.RawData{
		"__id":                                    llx.StringData(domainID + "/federationConfiguration/" + convert.ToValue(configuration.GetId())),
		"id":                                      llx.StringDataPtr(configuration.GetId()),
		"displayName":                             llx.StringDataPtr(configuration.GetDisplayName()),
		"issuerUri":                               llx.StringDataPtr(configuration.GetIssuerUri()),
		"metadataExchangeUri":                     llx.StringDataPtr(configuration.GetMetadataExchangeUri()),
		"passiveSignInUri":                        llx.StringDataPtr(configuration.GetPassiveSignInUri()),
		"activeSignInUri":                         llx.StringDataPtr(configuration.GetActiveSignInUri()),
		"signOutUri":                              llx.StringDataPtr(configuration.GetSignOutUri()),
		"passwordResetUri":                        llx.StringDataPtr(configuration.GetPasswordResetUri()),
		"preferredAuthenticationProtocol":         llx.StringData(authenticationProtocolString(configuration.GetPreferredAuthenticationProtocol())),
		"federatedIdpMfaBehavior":                 llx.StringData(federatedIdpMfaBehaviorString(configuration.GetFederatedIdpMfaBehavior())),
		"isSignedAuthenticationRequestRequired":   llx.BoolDataPtr(configuration.GetIsSignedAuthenticationRequestRequired()),
		"promptLoginBehavior":                     llx.StringData(promptLoginBehaviorString(configuration.GetPromptLoginBehavior())),
		"signingCertificate":                      llx.StringDataPtr(configuration.GetSigningCertificate()),
		"nextSigningCertificate":                  llx.StringDataPtr(configuration.GetNextSigningCertificate()),
		"signingCertificateUpdateResult":          llx.StringData(certificateUpdateResult),
		"signingCertificateUpdateLastRunDateTime": certificateUpdateLastRun,
		"systemBrowserEnabledOn":                  llx.ArrayData(systemBrowserEnabledOnList(configuration.GetSystemBrowserEnabledOn()), types.String),
	}
}
