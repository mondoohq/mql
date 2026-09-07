// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcore_types "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// consentPortalSourceCacheID builds the cache key for one source of a consent
// portal. The identifier alone is not unique across portals, and a portal may
// serve the same identifier under two source types, so the key carries the
// portal, the type, and the identifier.
func consentPortalSourceCacheID(portalArn, sourceType, identifier string) string {
	return fmt.Sprintf("%s/source/%s/%s", portalArn, sourceType, identifier)
}

// matchesAgentCoreIdentifier reports whether an ARN names the resource a
// source identifier refers to.
//
// AgentCore accepts either form when a portal is configured, and reports back
// whichever was used, so a source may carry a bare gateway id or a full ARN.
// A bare id matches the last path segment of the ARN; comparing the whole
// strings would resolve only the ARN-configured half of real portals, and
// because a failed resolution is logged and skipped that would surface as a
// silently null gateway rather than an error.
func matchesAgentCoreIdentifier(arn, identifier string) bool {
	if identifier == "" || arn == "" {
		return false
	}
	if arn == identifier {
		return true
	}
	// Only a bare identifier may match by suffix. An identifier that is itself
	// an ARN and did not match outright names a different resource.
	if strings.HasPrefix(identifier, "arn:") {
		return false
	}
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:] == identifier
	}
	return false
}

// --- Consent portals ---

func (a *mqlAwsBedrockAgentCore) consentPortals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListConsentPortalsPaginator(svc, &bedrockagentcorecontrol.ListConsentPortalsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, portal := range page.ConsentPortals {
				mqlPortal, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.consentPortal", map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(portal.ConsentPortalArn),
					"arn":         llx.StringDataPtr(portal.ConsentPortalArn),
					"name":        llx.StringDataPtr(portal.Name),
					"region":      llx.StringData(region),
					"description": llx.StringDataPtr(portal.Description),
					"status":      llx.StringData(string(portal.Status)),
					"portalUrl":   llx.StringDataPtr(portal.PortalUrl),
					"createdAt":   llx.TimeDataPtr(portal.CreatedAt),
					"updatedAt":   llx.TimeDataPtr(portal.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				cast := mqlPortal.(*mqlAwsBedrockAgentCoreConsentPortal)
				cast.cacheRegion = region
				cast.cachePortalId = convert.ToValue(portal.ConsentPortalId)
				cast.cacheSources = portal.Sources
				res = append(res, mqlPortal)
			}
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsBedrockAgentCoreConsentPortalInternal struct {
	cacheRegion   string
	cachePortalId string
	cacheSources  []agentcore_types.ConsentPortalSource
	detailOnce    sync.Once
	detail        *bedrockagentcorecontrol.GetConsentPortalOutput
	detailErr     error
}

// fetchDetail reads the identity-provider configuration and execution role,
// which the list API does not carry. An access denial leaves detail nil so
// those fields resolve to null rather than reporting an unread configuration
// as absent.
func (a *mqlAwsBedrockAgentCoreConsentPortal) fetchDetail() (*bedrockagentcorecontrol.GetConsentPortalOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.BedrockAgentCoreControl(a.cacheRegion)
		identifier := a.cachePortalId
		if identifier == "" {
			identifier = a.Arn.Data
		}

		out, err := svc.GetConsentPortal(context.Background(), &bedrockagentcorecontrol.GetConsentPortalInput{
			ConsentPortalIdentifier: &identifier,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("portal", identifier).Msg("access denied getting agentcore consent portal")
				return
			}
			a.detailErr = err
			return
		}
		a.detail = out
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) statusReason() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.StatusReason == nil {
		a.StatusReason = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *detail.StatusReason, nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) oauthScopes() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.IdpConfig == nil {
		a.OauthScopes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return toInterfaceArr(detail.IdpConfig.Scopes), nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) oauthAudience() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.IdpConfig == nil || detail.IdpConfig.Audience == nil {
		a.OauthAudience = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *detail.IdpConfig.Audience, nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.ExecutionRoleArn == nil || *detail.ExecutionRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.ExecutionRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// credentialProvider resolves the OAuth2 provider out of the account's
// already-fetched provider list.
//
// aws.bedrock.agentCore.oauth2CredentialProvider has no init, so a NewResource
// call by ARN would create a husk carrying only that ARN instead of the real
// provider. Scanning the cached list also keeps this off a per-portal API call.
func (a *mqlAwsBedrockAgentCoreConsentPortal) credentialProvider() (*mqlAwsBedrockAgentCoreOauth2CredentialProvider, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.IdpConfig == nil || detail.IdpConfig.CredentialProviderArn == nil {
		a.CredentialProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wantArn := *detail.IdpConfig.CredentialProviderArn

	agentCore, err := a.parentAgentCore()
	if err != nil {
		return nil, err
	}
	providers := agentCore.GetOauth2CredentialProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	for _, raw := range providers.Data {
		provider, ok := raw.(*mqlAwsBedrockAgentCoreOauth2CredentialProvider)
		if !ok {
			continue
		}
		if provider.Arn.Data == wantArn {
			return provider, nil
		}
	}

	a.CredentialProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) parentAgentCore() (*mqlAwsBedrockAgentCore, error) {
	obj, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsBedrockAgentCore), nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortal) sources() ([]any, error) {
	portalArn := a.Arn.Data
	res := []any{}
	for _, source := range a.cacheSources {
		sourceType := string(source.Type)
		identifier := convert.ToValue(source.Identifier)

		mqlSource, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.consentPortal.source", map[string]*llx.RawData{
			"__id":       llx.StringData(consentPortalSourceCacheID(portalArn, sourceType, identifier)),
			"identifier": llx.StringData(identifier),
			"type":       llx.StringData(sourceType),
		})
		if err != nil {
			return nil, err
		}
		cast := mqlSource.(*mqlAwsBedrockAgentCoreConsentPortalSource)
		cast.cacheRegion = a.cacheRegion
		res = append(res, mqlSource)
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreConsentPortalSource) id() (string, error) {
	return a.__id, nil
}

type mqlAwsBedrockAgentCoreConsentPortalSourceInternal struct {
	cacheRegion string
}

// gateway resolves the source against the account's already-fetched gateway
// list. aws.bedrock.agentCore.gateway has no init, so resolving by ARN through
// NewResource would produce a husk rather than the real gateway.
func (a *mqlAwsBedrockAgentCoreConsentPortalSource) gateway() (*mqlAwsBedrockAgentCoreGateway, error) {
	if a.Type.Data != string(agentcore_types.ConsentPortalSourceTypeAgentcoreGateway) {
		a.Gateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	gateways := obj.(*mqlAwsBedrockAgentCore).GetGateways()
	if gateways.Error != nil {
		return nil, gateways.Error
	}

	identifier := a.Identifier.Data
	for _, raw := range gateways.Data {
		gateway, ok := raw.(*mqlAwsBedrockAgentCoreGateway)
		if !ok {
			continue
		}
		if gateway.Region.Data != a.cacheRegion {
			continue
		}
		if matchesAgentCoreIdentifier(gateway.GetArn().Data, identifier) {
			return gateway, nil
		}
	}

	a.Gateway.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
