// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"os"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// unstableOperations names the API operations the client refuses to call until
// they are turned on explicitly. Datadog marks an operation unstable while its
// shape may still change; the read paths listed here are ones this provider
// depends on, so leaving them off would make the resource return an error
// instead of data on every organization.
var unstableOperations = []string{
	"v2.ListExecutionPolicies",
	"v2.GetExecutionPolicy",
	"v2.ListSecurityFindingsAutomationInboxRules",
	"v2.ListSecurityFindingsAutomationDefaultInboxRules",
	"v2.ListSnowflakeIntegrationAccounts",
	"v2.ListDatabricksIntegrationAccounts",
}

type DatadogConnection struct {
	plugin.Connection
	Conf        *inventory.Config
	asset       *inventory.Asset
	apiClient   *datadog.APIClient
	authCtx     context.Context
	orgPublicId string
}

func NewDatadogConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*DatadogConnection, error) {
	conn := &DatadogConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	apiKey := os.Getenv("DD_API_KEY")
	appKey := os.Getenv("DD_APP_KEY")
	site := os.Getenv("DD_SITE")

	// Credentials can provide api-key and app-key via the user field
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			switch cred.User {
			case "app-key":
				appKey = string(cred.Secret)
			default:
				// Default password credential is the API key (backward-compatible)
				apiKey = string(cred.Secret)
			}
		}
	}

	if conf.Options != nil {
		if v, ok := conf.Options["app-key"]; ok && v != "" {
			appKey = v
		}
		if v, ok := conf.Options["site"]; ok && v != "" {
			site = v
		}
	}

	if apiKey == "" {
		return nil, errors.New("a valid Datadog API key is required (set DD_API_KEY or use --api-key)")
	}
	if appKey == "" {
		return nil, errors.New("a valid Datadog application key is required (set DD_APP_KEY or use --app-key)")
	}

	ctx := context.WithValue(
		context.Background(),
		datadog.ContextAPIKeys,
		map[string]datadog.APIKey{
			"apiKeyAuth": {Key: apiKey},
			"appKeyAuth": {Key: appKey},
		},
	)

	if site != "" {
		ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
			"site": site,
		})
	}

	configuration := datadog.NewConfiguration()
	for _, op := range unstableOperations {
		configuration.SetUnstableOperationEnabled(op, true)
	}
	conn.apiClient = datadog.NewAPIClient(configuration)
	conn.authCtx = ctx

	orgPublicId, err := resolveOrgPublicId(ctx, conn.apiClient)
	if err != nil {
		return nil, err
	}
	conn.orgPublicId = orgPublicId

	return conn, nil
}

// resolveOrgPublicId determines the public ID of the organization the supplied
// credentials belong to. It is what separates one Datadog org from another in
// the asset's platform ID, so a connection without it is refused rather than
// left to collide with every other org scanned from this installation.
//
// ListOrgs is tried first because it is the authoritative source, but it needs
// the org_management permission that scoped application keys routinely lack.
// GetCurrentUser carries the org in its included resources and needs no
// permission beyond the keys already in use.
func resolveOrgPublicId(ctx context.Context, client *datadog.APIClient) (string, error) {
	orgResp, _, err := datadogV1.NewOrganizationsApi(client).ListOrgs(ctx)
	if err == nil {
		if orgs := orgResp.GetOrgs(); len(orgs) > 0 {
			if publicId := orgs[0].GetPublicId(); publicId != "" {
				return publicId, nil
			}
		}
	} else {
		log.Debug().Err(err).Msg("datadog> could not list organizations, falling back to the current user")
	}

	userResp, _, err := datadogV2.NewUsersApi(client).GetCurrentUser(ctx)
	if err != nil {
		return "", errors.New("could not determine the Datadog organization: " + err.Error())
	}
	if publicId := orgPublicIdFromUser(userResp); publicId != "" {
		return publicId, nil
	}

	return "", errors.New("could not determine the Datadog organization from the supplied credentials")
}

// orgPublicIdFromUser picks the organization out of the current user's included
// resources. Included is a union of organizations, permissions and roles, so
// every entry has to be checked for which arm is populated.
func orgPublicIdFromUser(resp datadogV2.UserResponse) string {
	for _, included := range resp.GetIncluded() {
		if included.Organization == nil {
			continue
		}
		if publicId := included.Organization.Attributes.GetPublicId(); publicId != "" {
			return publicId
		}
	}
	return ""
}

func (c *DatadogConnection) Name() string {
	return "datadog"
}

func (c *DatadogConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *DatadogConnection) ApiClient() *datadog.APIClient {
	return c.apiClient
}

func (c *DatadogConnection) AuthCtx() context.Context {
	return c.authCtx
}

func (c *DatadogConnection) OrgPublicId() string {
	return c.orgPublicId
}
