// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/databricks/databricks-sdk-go/service/billing"
	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/oauth2"
	"github.com/databricks/databricks-sdk-go/service/provisioning"
	"github.com/databricks/databricks-sdk-go/service/settings"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlDatabricksLogDeliveryInternal struct {
	cacheStorageConfigurationId string
	cacheCredentialsId          string
}

func (r *mqlDatabricks) logDeliveryConfigurations() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	configs, err := acc.LogDelivery.ListAll(context.Background(), billing.ListLogDeliveryRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range configs {
		c := configs[i]

		var deliveryStatus, deliveryMessage, lastAttempt, lastSuccess string
		if c.LogDeliveryStatus != nil {
			deliveryStatus = string(c.LogDeliveryStatus.Status)
			deliveryMessage = c.LogDeliveryStatus.Message
			lastAttempt = c.LogDeliveryStatus.LastAttemptTime
			lastSuccess = c.LogDeliveryStatus.LastSuccessfulAttemptTime
		}

		workspaceIds := make([]any, 0, len(c.WorkspaceIdsFilter))
		for _, id := range c.WorkspaceIdsFilter {
			workspaceIds = append(workspaceIds, id)
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.logDelivery", map[string]*llx.RawData{
			"__id":                      llx.StringData("databricks.logDelivery/" + c.ConfigId),
			"id":                        llx.StringData(c.ConfigId),
			"configName":                llx.StringData(c.ConfigName),
			"logType":                   llx.StringData(string(c.LogType)),
			"status":                    llx.StringData(string(c.Status)),
			"outputFormat":              llx.StringData(string(c.OutputFormat)),
			"deliveryPathPrefix":        llx.StringData(c.DeliveryPathPrefix),
			"deliveryStartTime":         llx.StringData(c.DeliveryStartTime),
			"workspaceIdsFilter":        llx.ArrayData(workspaceIds, types.Int),
			"deliveryStatus":            llx.StringData(deliveryStatus),
			"deliveryStatusMessage":     llx.StringData(deliveryMessage),
			"lastAttemptTime":           llx.StringData(lastAttempt),
			"lastSuccessfulAttemptTime": llx.StringData(lastSuccess),
			"createdAt":                 llx.TimeDataPtr(epochMsTime(c.CreationTime)),
			"updatedAt":                 llx.TimeDataPtr(epochMsTime(c.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		config := res.(*mqlDatabricksLogDelivery)
		config.cacheStorageConfigurationId = c.StorageConfigurationId
		config.cacheCredentialsId = c.CredentialsId
		out = append(out, config)
	}
	return out, nil
}

func (r *mqlDatabricksLogDelivery) storageConfiguration() (*mqlDatabricksStorageConfiguration, error) {
	if r.cacheStorageConfigurationId == "" {
		r.StorageConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "databricks.storageConfiguration", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheStorageConfigurationId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksStorageConfiguration), nil
}

func (r *mqlDatabricksLogDelivery) credentialConfiguration() (*mqlDatabricksCredentialConfiguration, error) {
	if r.cacheCredentialsId == "" {
		r.CredentialConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "databricks.credentialConfiguration", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheCredentialsId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCredentialConfiguration), nil
}

// newMqlDatabricksStorageConfiguration maps an account storage configuration to
// its resource. Shared by the list path and the init lookup so a configuration
// hydrated by id carries the same fields as a listed one.
func newMqlDatabricksStorageConfiguration(runtime *plugin.Runtime, s provisioning.StorageConfiguration) (*mqlDatabricksStorageConfiguration, error) {
	bucketName := ""
	if s.RootBucketInfo != nil {
		bucketName = s.RootBucketInfo.BucketName
	}
	res, err := CreateResource(runtime, "databricks.storageConfiguration", map[string]*llx.RawData{
		"__id":       llx.StringData("databricks.storageConfiguration/" + s.StorageConfigurationId),
		"id":         llx.StringData(s.StorageConfigurationId),
		"name":       llx.StringData(s.StorageConfigurationName),
		"bucketName": llx.StringData(bucketName),
		"roleArn":    llx.StringData(s.RoleArn),
		"createdAt":  llx.TimeDataPtr(epochMsTime(s.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksStorageConfiguration), nil
}

// initDatabricksStorageConfiguration resolves a single storage configuration by
// id so a log delivery configuration can hydrate the bucket it writes to. The
// account API offers no get-by-id that returns the same shape as the listing,
// so the listing is scanned.
func initDatabricksStorageConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, errors.New("databricks.storageConfiguration requires a non-empty id")
	}

	acc, err := accountClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	config, err := acc.Storage.GetByStorageConfigurationId(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksStorageConfiguration(runtime, *config)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricks) storageConfigurations() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	configs, err := acc.Storage.List(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range configs {
		res, err := newMqlDatabricksStorageConfiguration(r.MqlRuntime, configs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksCredentialConfiguration maps an account credential
// configuration to its resource.
func newMqlDatabricksCredentialConfiguration(runtime *plugin.Runtime, c provisioning.Credential) (*mqlDatabricksCredentialConfiguration, error) {
	roleArn := ""
	if c.AwsCredentials != nil && c.AwsCredentials.StsRole != nil {
		roleArn = c.AwsCredentials.StsRole.RoleArn
	}
	res, err := CreateResource(runtime, "databricks.credentialConfiguration", map[string]*llx.RawData{
		"__id":      llx.StringData("databricks.credentialConfiguration/" + c.CredentialsId),
		"id":        llx.StringData(c.CredentialsId),
		"name":      llx.StringData(c.CredentialsName),
		"roleArn":   llx.StringData(roleArn),
		"createdAt": llx.TimeDataPtr(epochMsTime(c.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCredentialConfiguration), nil
}

// initDatabricksCredentialConfiguration resolves a single credential
// configuration by id so a log delivery configuration can hydrate the role it
// writes with.
func initDatabricksCredentialConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, errors.New("databricks.credentialConfiguration requires a non-empty id")
	}

	acc, err := accountClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	config, err := acc.Credentials.GetByCredentialsId(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksCredentialConfiguration(runtime, *config)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricks) credentialConfigurations() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	creds, err := acc.Credentials.List(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range creds {
		res, err := newMqlDatabricksCredentialConfiguration(r.MqlRuntime, creds[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksFederationPolicy maps an OIDC federation policy to its
// resource. Account-level and service-principal policies share one shape, and
// servicePrincipalId is what distinguishes them.
func newMqlDatabricksFederationPolicy(runtime *plugin.Runtime, p oauth2.FederationPolicy) (*mqlDatabricksFederationPolicy, error) {
	var issuer, subject, subjectClaim, jwksUri string
	audiences := []any{}
	if p.OidcPolicy != nil {
		issuer = p.OidcPolicy.Issuer
		subject = p.OidcPolicy.Subject
		subjectClaim = p.OidcPolicy.SubjectClaim
		jwksUri = p.OidcPolicy.JwksUri
		// JwksJson holds the inlined signing keys, which are public but bulky
		// and carry no audit signal beyond the URI already reported.
		audiences = strSlice(p.OidcPolicy.Audiences)
	}

	res, err := CreateResource(runtime, "databricks.federationPolicy", map[string]*llx.RawData{
		"__id":               llx.StringData("databricks.federationPolicy/" + p.Uid),
		"id":                 llx.StringData(p.PolicyId),
		"name":               llx.StringData(p.Name),
		"description":        llx.StringData(p.Description),
		"uid":                llx.StringData(p.Uid),
		"servicePrincipalId": llx.IntData(p.ServicePrincipalId),
		"oidcIssuer":         llx.StringData(issuer),
		"oidcAudiences":      llx.ArrayData(audiences, types.String),
		"oidcSubject":        llx.StringData(subject),
		"oidcSubjectClaim":   llx.StringData(subjectClaim),
		"oidcJwksUri":        llx.StringData(jwksUri),
		"createTime":         llx.TimeDataPtr(rfc3339Time(p.CreateTime)),
		"updateTime":         llx.TimeDataPtr(rfc3339Time(p.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksFederationPolicy), nil
}

func (r *mqlDatabricks) federationPolicies() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	policies, err := acc.FederationPolicy.ListAll(context.Background(), oauth2.ListAccountFederationPoliciesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range policies {
		res, err := newMqlDatabricksFederationPolicy(r.MqlRuntime, policies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// federationPolicies lists the policies letting an external workload
// authenticate as this service principal. These are separate from the
// account-level policies and are keyed on the service principal's numeric id.
func (r *mqlDatabricksServicePrincipal) federationPolicies() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	spId, err := strconv.ParseInt(r.Id.Data, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("databricks.servicePrincipal has a non-numeric id %q, cannot list federation policies", r.Id.Data)
	}

	// ListByServicePrincipalId returns a single response page and discards its
	// NextPageToken, so a service principal with more policies than fit one page
	// would report only the first. ListAll drains the pages.
	policies, err := acc.ServicePrincipalFederationPolicy.ListAll(context.Background(),
		oauth2.ListServicePrincipalFederationPoliciesRequest{ServicePrincipalId: spId})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range policies {
		res, err := newMqlDatabricksFederationPolicy(r.MqlRuntime, policies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// secrets lists the OAuth secrets issued to this service principal. The secret
// value is returned only at creation, so only the lifecycle is readable.
func (r *mqlDatabricksServicePrincipal) secrets() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	secrets, err := acc.ServicePrincipalSecrets.ListAll(context.Background(), oauth2.ListServicePrincipalSecretsRequest{
		ServicePrincipalId: r.Id.Data,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range secrets {
		s := secrets[i]
		// SecretHash is deliberately not mapped.
		res, err := CreateResource(r.MqlRuntime, "databricks.servicePrincipal.secret", map[string]*llx.RawData{
			"__id":       llx.StringData("databricks.servicePrincipal.secret/" + r.Id.Data + "/" + s.Id),
			"id":         llx.StringData(s.Id),
			"status":     llx.StringData(s.Status),
			"createTime": llx.TimeDataPtr(rfc3339Time(s.CreateTime)),
			"expireTime": llx.TimeDataPtr(rfc3339Time(s.ExpireTime)),
			"updateTime": llx.TimeDataPtr(rfc3339Time(s.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// appIntegrationType distinguishes an application the account registered from
// one Databricks publishes.
const (
	appIntegrationCustom    = "CUSTOM"
	appIntegrationPublished = "PUBLISHED"
)

func (r *mqlDatabricks) appIntegrations() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	out := []any{}

	custom, err := acc.CustomAppIntegration.ListAll(ctx, oauth2.ListCustomAppIntegrationsRequest{})
	if err != nil {
		return nil, err
	}
	for i := range custom {
		c := custom[i]
		var accessTtl, refreshTtl int
		var singleUse bool
		if c.TokenAccessPolicy != nil {
			accessTtl = c.TokenAccessPolicy.AccessTokenTtlInMinutes
			refreshTtl = c.TokenAccessPolicy.RefreshTokenTtlInMinutes
			singleUse = c.TokenAccessPolicy.EnableSingleUseRefreshTokens
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.appIntegration", map[string]*llx.RawData{
			"__id":                   llx.StringData("databricks.appIntegration/" + c.IntegrationId),
			"id":                     llx.StringData(c.IntegrationId),
			"name":                   llx.StringData(c.Name),
			"integrationType":        llx.StringData(appIntegrationCustom),
			"clientId":               llx.StringData(c.ClientId),
			"confidential":           llx.BoolData(c.Confidential),
			"redirectUrls":           llx.ArrayData(strSlice(c.RedirectUrls), types.String),
			"scopes":                 llx.ArrayData(strSlice(c.Scopes), types.String),
			"userAuthorizedScopes":   llx.ArrayData(strSlice(c.UserAuthorizedScopes), types.String),
			"accessTokenTtlMinutes":  llx.IntData(accessTtl),
			"refreshTokenTtlMinutes": llx.IntData(refreshTtl),
			"singleUseRefreshTokens": llx.BoolData(singleUse),
			"creatorUsername":        llx.StringData(c.CreatorUsername),
			"createTime":             llx.StringData(c.CreateTime),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}

	published, err := acc.PublishedAppIntegration.ListAll(ctx, oauth2.ListPublishedAppIntegrationsRequest{})
	if err != nil {
		return nil, err
	}
	for i := range published {
		p := published[i]
		var accessTtl, refreshTtl int
		var singleUse bool
		if p.TokenAccessPolicy != nil {
			accessTtl = p.TokenAccessPolicy.AccessTokenTtlInMinutes
			refreshTtl = p.TokenAccessPolicy.RefreshTokenTtlInMinutes
			singleUse = p.TokenAccessPolicy.EnableSingleUseRefreshTokens
		}

		// A published integration carries no redirect URLs or scopes of its
		// own; Databricks defines those. The empty lists are the true shape,
		// not a gap in the mapping.
		res, err := CreateResource(r.MqlRuntime, "databricks.appIntegration", map[string]*llx.RawData{
			"__id":                   llx.StringData("databricks.appIntegration/" + p.IntegrationId),
			"id":                     llx.StringData(p.IntegrationId),
			"name":                   llx.StringData(p.Name),
			"integrationType":        llx.StringData(appIntegrationPublished),
			"clientId":               llx.StringData(p.AppId),
			"confidential":           llx.BoolData(false),
			"redirectUrls":           llx.ArrayData([]any{}, types.String),
			"scopes":                 llx.ArrayData([]any{}, types.String),
			"userAuthorizedScopes":   llx.ArrayData([]any{}, types.String),
			"accessTokenTtlMinutes":  llx.IntData(accessTtl),
			"refreshTokenTtlMinutes": llx.IntData(refreshTtl),
			"singleUseRefreshTokens": llx.BoolData(singleUse),
			"creatorUsername":        llx.StringData(""),
			"createTime":             llx.StringData(p.CreateTime),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}

	return out, nil
}

// internetDestinationMap keys egress destinations by hostname so a policy check
// can look one up directly. The pair carries no id of its own, so a map beats a
// sub-resource.
func internetDestinationMap(dests []settings.EgressNetworkPolicyNetworkAccessPolicyInternetDestination) map[string]any {
	out := make(map[string]any, len(dests))
	for i := range dests {
		out[dests[i].Destination] = string(dests[i].InternetDestinationType)
	}
	return out
}

// storageDestinationDicts flattens the storage egress destinations. The fields
// that identify a destination differ by cloud, so each entry keeps only the ones
// its type populates.
func storageDestinationDicts(dests []settings.EgressNetworkPolicyNetworkAccessPolicyStorageDestination) []any {
	out := make([]any, 0, len(dests))
	for i := range dests {
		d := dests[i]
		entry := map[string]any{"type": string(d.StorageDestinationType)}
		if d.BucketName != "" {
			entry["bucketName"] = d.BucketName
		}
		if d.Region != "" {
			entry["region"] = d.Region
		}
		if d.AzureStorageAccount != "" {
			entry["azureStorageAccount"] = d.AzureStorageAccount
		}
		if d.AzureStorageService != "" {
			entry["azureStorageService"] = d.AzureStorageService
		}
		out = append(out, entry)
	}
	return out
}

func (r *mqlDatabricks) networkPolicies() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	policies, err := acc.NetworkPolicies.ListNetworkPoliciesRpcAll(context.Background(), settings.ListNetworkPoliciesRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range policies {
		p := policies[i]

		restrictionMode := ""
		enforcementMode := ""
		dryRunFilter := []any{}
		allowedInternet := map[string]any{}
		blockedInternet := map[string]any{}
		allowedStorage := []any{}

		if p.Egress != nil && p.Egress.NetworkAccess != nil {
			na := p.Egress.NetworkAccess
			restrictionMode = string(na.RestrictionMode)
			allowedInternet = internetDestinationMap(na.AllowedInternetDestinations)
			blockedInternet = internetDestinationMap(na.BlockedInternetDestinations)
			allowedStorage = storageDestinationDicts(na.AllowedStorageDestinations)
			if na.PolicyEnforcement != nil {
				enforcementMode = string(na.PolicyEnforcement.EnforcementMode)
				for _, f := range na.PolicyEnforcement.DryRunModeProductFilter {
					dryRunFilter = append(dryRunFilter, string(f))
				}
			}
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.networkPolicy", map[string]*llx.RawData{
			"__id":                        llx.StringData("databricks.networkPolicy/" + p.NetworkPolicyId),
			"id":                          llx.StringData(p.NetworkPolicyId),
			"egressRestrictionMode":       llx.StringData(restrictionMode),
			"egressEnforcementMode":       llx.StringData(enforcementMode),
			"egressDryRunProductFilter":   llx.ArrayData(dryRunFilter, types.String),
			"allowedInternetDestinations": llx.MapData(allowedInternet, types.String),
			"blockedInternetDestinations": llx.MapData(blockedInternet, types.String),
			"allowedStorageDestinations":  llx.ArrayData(allowedStorage, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// permissionAssignments lists the principals granted access to this workspace at
// the account level. This is the grant that admits a principal to the workspace
// at all, and it is separate from the in-workspace access control lists.
func (r *mqlDatabricksWorkspace) permissionAssignments() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	workspaceId := r.WorkspaceId.Data
	assignments, err := acc.WorkspaceAssignment.ListAll(context.Background(), iam.ListWorkspaceAssignmentRequest{
		WorkspaceId: workspaceId,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range assignments {
		a := assignments[i]
		if a.Principal == nil {
			// An assignment naming no principal cannot be attributed, and its
			// id would collide with any other such entry.
			continue
		}

		name, kind := assignedPrincipal(*a.Principal)
		if name == "" {
			continue
		}

		permissions := make([]any, 0, len(a.Permissions))
		for _, p := range a.Permissions {
			permissions = append(permissions, string(p))
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.workspaceAssignment", map[string]*llx.RawData{
			"__id":          llx.StringData("databricks.workspaceAssignment/" + strconv.FormatInt(workspaceId, 10) + "/" + strconv.FormatInt(a.Principal.PrincipalId, 10)),
			"workspaceId":   llx.IntData(workspaceId),
			"principal":     llx.StringData(name),
			"principalType": llx.StringData(kind),
			"principalId":   llx.IntData(a.Principal.PrincipalId),
			"displayName":   llx.StringData(a.Principal.DisplayName),
			"permissions":   llx.ArrayData(permissions, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// assignedPrincipal resolves the name and kind of a workspace assignment's
// principal. Exactly one of the three name fields is set, which is what
// distinguishes a user from a group from a service principal.
func assignedPrincipal(p iam.PrincipalOutput) (name string, kind string) {
	switch {
	case p.UserName != "":
		return p.UserName, principalKindUser
	case p.GroupName != "":
		return p.GroupName, principalKindGroup
	case p.ServicePrincipalName != "":
		return p.ServicePrincipalName, principalKindServicePrincipal
	}
	return "", ""
}
