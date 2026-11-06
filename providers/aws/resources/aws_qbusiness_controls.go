// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/qbusiness"
	qbusinesstypes "github.com/aws/aws-sdk-go-v2/service/qbusiness/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// qbusinessEnabled maps an ENABLED/DISABLED control onto a boolean. An unset
// control reports ok=false so the field reads as null.
func qbusinessEnabled[T ~string](v T) (enabled bool, ok bool) {
	switch string(v) {
	case "ENABLED":
		return true, true
	case "DISABLED":
		return false, true
	}
	return false, false
}

func qbusinessBoolField[T ~string](v T, field *plugin.TValue[bool]) (bool, error) {
	enabled, ok := qbusinessEnabled(v)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return enabled, nil
}

// --- Application settings from GetApplication ---

func (a *mqlAwsQBusinessApplication) attachmentsEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	var mode qbusinesstypes.AttachmentsControlMode
	if detail != nil && detail.AttachmentsConfiguration != nil {
		mode = detail.AttachmentsConfiguration.AttachmentsControlMode
	}
	return qbusinessBoolField(mode, &a.AttachmentsEnabled)
}

func (a *mqlAwsQBusinessApplication) qAppsEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	var mode qbusinesstypes.QAppsControlMode
	if detail != nil && detail.QAppsConfiguration != nil {
		mode = detail.QAppsConfiguration.QAppsControlMode
	}
	return qbusinessBoolField(mode, &a.QAppsEnabled)
}

func (a *mqlAwsQBusinessApplication) personalizationEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	var mode qbusinesstypes.PersonalizationControlMode
	if detail != nil && detail.PersonalizationConfiguration != nil {
		mode = detail.PersonalizationConfiguration.PersonalizationControlMode
	}
	return qbusinessBoolField(mode, &a.PersonalizationEnabled)
}

func (a *mqlAwsQBusinessApplication) autoSubscribeEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	var status qbusinesstypes.AutoSubscriptionStatus
	if detail != nil && detail.AutoSubscriptionConfiguration != nil {
		status = detail.AutoSubscriptionConfiguration.AutoSubscribe
	}
	return qbusinessBoolField(status, &a.AutoSubscribeEnabled)
}

func (a *mqlAwsQBusinessApplication) defaultSubscriptionType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.AutoSubscriptionConfiguration == nil || detail.AutoSubscriptionConfiguration.DefaultSubscriptionType == "" {
		a.DefaultSubscriptionType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.AutoSubscriptionConfiguration.DefaultSubscriptionType), nil
}

func (a *mqlAwsQBusinessApplication) clientIdsForOidc() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.ClientIdsForOidc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.SliceAnyToInterface(detail.ClientIdsForOIDC), nil
}

func (a *mqlAwsQBusinessApplication) identityCenterApplication() (*mqlAwsIdentitycenterApplication, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.IdentityCenterApplicationArn) == "" {
		a.IdentityCenterApplication.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wantArn := *detail.IdentityCenterApplicationArn
	obj, err := CreateResource(a.MqlRuntime, ResourceAwsIdentitycenter, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances := obj.(*mqlAwsIdentitycenter).GetInstances()
	if instances.Error != nil {
		return nil, instances.Error
	}
	for _, rawInstance := range instances.Data {
		instance, ok := rawInstance.(*mqlAwsIdentitycenterInstance)
		if !ok {
			continue
		}
		apps := instance.GetApplications()
		if apps.Error != nil {
			return nil, apps.Error
		}
		for _, rawApp := range apps.Data {
			if app, ok := rawApp.(*mqlAwsIdentitycenterApplication); ok && app.Arn.Data == wantArn {
				return app, nil
			}
		}
	}
	a.IdentityCenterApplication.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// qbusinessIamProviderArn returns the IAM identity provider ARN of an
// application when its identity type uses that kind of provider.
func qbusinessIamProviderArn(detail *qbusiness.GetApplicationOutput, want qbusinesstypes.IdentityType) string {
	if detail == nil || detail.IdentityType != want {
		return ""
	}
	return convert.ToValue(detail.IamIdentityProviderArn)
}

func (a *mqlAwsQBusinessApplication) iamSamlProvider() (*mqlAwsIamSamlProvider, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	wantArn := qbusinessIamProviderArn(detail, qbusinesstypes.IdentityTypeAwsIamIdpSaml)
	if wantArn == "" {
		a.IamSamlProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	iam, err := CreateResource(a.MqlRuntime, ResourceAwsIam, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	providers := iam.(*mqlAwsIam).GetSamlProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	for _, raw := range providers.Data {
		if p, ok := raw.(*mqlAwsIamSamlProvider); ok && p.Arn.Data == wantArn {
			return p, nil
		}
	}
	a.IamSamlProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsQBusinessApplication) iamOidcProvider() (*mqlAwsIamOidcProvider, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	wantArn := qbusinessIamProviderArn(detail, qbusinesstypes.IdentityTypeAwsIamIdpOidc)
	if wantArn == "" {
		a.IamOidcProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	iam, err := CreateResource(a.MqlRuntime, ResourceAwsIam, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	providers := iam.(*mqlAwsIam).GetOidcProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	for _, raw := range providers.Data {
		if p, ok := raw.(*mqlAwsIamOidcProvider); ok && p.Arn.Data == wantArn {
			return p, nil
		}
	}
	a.IamOidcProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- Chat controls ---

// qbusinessChatControls is the chat controls configuration of an application,
// collected across pages. A nil value with no error means the read was
// refused with structured errors off.
type qbusinessChatControls struct {
	responseScope          string
	blockedPhrases         []string
	topicNames             []string
	creatorMode            qbusinesstypes.CreatorModeControl
	hallucinationReduction qbusinesstypes.HallucinationReductionControl
	orchestration          qbusinesstypes.OrchestrationControl
}

// mergeChatControlsPage folds one GetChatControlsConfiguration page into c.
// Settings repeat on every page; topic configurations are paginated.
func mergeChatControlsPage(c *qbusinessChatControls, page *qbusiness.GetChatControlsConfigurationOutput) {
	if page.ResponseScope != "" {
		c.responseScope = string(page.ResponseScope)
	}
	if page.BlockedPhrases != nil && c.blockedPhrases == nil {
		c.blockedPhrases = page.BlockedPhrases.BlockedPhrases
	}
	if page.CreatorModeConfiguration != nil {
		c.creatorMode = page.CreatorModeConfiguration.CreatorModeControl
	}
	if page.HallucinationReductionConfiguration != nil {
		c.hallucinationReduction = page.HallucinationReductionConfiguration.HallucinationReductionControl
	}
	if page.OrchestrationConfiguration != nil {
		c.orchestration = page.OrchestrationConfiguration.Control
	}
	for _, t := range page.TopicConfigurations {
		if n := convert.ToValue(t.Name); n != "" {
			c.topicNames = append(c.topicNames, n)
		}
	}
}

type qbusinessChatControlsCache struct {
	chatLock    sync.Mutex
	chatFetched atomic.Bool
	chat        *qbusinessChatControls
	chatErr     error
}

func (a *mqlAwsQBusinessApplication) chatControls() (*qbusinessChatControls, error) {
	if a.chatFetched.Load() {
		return a.chat, a.chatErr
	}
	a.chatLock.Lock()
	defer a.chatLock.Unlock()
	if a.chatFetched.Load() {
		return a.chat, a.chatErr
	}
	defer a.chatFetched.Store(true)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	appId := a.Id.Data
	res := &qbusinessChatControls{}
	paginator := qbusiness.NewGetChatControlsConfigurationPaginator(svc, &qbusiness.GetChatControlsConfigurationInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return nil, nil
				}
				a.chatErr = llx.Forbidden(err, llx.WithPermissions("qbusiness:GetChatControlsConfiguration"))
				return nil, a.chatErr
			}
			a.chatErr = err
			return nil, err
		}
		mergeChatControlsPage(res, page)
	}
	if res.blockedPhrases == nil {
		res.blockedPhrases = []string{}
	}
	if res.topicNames == nil {
		res.topicNames = []string{}
	}
	a.chat = res
	return res, nil
}

func (a *mqlAwsQBusinessApplication) chatResponseScope() (string, error) {
	c, err := a.chatControls()
	if err != nil {
		return "", err
	}
	if c == nil || c.responseScope == "" {
		a.ChatResponseScope.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return c.responseScope, nil
}

func (a *mqlAwsQBusinessApplication) chatBlockedPhrases() ([]any, error) {
	c, err := a.chatControls()
	if err != nil {
		return nil, err
	}
	if c == nil {
		a.ChatBlockedPhrases.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.SliceAnyToInterface(c.blockedPhrases), nil
}

func (a *mqlAwsQBusinessApplication) chatTopicNames() ([]any, error) {
	c, err := a.chatControls()
	if err != nil {
		return nil, err
	}
	if c == nil {
		a.ChatTopicNames.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.SliceAnyToInterface(c.topicNames), nil
}

func (a *mqlAwsQBusinessApplication) chatCreatorModeEnabled() (bool, error) {
	c, err := a.chatControls()
	if err != nil {
		return false, err
	}
	var v qbusinesstypes.CreatorModeControl
	if c != nil {
		v = c.creatorMode
	}
	return qbusinessBoolField(v, &a.ChatCreatorModeEnabled)
}

func (a *mqlAwsQBusinessApplication) chatHallucinationReductionEnabled() (bool, error) {
	c, err := a.chatControls()
	if err != nil {
		return false, err
	}
	var v qbusinesstypes.HallucinationReductionControl
	if c != nil {
		v = c.hallucinationReduction
	}
	return qbusinessBoolField(v, &a.ChatHallucinationReductionEnabled)
}

func (a *mqlAwsQBusinessApplication) chatOrchestrationEnabled() (bool, error) {
	c, err := a.chatControls()
	if err != nil {
		return false, err
	}
	var v qbusinesstypes.OrchestrationControl
	if c != nil {
		v = c.orchestration
	}
	return qbusinessBoolField(v, &a.ChatOrchestrationEnabled)
}

// --- Resource-based policy ---

type qbusinessPolicyCache struct {
	policyLock       sync.Mutex
	policyFetched    atomic.Bool
	policyText       string
	policyAbsent     bool
	policyUnreadable bool
	policyErr        error
}

func (a *mqlAwsQBusinessApplication) loadPolicy() error {
	if a.policyFetched.Load() {
		return a.policyErr
	}
	a.policyLock.Lock()
	defer a.policyLock.Unlock()
	if a.policyFetched.Load() {
		return a.policyErr
	}
	defer a.policyFetched.Store(true)

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	appId := a.Id.Data
	out, err := conn.QBusiness(a.cacheRegion).GetPolicy(context.Background(), &qbusiness.GetPolicyInput{ApplicationId: &appId})
	if err != nil {
		switch {
		case isResourceNotFoundError(err):
			a.policyAbsent = true
		case Is400AccessDeniedError(err):
			if plugin.StructuredErrors() {
				a.policyErr = llx.Forbidden(err, llx.WithPermissions("qbusiness:GetPolicy"))
			} else {
				a.policyUnreadable = true
			}
		default:
			a.policyErr = err
		}
		return a.policyErr
	}
	a.policyText = convert.ToValue(out.Policy)
	if strings.TrimSpace(a.policyText) == "" {
		a.policyAbsent = true
	}
	return nil
}

func (a *mqlAwsQBusinessApplication) policy() (string, error) {
	if err := a.loadPolicy(); err != nil {
		return "", err
	}
	if a.policyAbsent || a.policyUnreadable {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return a.policyText, nil
}

func (a *mqlAwsQBusinessApplication) policyStatements() ([]any, error) {
	if err := a.loadPolicy(); err != nil {
		return nil, err
	}
	if a.policyUnreadable {
		// An empty list would claim the policy grants nothing; an unread
		// policy supports no such claim.
		a.PolicyStatements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.policyAbsent {
		return []any{}, nil
	}
	parent := a.GetArn()
	if parent.Error != nil {
		return nil, parent.Error
	}
	return newPolicyStatementResources(a.MqlRuntime, parent.Data, a.policyText)
}

func (a *mqlAwsQBusinessApplication) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

// --- Data accessors ---

type mqlAwsQBusinessDataAccessorInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     atomic.Bool
	detail      *qbusiness.GetDataAccessorOutput
}

func (a *mqlAwsQBusinessApplication) dataAccessors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := qbusiness.NewListDataAccessorsPaginator(svc, &qbusiness.ListDataAccessorsInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return res, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("qbusiness:ListDataAccessors"))
			}
			return nil, err
		}
		for _, d := range page.DataAccessors {
			authType := ""
			if d.AuthenticationDetail != nil {
				authType = string(d.AuthenticationDetail.AuthenticationType)
			}
			mqlD, err := CreateResource(a.MqlRuntime, ResourceAwsQBusinessDataAccessor, map[string]*llx.RawData{
				"__id":               llx.StringDataPtr(d.DataAccessorArn),
				"arn":                llx.StringDataPtr(d.DataAccessorArn),
				"id":                 llx.StringDataPtr(d.DataAccessorId),
				"applicationId":      llx.StringData(appId),
				"name":               llx.StringDataPtr(d.DisplayName),
				"region":             llx.StringData(region),
				"principal":          llx.StringDataPtr(d.Principal),
				"authenticationType": llx.StringData(authType),
				"idcApplicationArn":  llx.StringDataPtr(d.IdcApplicationArn),
				"createdAt":          llx.TimeDataPtr(d.CreatedAt),
				"updatedAt":          llx.TimeDataPtr(d.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			cast := mqlD.(*mqlAwsQBusinessDataAccessor)
			cast.cacheRegion = region
			res = append(res, cast)
		}
	}
	return res, nil
}

func (a *mqlAwsQBusinessDataAccessor) fetchDetail() (*qbusiness.GetDataAccessorOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	appId, accessorId := a.ApplicationId.Data, a.Id.Data
	out, err := conn.QBusiness(a.cacheRegion).GetDataAccessor(context.Background(), &qbusiness.GetDataAccessorInput{
		ApplicationId:  &appId,
		DataAccessorId: &accessorId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("qbusiness:GetDataAccessor"))
		}
		return nil, err
	}
	a.detail = out
	a.fetched.Store(true)
	return a.detail, nil
}

func dataAccessorActions(configs []qbusinesstypes.ActionConfiguration) []any {
	res := []any{}
	for _, c := range configs {
		if action := convert.ToValue(c.Action); action != "" {
			res = append(res, action)
		}
	}
	return res
}

func (a *mqlAwsQBusinessDataAccessor) actions() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.Actions.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return dataAccessorActions(detail.ActionConfigurations), nil
}

// --- Plugin ---

func (a *mqlAwsQBusinessPlugin) fetchDetail() (*qbusiness.GetPluginOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	appId, pluginId := a.ApplicationId.Data, a.Id.Data
	out, err := conn.QBusiness(a.Region.Data).GetPlugin(context.Background(), &qbusiness.GetPluginInput{ApplicationId: &appId, PluginId: &pluginId})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("qbusiness:GetPlugin"))
		}
		return nil, err
	}
	a.detail = out
	a.fetched.Store(true)
	return a.detail, nil
}

func pluginAuthType(cfg qbusinesstypes.PluginAuthConfiguration) string {
	switch cfg.(type) {
	case *qbusinesstypes.PluginAuthConfigurationMemberBasicAuthConfiguration:
		return "basicAuth"
	case *qbusinesstypes.PluginAuthConfigurationMemberOAuth2ClientCredentialConfiguration:
		return "oAuth2ClientCredential"
	case *qbusinesstypes.PluginAuthConfigurationMemberIdcAuthConfiguration:
		return "idcAuth"
	case *qbusinesstypes.PluginAuthConfigurationMemberNoAuthConfiguration:
		return "noAuth"
	}
	return ""
}

func (a *mqlAwsQBusinessPlugin) authType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	t := ""
	if detail != nil {
		t = pluginAuthType(detail.AuthConfiguration)
	}
	if t == "" {
		a.AuthType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return t, nil
}

// --- Web experience ---

func (a *mqlAwsQBusinessWebExperience) fetchDetail() (*qbusiness.GetWebExperienceOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	appId, webExperienceId := a.ApplicationId.Data, a.Id.Data
	out, err := conn.QBusiness(a.Region.Data).GetWebExperience(context.Background(), &qbusiness.GetWebExperienceInput{
		ApplicationId:   &appId,
		WebExperienceId: &webExperienceId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("qbusiness:GetWebExperience"))
		}
		return nil, err
	}
	a.detail = out
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsQBusinessWebExperience) arn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || convert.ToValue(detail.WebExperienceArn) == "" {
		a.Arn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.WebExperienceArn, nil
}

func (a *mqlAwsQBusinessWebExperience) origins() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.Origins.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.SliceAnyToInterface(detail.Origins), nil
}

func (a *mqlAwsQBusinessWebExperience) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.RoleArn) == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func webExperienceIdentityProviderType(cfg qbusinesstypes.IdentityProviderConfiguration) string {
	switch cfg.(type) {
	case *qbusinesstypes.IdentityProviderConfigurationMemberSamlConfiguration:
		return "saml"
	case *qbusinesstypes.IdentityProviderConfigurationMemberOpenIDConnectConfiguration:
		return "openIdConnect"
	}
	return ""
}

func (a *mqlAwsQBusinessWebExperience) identityProviderType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	t := ""
	if detail != nil {
		t = webExperienceIdentityProviderType(detail.IdentityProviderConfiguration)
	}
	if t == "" {
		a.IdentityProviderType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return t, nil
}

func (a *mqlAwsQBusinessWebExperience) browserExtensions() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.BrowserExtensions.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	if detail.BrowserExtensionConfiguration != nil {
		for _, e := range detail.BrowserExtensionConfiguration.EnabledBrowserExtensions {
			res = append(res, string(e))
		}
	}
	return res, nil
}
