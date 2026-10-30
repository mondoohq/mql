// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// --- Payments: payment managers ---

func (a *mqlAwsBedrockAgentCore) paymentManagers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListPaymentManagersPaginator(svc, &bedrockagentcorecontrol.ListPaymentManagersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range page.PaymentManagers {
				mqlManager, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.paymentManager", map[string]*llx.RawData{
					"__id":           llx.StringDataPtr(m.PaymentManagerArn),
					"arn":            llx.StringDataPtr(m.PaymentManagerArn),
					"id":             llx.StringDataPtr(m.PaymentManagerId),
					"name":           llx.StringDataPtr(m.Name),
					"region":         llx.StringData(region),
					"description":    llx.StringDataPtr(m.Description),
					"status":         llx.StringDataPtr(nonEmptyEnum(m.Status)),
					"authorizerType": llx.StringDataPtr(nonEmptyEnum(m.AuthorizerType)),
					"createdAt":      llx.TimeDataPtr(m.CreatedAt),
					"updatedAt":      llx.TimeDataPtr(m.LastUpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlManagerRes := mqlManager.(*mqlAwsBedrockAgentCorePaymentManager)
				mqlManagerRes.cacheRoleArn = convert.ToValue(m.RoleArn)
				mqlManagerRes.cacheKmsKeyArn = convert.ToValue(m.KmsKeyArn)
				res = append(res, mqlManagerRes)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCorePaymentManagerInternal struct {
	cacheRoleArn   string
	cacheKmsKeyArn string
	fetchLock      sync.Mutex
	fetched        bool
	detail         *bedrockagentcorecontrol.GetPaymentManagerOutput
}

// fetchDetail loads the workload identity and tags, which the list operation
// does not return.
func (a *mqlAwsBedrockAgentCorePaymentManager) fetchDetail() (*bedrockagentcorecontrol.GetPaymentManagerOutput, error) {
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.Region.Data)
	managerId := a.Id.Data
	detail, err := svc.GetPaymentManager(context.Background(), &bedrockagentcorecontrol.GetPaymentManagerInput{
		PaymentManagerId: &managerId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.fetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:GetPaymentManager"))
		}
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCorePaymentManager) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBedrockAgentCorePaymentManager) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBedrockAgentCorePaymentManager) workloadIdentity() (*mqlAwsBedrockAgentCoreWorkloadIdentity, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.WorkloadIdentityDetails == nil || convert.ToValue(detail.WorkloadIdentityDetails.WorkloadIdentityArn) == "" {
		a.WorkloadIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.agentCore.workloadIdentity",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.WorkloadIdentityDetails.WorkloadIdentityArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockAgentCoreWorkloadIdentity), nil
}

// tags reads the payment manager's tags from ListTagsForResource.
// GetPaymentManager declares a tags field but never fills it.
func (a *mqlAwsBedrockAgentCorePaymentManager) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.Region.Data)
	arn := a.Arn.Data
	out, err := svc.ListTagsForResource(context.Background(), &bedrockagentcorecontrol.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.Tags.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:ListTagsForResource"))
		}
		return nil, err
	}
	return toInterfaceMap(out.Tags), nil
}

// --- Payments: payment connectors ---

// bedrockAgentCorePaymentConnectorId builds the cache key of a payment
// connector. Connectors have no ARN of their own and their ids are only
// unique within the payment manager that owns them.
func bedrockAgentCorePaymentConnectorId(managerArn, connectorId string) string {
	return managerArn + "/paymentConnector/" + connectorId
}

func (a *mqlAwsBedrockAgentCorePaymentManager) connectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.BedrockAgentCoreControl(region)
	ctx := context.Background()
	managerId := a.Id.Data
	managerArn := a.Arn.Data
	res := []any{}

	paginator := bedrockagentcorecontrol.NewListPaymentConnectorsPaginator(svc, &bedrockagentcorecontrol.ListPaymentConnectorsInput{
		PaymentManagerId: &managerId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return []any{}, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:ListPaymentConnectors"))
			}
			return nil, err
		}
		for _, c := range page.PaymentConnectors {
			connectorId := convert.ToValue(c.PaymentConnectorId)
			mqlConnector, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.paymentConnector", map[string]*llx.RawData{
				"__id":          llx.StringData(bedrockAgentCorePaymentConnectorId(managerArn, connectorId)),
				"id":            llx.StringData(connectorId),
				"name":          llx.StringDataPtr(c.Name),
				"region":        llx.StringData(region),
				"status":        llx.StringDataPtr(nonEmptyEnum(c.Status)),
				"type":          llx.StringDataPtr(nonEmptyEnum(c.Type)),
				"provisionMode": llx.StringDataPtr(nonEmptyEnum(c.ProvisionMode)),
				"updatedAt":     llx.TimeDataPtr(c.LastUpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			mqlConnectorRes := mqlConnector.(*mqlAwsBedrockAgentCorePaymentConnector)
			mqlConnectorRes.cachePaymentManagerId = managerId
			res = append(res, mqlConnectorRes)
		}
	}
	return res, nil
}

type mqlAwsBedrockAgentCorePaymentConnectorInternal struct {
	cachePaymentManagerId string
	fetchLock             sync.Mutex
	fetched               bool
	detail                *bedrockagentcorecontrol.GetPaymentConnectorOutput
}

// fetchDetail loads the creation time, credential timestamps, and credential
// provider configuration, which the list operation does not return.
func (a *mqlAwsBedrockAgentCorePaymentConnector) fetchDetail() (*bedrockagentcorecontrol.GetPaymentConnectorOutput, error) {
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.Region.Data)
	managerId := a.cachePaymentManagerId
	connectorId := a.Id.Data
	detail, err := svc.GetPaymentConnector(context.Background(), &bedrockagentcorecontrol.GetPaymentConnectorInput{
		PaymentManagerId:   &managerId,
		PaymentConnectorId: &connectorId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.fetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:GetPaymentConnector"))
		}
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCorePaymentConnector) description() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.Description == nil {
		a.Description.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.Description, nil
}

func (a *mqlAwsBedrockAgentCorePaymentConnector) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.CreatedAt == nil {
		a.CreatedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return detail.CreatedAt, nil
}

func (a *mqlAwsBedrockAgentCorePaymentConnector) credentialsUpdatedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.CredentialsUpdatedAt == nil {
		a.CredentialsUpdatedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return detail.CredentialsUpdatedAt, nil
}

// paymentCredentialProviderArns extracts the credential provider ARNs from a
// connector's per-vendor credential configurations, skipping members this SDK
// version does not know and entries without an ARN.
func paymentCredentialProviderArns(configs []bacctypes.CredentialsProviderConfiguration) []string {
	res := []string{}
	for _, cfg := range configs {
		var arn string
		switch v := cfg.(type) {
		case *bacctypes.CredentialsProviderConfigurationMemberCoinbaseCDP:
			arn = convert.ToValue(v.Value.CredentialProviderArn)
		case *bacctypes.CredentialsProviderConfigurationMemberStripePrivy:
			arn = convert.ToValue(v.Value.CredentialProviderArn)
		}
		if arn != "" {
			res = append(res, arn)
		}
	}
	return res
}

func (a *mqlAwsBedrockAgentCorePaymentConnector) credentialProviders() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.CredentialProviders.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	arns := paymentCredentialProviderArns(detail.CredentialProviderConfigurations)
	if len(arns) == 0 {
		return []any{}, nil
	}

	// Resolve against the account-wide listing, which is fetched once and
	// cached on the AgentCore namespace, instead of one lookup per connector.
	agentCore, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore", map[string]*llx.RawData{
		"__id": llx.StringData("aws.bedrock.agentCore"),
	})
	if err != nil {
		return nil, err
	}
	listed := agentCore.(*mqlAwsBedrockAgentCore).GetPaymentCredentialProviders()
	if listed.Error != nil {
		return nil, listed.Error
	}
	byArn := map[string]any{}
	for _, p := range listed.Data {
		provider := p.(*mqlAwsBedrockAgentCorePaymentCredentialProvider)
		byArn[provider.Arn.Data] = provider
	}

	res := []any{}
	for _, arn := range arns {
		if provider, ok := byArn[arn]; ok {
			res = append(res, provider)
			continue
		}
		// Not in the listing (another account's provider, or a region that
		// could not be listed): report the reference with what the ARN says
		// and leave the rest unread.
		region, _ := GetRegionFromArn(arn)
		provider, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.paymentCredentialProvider", map[string]*llx.RawData{
			"__id":      llx.StringData(arn),
			"arn":       llx.StringData(arn),
			"name":      llx.NilData,
			"region":    llx.StringData(region),
			"vendor":    llx.NilData,
			"createdAt": llx.NilData,
			"updatedAt": llx.NilData,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, provider)
	}
	return res, nil
}

// --- Payments: payment credential providers ---

func (a *mqlAwsBedrockAgentCore) paymentCredentialProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListPaymentCredentialProvidersPaginator(svc, &bedrockagentcorecontrol.ListPaymentCredentialProvidersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, p := range page.CredentialProviders {
				mqlProvider, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.paymentCredentialProvider", map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(p.CredentialProviderArn),
					"arn":       llx.StringDataPtr(p.CredentialProviderArn),
					"name":      llx.StringDataPtr(p.Name),
					"region":    llx.StringData(region),
					"vendor":    llx.StringDataPtr(nonEmptyEnum(p.CredentialProviderVendor)),
					"createdAt": llx.TimeDataPtr(p.CreatedTime),
					"updatedAt": llx.TimeDataPtr(p.LastUpdatedTime),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProvider)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCorePaymentCredentialProviderInternal struct {
	lazyTags
}

func (a *mqlAwsBedrockAgentCorePaymentCredentialProvider) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return agentCoreTags(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}
