// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- registries ---

func (a *mqlAwsEcr) registries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "ecr", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Ecr(region)
		out, err := svc.DescribeRegistry(ctx, &ecr.DescribeRegistryInput{})
		if err != nil {
			return nil, err
		}
		replication := llx.NilData
		if out.ReplicationConfiguration != nil && len(out.ReplicationConfiguration.Rules) > 0 {
			replication = llx.DictData(ecrReplicationConfigurationToDict(out.ReplicationConfiguration))
		}
		registryID := convert.ToValue(out.RegistryId)
		res, err := CreateResource(a.MqlRuntime, ResourceAwsEcrRegistry, map[string]*llx.RawData{
			"__id":                     llx.StringData("aws.ecr.registry/" + region + "/" + registryID),
			"registryId":               llx.StringData(registryID),
			"region":                   llx.StringData(region),
			"replicationConfiguration": replication,
		})
		if err != nil {
			return nil, err
		}
		return []any{res}, nil
	})
}

func (a *mqlAwsEcrRegistry) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcrRegistry) policy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr(a.Region.Data)
	out, err := svc.GetRegistryPolicy(context.Background(), &ecr.GetRegistryPolicyInput{})
	if err != nil {
		var notFound *ecrtypes.RegistryPolicyNotFoundException
		if errors.As(err, &notFound) {
			a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
				return "", nil
			}
			return "", llx.Forbidden(err, llx.WithPermissions("ecr:GetRegistryPolicy"))
		}
		return "", err
	}
	if out.PolicyText == nil {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *out.PolicyText, nil
}

// ecrSigningRulesToDicts renders the registry signing rules with the keys the
// schema documents; the SDK structs carry no json tags.
func ecrSigningRulesToDicts(cfg *ecrtypes.SigningConfiguration) []any {
	res := []any{}
	if cfg == nil {
		return res
	}
	for _, rule := range cfg.Rules {
		filters := make([]any, 0, len(rule.RepositoryFilters))
		for _, f := range rule.RepositoryFilters {
			filters = append(filters, map[string]any{
				"filter":     convert.ToValue(f.Filter),
				"filterType": string(f.FilterType),
			})
		}
		res = append(res, map[string]any{
			"signingProfileArn": convert.ToValue(rule.SigningProfileArn),
			"repositoryFilters": filters,
		})
	}
	return res
}

func (a *mqlAwsEcrRegistry) signingRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ecr(a.Region.Data)
	out, err := svc.GetSigningConfiguration(context.Background(), &ecr.GetSigningConfigurationInput{})
	if err != nil {
		var notFound *ecrtypes.SigningConfigurationNotFoundException
		if errors.As(err, &notFound) {
			return []any{}, nil
		}
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.SigningRules.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("ecr:GetSigningConfiguration"))
		}
		return nil, err
	}
	return ecrSigningRulesToDicts(out.SigningConfiguration), nil
}

// --- pull-through cache rules ---

func (a *mqlAwsEcr) pullThroughCacheRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "ecr", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Ecr(region)
		res := []any{}
		paginator := ecr.NewDescribePullThroughCacheRulesPaginator(svc, &ecr.DescribePullThroughCacheRulesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, rule := range page.PullThroughCacheRules {
				prefix := convert.ToValue(rule.EcrRepositoryPrefix)
				mqlRule, err := CreateResource(a.MqlRuntime, ResourceAwsEcrPullThroughCacheRule, map[string]*llx.RawData{
					"__id":                     llx.StringData("aws.ecr.pullThroughCacheRule/" + region + "/" + convert.ToValue(rule.RegistryId) + "/" + prefix),
					"ecrRepositoryPrefix":      llx.StringData(prefix),
					"upstreamRegistryUrl":      llx.StringDataPtr(rule.UpstreamRegistryUrl),
					"upstreamRegistry":         llx.StringDataPtr(nonEmptyEnum(rule.UpstreamRegistry)),
					"upstreamRepositoryPrefix": llx.StringDataPtr(rule.UpstreamRepositoryPrefix),
					"registryId":               llx.StringDataPtr(rule.RegistryId),
					"region":                   llx.StringData(region),
					"createdAt":                llx.TimeDataPtr(rule.CreatedAt),
					"updatedAt":                llx.TimeDataPtr(rule.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				r := mqlRule.(*mqlAwsEcrPullThroughCacheRule)
				r.cacheCredentialArn = convert.ToValue(rule.CredentialArn)
				r.cacheCustomRoleArn = convert.ToValue(rule.CustomRoleArn)
				res = append(res, r)
			}
		}
		return res, nil
	})
}

type mqlAwsEcrPullThroughCacheRuleInternal struct {
	cacheCredentialArn string
	cacheCustomRoleArn string
}

func (a *mqlAwsEcrPullThroughCacheRule) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcrPullThroughCacheRule) credential() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheCredentialArn == "" {
		a.Credential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsSecretsmanagerSecret, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheCredentialArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func ecrRole(runtime *plugin.Runtime, roleArn string, field *plugin.TValue[*mqlAwsIamRole]) (*mqlAwsIamRole, error) {
	if roleArn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAwsIamRole, map[string]*llx.RawData{
		"arn": llx.StringData(roleArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEcrPullThroughCacheRule) customRole() (*mqlAwsIamRole, error) {
	return ecrRole(a.MqlRuntime, a.cacheCustomRoleArn, &a.CustomRole)
}

// --- repository creation templates ---

func (a *mqlAwsEcr) repositoryCreationTemplates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "ecr", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Ecr(region)
		res := []any{}
		paginator := ecr.NewDescribeRepositoryCreationTemplatesPaginator(svc, &ecr.DescribeRepositoryCreationTemplatesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, tpl := range page.RepositoryCreationTemplates {
				mqlTpl, err := newMqlEcrRepositoryCreationTemplate(a.MqlRuntime, region, convert.ToValue(page.RegistryId), tpl)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlTpl)
			}
		}
		return res, nil
	})
}

func newMqlEcrRepositoryCreationTemplate(runtime *plugin.Runtime, region, registryID string, tpl ecrtypes.RepositoryCreationTemplate) (*mqlAwsEcrRepositoryCreationTemplate, error) {
	prefix := convert.ToValue(tpl.Prefix)
	appliedFor := make([]any, 0, len(tpl.AppliedFor))
	for _, v := range tpl.AppliedFor {
		appliedFor = append(appliedFor, string(v))
	}
	resourceTags := make(map[string]any, len(tpl.ResourceTags))
	for _, t := range tpl.ResourceTags {
		if t.Key != nil {
			resourceTags[*t.Key] = convert.ToValue(t.Value)
		}
	}
	var encryptionType *string
	var kmsKey *string
	if tpl.EncryptionConfiguration != nil {
		encryptionType = nonEmptyEnum(tpl.EncryptionConfiguration.EncryptionType)
		if tpl.EncryptionConfiguration.KmsKey != nil && *tpl.EncryptionConfiguration.KmsKey != "" {
			kmsKey = tpl.EncryptionConfiguration.KmsKey
		}
	}
	res, err := CreateResource(runtime, ResourceAwsEcrRepositoryCreationTemplate, map[string]*llx.RawData{
		"__id":               llx.StringData("aws.ecr.repositoryCreationTemplate/" + region + "/" + registryID + "/" + prefix),
		"prefix":             llx.StringData(prefix),
		"region":             llx.StringData(region),
		"description":        llx.StringDataPtr(tpl.Description),
		"appliedFor":         llx.ArrayData(appliedFor, types.String),
		"imageTagMutability": llx.StringDataPtr(nonEmptyEnum(tpl.ImageTagMutability)),
		"encryptionType":     llx.StringDataPtr(encryptionType),
		"repositoryPolicy":   llx.StringDataPtr(tpl.RepositoryPolicy),
		"lifecyclePolicy":    llx.StringDataPtr(tpl.LifecyclePolicy),
		"resourceTags":       llx.MapData(resourceTags, types.String),
		"createdAt":          llx.TimeDataPtr(tpl.CreatedAt),
		"updatedAt":          llx.TimeDataPtr(tpl.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	mqlTpl := res.(*mqlAwsEcrRepositoryCreationTemplate)
	mqlTpl.cacheKmsKey = kmsKey
	mqlTpl.cacheCustomRoleArn = convert.ToValue(tpl.CustomRoleArn)
	return mqlTpl, nil
}

type mqlAwsEcrRepositoryCreationTemplateInternal struct {
	cacheKmsKey        *string
	cacheCustomRoleArn string
}

func (a *mqlAwsEcrRepositoryCreationTemplate) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsEcrRepositoryCreationTemplate) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKey, a.Region.Data, &a.KmsKey.State)
}

func (a *mqlAwsEcrRepositoryCreationTemplate) customRole() (*mqlAwsIamRole, error) {
	return ecrRole(a.MqlRuntime, a.cacheCustomRoleArn, &a.CustomRole)
}
