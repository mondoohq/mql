// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// bedrockKnowledgeBaseVpcConfigurationId builds the cache key of a knowledge
// base VPC configuration. The configuration id is only unique within its
// knowledge base, and knowledge base ids are only unique within a region.
func bedrockKnowledgeBaseVpcConfigurationId(region, knowledgeBaseId, vpcConfigurationId string) string {
	return region + "/" + knowledgeBaseId + "/vpcConfiguration/" + vpcConfigurationId
}

func (a *mqlAwsBedrockKnowledgeBase) vpcConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.BedrockAgent(region)
	ctx := context.Background()
	kbId := a.Id.Data
	res := []any{}

	paginator := bedrockagent.NewListVpcConfigurationsPaginator(svc, &bedrockagent.ListVpcConfigurationsInput{
		KnowledgeBaseId: &kbId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return []any{}, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("bedrock:ListVpcConfigurations"))
			}
			return nil, err
		}
		for i := range page.Items {
			mqlCfg, err := newMqlAwsBedrockKnowledgeBaseVpcConfiguration(a.MqlRuntime, region, kbId, &page.Items[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCfg)
		}
	}
	return res, nil
}

func newMqlAwsBedrockKnowledgeBaseVpcConfiguration(runtime *plugin.Runtime, region, kbId string, item *bedrockagenttypes.VpcConfigurationSummary) (*mqlAwsBedrockKnowledgeBaseVpcConfiguration, error) {
	cfgId := convert.ToValue(item.VpcConfigurationId)
	port := llx.NilData
	if item.Port != nil {
		port = llx.IntData(int64(*item.Port))
	}
	res, err := CreateResource(runtime, "aws.bedrock.knowledgeBase.vpcConfiguration", map[string]*llx.RawData{
		"__id":           llx.StringData(bedrockKnowledgeBaseVpcConfigurationId(region, kbId, cfgId)),
		"id":             llx.StringData(cfgId),
		"region":         llx.StringData(region),
		"name":           llx.StringDataPtr(item.Name),
		"description":    llx.StringDataPtr(item.Description),
		"status":         llx.StringDataPtr(nonEmptyEnum(item.Status)),
		"statusMessage":  llx.StringDataPtr(item.StatusMessage),
		"protocol":       llx.StringDataPtr(nonEmptyEnum(item.Protocol)),
		"port":           port,
		"resourceTarget": llx.StringDataPtr(item.ResourceTarget),
		"resolutionMode": llx.StringDataPtr(nonEmptyEnum(item.ResolutionMode)),
		"hostHeader":     llx.StringDataPtr(item.HostHeader),
		"tlsServerName":  llx.StringDataPtr(item.TlsServerName),
		"createdAt":      llx.TimeDataPtr(item.CreatedAt),
	})
	if err != nil {
		return nil, err
	}
	mqlCfg := res.(*mqlAwsBedrockKnowledgeBaseVpcConfiguration)
	mqlCfg.cacheKnowledgeBaseId = kbId
	mqlCfg.cacheVpcId = convert.ToValue(item.VpcId)
	return mqlCfg, nil
}

type mqlAwsBedrockKnowledgeBaseVpcConfigurationInternal struct {
	cacheKnowledgeBaseId string
	cacheVpcId           string
	fetchLock            sync.Mutex
	fetched              bool
	detail               *bedrockagenttypes.VpcConfiguration
}

// fetchDetail loads the subnets and last-update time, which the list
// operation does not return.
func (a *mqlAwsBedrockKnowledgeBaseVpcConfiguration) fetchDetail() (*bedrockagenttypes.VpcConfiguration, error) {
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.Region.Data)
	kbId := a.cacheKnowledgeBaseId
	cfgId := a.Id.Data
	out, err := svc.GetVpcConfiguration(context.Background(), &bedrockagent.GetVpcConfigurationInput{
		KnowledgeBaseId:    &kbId,
		VpcConfigurationId: &cfgId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.fetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock:GetVpcConfiguration"))
		}
		return nil, err
	}
	a.detail = out.VpcConfiguration
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockKnowledgeBaseVpcConfiguration) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), a.cacheVpcId)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsBedrockKnowledgeBaseVpcConfiguration) subnets() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.Subnets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, subnetId := range detail.SubnetIds {
		if subnetId == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), subnetId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsBedrockKnowledgeBaseVpcConfiguration) updatedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.UpdatedAt == nil {
		a.UpdatedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return detail.UpdatedAt, nil
}
