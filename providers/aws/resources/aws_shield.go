// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/shield"
	shieldtypes "github.com/aws/aws-sdk-go-v2/service/shield/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsShield) id() (string, error) {
	return "aws.shield", nil
}

func (a *mqlAwsShield) subscriptionState() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1") // Shield is a global service, must use us-east-1
	ctx := context.Background()

	resp, err := svc.GetSubscriptionState(ctx, &shield.GetSubscriptionStateInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Msg("access denied querying Shield subscription state; returning UNKNOWN")
			return "UNKNOWN", nil
		}
		return "", err
	}
	return string(resp.SubscriptionState), nil
}

func (a *mqlAwsShield) subscription() (*mqlAwsShieldSubscription, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	ctx := context.Background()

	resp, err := svc.DescribeSubscription(ctx, &shield.DescribeSubscriptionInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.Subscription.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		var notFoundErr *shieldtypes.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			a.Subscription.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	sub := resp.Subscription
	// Per-resource-type protection limits, keyed by resource type. The SDK
	// returns these inside SubscriptionLimits.ProtectionLimits as a slice of
	// {Type, Max} entries — flatten into a map for direct key-based queries.
	protectedResourceTypeLimits := map[string]any{}
	var maxProtectionGroups int64
	var maxArbitraryPatternMembers int64
	if sub.SubscriptionLimits != nil {
		if pl := sub.SubscriptionLimits.ProtectionLimits; pl != nil {
			for _, l := range pl.ProtectedResourceTypeLimits {
				if l.Type == nil {
					continue
				}
				protectedResourceTypeLimits[*l.Type] = l.Max
			}
		}
		if pgl := sub.SubscriptionLimits.ProtectionGroupLimits; pgl != nil {
			maxProtectionGroups = pgl.MaxProtectionGroups
			if ptl := pgl.PatternTypeLimits; ptl != nil && ptl.ArbitraryPatternLimits != nil {
				maxArbitraryPatternMembers = ptl.ArbitraryPatternLimits.MaxMembers
			}
		}
	}

	mqlSub, err := CreateResource(a.MqlRuntime, "aws.shield.subscription",
		map[string]*llx.RawData{
			"arn":                         llx.StringDataPtr(sub.SubscriptionArn),
			"startTime":                   llx.TimeDataPtr(sub.StartTime),
			"endTime":                     llx.TimeDataPtr(sub.EndTime),
			"lengthInSeconds":             llx.IntData(sub.TimeCommitmentInSeconds),
			"autoRenewEnabled":            llx.BoolData(sub.AutoRenew == shieldtypes.AutoRenewEnabled),
			"protectedResourceTypeLimits": llx.MapData(protectedResourceTypeLimits, types.Int),
			"maxProtectionGroups":         llx.IntData(maxProtectionGroups),
			"maxArbitraryPatternMembers":  llx.IntData(maxArbitraryPatternMembers),
			"proactiveEngagementStatus":   llx.StringData(string(sub.ProactiveEngagementStatus)),
		})
	if err != nil {
		return nil, err
	}
	return mqlSub.(*mqlAwsShieldSubscription), nil
}

func (a *mqlAwsShieldSubscription) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsShield) protections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	ctx := context.Background()

	res := []any{}
	paginator := shield.NewListProtectionsPaginator(svc, &shield.ListProtectionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			var notFoundErr *shieldtypes.ResourceNotFoundException
			if errors.As(err, &notFoundErr) {
				return res, nil
			}
			return nil, err
		}
		for _, p := range page.Protections {
			appLayerEnabled := false
			appLayerAction := ""
			if cfg := p.ApplicationLayerAutomaticResponseConfiguration; cfg != nil {
				appLayerEnabled = cfg.Status == shieldtypes.ApplicationLayerAutomaticResponseStatusEnabled
				if cfg.Action != nil {
					switch {
					case cfg.Action.Block != nil:
						appLayerAction = "BLOCK"
					case cfg.Action.Count != nil:
						appLayerAction = "COUNT"
					}
				}
			}
			mqlProtection, err := CreateResource(a.MqlRuntime, "aws.shield.protection",
				map[string]*llx.RawData{
					"id":             llx.StringDataPtr(p.Id),
					"arn":            llx.StringDataPtr(p.ProtectionArn),
					"name":           llx.StringDataPtr(p.Name),
					"resourceArn":    llx.StringDataPtr(p.ResourceArn),
					"healthCheckIds": llx.ArrayData(llx.TArr2Raw(p.HealthCheckIds), "string"),
					"applicationLayerAutomaticResponseEnabled": llx.BoolData(appLayerEnabled),
					"applicationLayerAutomaticResponseAction":  llx.StringData(appLayerAction),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlProtection)
		}
	}
	return res, nil
}

func (a *mqlAwsShieldProtection) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsShield) protectionGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	ctx := context.Background()

	res := []any{}
	paginator := shield.NewListProtectionGroupsPaginator(svc, &shield.ListProtectionGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			var notFoundErr *shieldtypes.ResourceNotFoundException
			if errors.As(err, &notFoundErr) {
				return res, nil
			}
			return nil, err
		}
		for _, pg := range page.ProtectionGroups {
			mqlGroup, err := CreateResource(a.MqlRuntime, "aws.shield.protectionGroup",
				map[string]*llx.RawData{
					"id":           llx.StringDataPtr(pg.ProtectionGroupId),
					"arn":          llx.StringDataPtr(pg.ProtectionGroupArn),
					"aggregation":  llx.StringData(string(pg.Aggregation)),
					"pattern":      llx.StringData(string(pg.Pattern)),
					"resourceType": llx.StringData(string(pg.ResourceType)),
					"members":      llx.ArrayData(llx.TArr2Raw(pg.Members), "string"),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func (a *mqlAwsShieldProtectionGroup) id() (string, error) {
	if a.Arn.Error != nil {
		return "", a.Arn.Error
	}
	if a.Arn.Data != "" {
		return a.Arn.Data, nil
	}
	return "aws.shield.protectionGroup/" + a.Id.Data, a.Id.Error
}

func (a *mqlAwsShield) drtAccess() (*mqlAwsShieldDrtAccess, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	ctx := context.Background()

	resp, err := svc.DescribeDRTAccess(ctx, &shield.DescribeDRTAccessInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.DrtAccess.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		var notFoundErr *shieldtypes.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			a.DrtAccess.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	mqlDrt, err := CreateResource(a.MqlRuntime, "aws.shield.drtAccess",
		map[string]*llx.RawData{
			"logBucketList": llx.ArrayData(llx.TArr2Raw(resp.LogBucketList), "string"),
		})
	if err != nil {
		return nil, err
	}
	mqlDrtAccess := mqlDrt.(*mqlAwsShieldDrtAccess)
	mqlDrtAccess.cacheRoleArn = resp.RoleArn
	return mqlDrtAccess, nil
}

type mqlAwsShieldDrtAccessInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsShieldDrtAccess) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsShieldDrtAccess) id() (string, error) {
	return "aws.shield.drtAccess", nil
}

func (a *mqlAwsShield) emergencyContacts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	ctx := context.Background()

	resp, err := svc.DescribeEmergencyContactSettings(ctx, &shield.DescribeEmergencyContactSettingsInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		var notFoundErr *shieldtypes.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, ec := range resp.EmergencyContactList {
		mqlContact, err := CreateResource(a.MqlRuntime, "aws.shield.emergencyContact",
			map[string]*llx.RawData{
				"emailAddress": llx.StringDataPtr(ec.EmailAddress),
				"phoneNumber":  llx.StringDataPtr(ec.PhoneNumber),
				"contactNotes": llx.StringDataPtr(ec.ContactNotes),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlContact)
	}
	return res, nil
}

func (a *mqlAwsShieldEmergencyContact) id() (string, error) {
	return "aws.shield.emergencyContact/" + a.EmailAddress.Data, nil
}

// shieldTagsForArn reads the tags of a Shield protection or protection group.
// Shield is a global service served from us-east-1.
func shieldTagsForArn(runtime *plugin.Runtime, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Shield("us-east-1")
	resp, err := svc.ListTagsForResource(context.Background(), &shield.ListTagsForResourceInput{ResourceARN: &resourceArn})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if plugin.StructuredErrors() {
				return nil, llx.Forbidden(err, llx.WithPermissions("shield:ListTagsForResource"))
			}
			return nil, errTagsUnreadable
		}
		return nil, err
	}
	return tagsToMap(resp.Tags,
		func(t shieldtypes.Tag) *string { return t.Key },
		func(t shieldtypes.Tag) *string { return t.Value }), nil
}

type mqlAwsShieldProtectionInternal struct {
	lazyTags
}

func (a *mqlAwsShieldProtection) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return shieldTagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}

type mqlAwsShieldProtectionGroupInternal struct {
	lazyTags
}

func (a *mqlAwsShieldProtectionGroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return shieldTagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}
