// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

// -- Origin access controls -------------------------------------------------

func (a *mqlAwsCloudfrontOriginAccessControl) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) originAccessControls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListOriginAccessControls(ctx, &cloudfront.ListOriginAccessControlsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListOriginAccessControls"), "could not gather aws cloudfront origin access controls")
		}
		if resp.OriginAccessControlList == nil {
			break
		}
		for _, item := range resp.OriginAccessControlList.Items {
			args := map[string]*llx.RawData{
				"id":                            llx.StringDataPtr(item.Id),
				"name":                          llx.StringDataPtr(item.Name),
				"description":                   llx.StringDataPtr(item.Description),
				"signingProtocol":               llx.StringData(string(item.SigningProtocol)),
				"signingBehavior":               llx.StringData(string(item.SigningBehavior)),
				"originAccessControlOriginType": llx.StringData(string(item.OriginAccessControlOriginType)),
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.originAccessControl", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.OriginAccessControlList.NextMarker == nil {
			break
		}
		marker = resp.OriginAccessControlList.NextMarker
	}
	return res, nil
}

// -- Key value stores -------------------------------------------------------

func (a *mqlAwsCloudfrontKeyValueStore) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) keyValueStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListKeyValueStores(ctx, &cloudfront.ListKeyValueStoresInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListKeyValueStores"), "could not gather aws cloudfront key value stores")
		}
		if resp.KeyValueStoreList == nil {
			break
		}
		for _, item := range resp.KeyValueStoreList.Items {
			args := map[string]*llx.RawData{
				"id":               llx.StringDataPtr(item.Id),
				"name":             llx.StringDataPtr(item.Name),
				"comment":          llx.StringDataPtr(item.Comment),
				"status":           llx.StringDataPtr(item.Status),
				"arn":              llx.StringDataPtr(item.ARN),
				"lastModifiedTime": llx.TimeDataPtr(item.LastModifiedTime),
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.keyValueStore", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.KeyValueStoreList.NextMarker == nil {
			break
		}
		marker = resp.KeyValueStoreList.NextMarker
	}
	return res, nil
}

// -- Public keys ------------------------------------------------------------

func (a *mqlAwsCloudfrontPublicKey) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) publicKeys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListPublicKeys(ctx, &cloudfront.ListPublicKeysInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListPublicKeys"), "could not gather aws cloudfront public keys")
		}
		if resp.PublicKeyList == nil {
			break
		}
		for _, item := range resp.PublicKeyList.Items {
			args := map[string]*llx.RawData{
				"id":          llx.StringDataPtr(item.Id),
				"name":        llx.StringDataPtr(item.Name),
				"comment":     llx.StringDataPtr(item.Comment),
				"encodedKey":  llx.StringDataPtr(item.EncodedKey),
				"createdTime": llx.TimeDataPtr(item.CreatedTime),
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.publicKey", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.PublicKeyList.NextMarker == nil {
			break
		}
		marker = resp.PublicKeyList.NextMarker
	}
	return res, nil
}

func initAwsCloudfrontPublicKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}

	obj, err := CreateResource(runtime, "aws.cloudfront", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cf := obj.(*mqlAwsCloudfront)
	keys := cf.GetPublicKeys()
	if keys.Error != nil {
		return nil, nil, keys.Error
	}
	idVal, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a string")
	}
	for _, raw := range keys.Data {
		pk := raw.(*mqlAwsCloudfrontPublicKey)
		if pk.Id.Data == idVal {
			return args, pk, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, errors.Errorf("aws.cloudfront.publicKey with id %q not found", idVal)
}

// -- Key groups -------------------------------------------------------------

func (a *mqlAwsCloudfrontKeyGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) keyGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListKeyGroups(ctx, &cloudfront.ListKeyGroupsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListKeyGroups"), "could not gather aws cloudfront key groups")
		}
		if resp.KeyGroupList == nil {
			break
		}
		for _, item := range resp.KeyGroupList.Items {
			kg := item.KeyGroup
			if kg == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"id":               llx.StringDataPtr(kg.Id),
				"lastModifiedTime": llx.TimeDataPtr(kg.LastModifiedTime),
				"items":            llx.ArrayData([]any{}, mqltypes.String),
				"name":             llx.StringData(""),
				"comment":          llx.StringData(""),
			}
			if kg.KeyGroupConfig != nil {
				args["name"] = llx.StringDataPtr(kg.KeyGroupConfig.Name)
				args["comment"] = llx.StringDataPtr(kg.KeyGroupConfig.Comment)
				args["items"] = llx.ArrayData(toAnySlice(kg.KeyGroupConfig.Items), mqltypes.String)
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.keyGroup", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.KeyGroupList.NextMarker == nil {
			break
		}
		marker = resp.KeyGroupList.NextMarker
	}
	return res, nil
}

func (a *mqlAwsCloudfrontKeyGroup) publicKeys() ([]any, error) {
	ids := a.Items.Data
	res := make([]any, 0, len(ids))
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		mqlPk, err := NewResource(a.MqlRuntime, "aws.cloudfront.publicKey",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		if mqlPk == nil {
			continue
		}
		res = append(res, mqlPk)
	}
	return res, nil
}

// -- Field-level encryption configurations ----------------------------------

func (a *mqlAwsCloudfrontFieldLevelEncryptionConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) fieldLevelEncryptionConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListFieldLevelEncryptionConfigs(ctx, &cloudfront.ListFieldLevelEncryptionConfigsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListFieldLevelEncryptionConfigs"), "could not gather aws cloudfront field level encryption configs")
		}
		if resp.FieldLevelEncryptionList == nil {
			break
		}
		for _, item := range resp.FieldLevelEncryptionList.Items {
			args := map[string]*llx.RawData{
				"id":                       llx.StringDataPtr(item.Id),
				"lastModifiedTime":         llx.TimeDataPtr(item.LastModifiedTime),
				"comment":                  llx.StringDataPtr(item.Comment),
				"queryArgProfileConfig":    llx.MapData(cloudfrontQueryArgProfileToDict(item.QueryArgProfileConfig), mqltypes.Any),
				"contentTypeProfileConfig": llx.MapData(cloudfrontContentTypeProfileToDict(item.ContentTypeProfileConfig), mqltypes.Any),
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.fieldLevelEncryptionConfig", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.FieldLevelEncryptionList.NextMarker == nil {
			break
		}
		marker = resp.FieldLevelEncryptionList.NextMarker
	}
	return res, nil
}

func cloudfrontQueryArgProfileToDict(q *types.QueryArgProfileConfig) map[string]any {
	if q == nil {
		return nil
	}
	out := map[string]any{}
	if q.ForwardWhenQueryArgProfileIsUnknown != nil {
		out["forwardWhenQueryArgProfileIsUnknown"] = *q.ForwardWhenQueryArgProfileIsUnknown
	}
	profiles := []any{}
	if q.QueryArgProfiles != nil {
		for _, p := range q.QueryArgProfiles.Items {
			entry := map[string]any{}
			if p.QueryArg != nil {
				entry["queryArg"] = *p.QueryArg
			}
			if p.ProfileId != nil {
				entry["profileId"] = *p.ProfileId
			}
			profiles = append(profiles, entry)
		}
	}
	out["profiles"] = profiles
	return out
}

func cloudfrontContentTypeProfileToDict(c *types.ContentTypeProfileConfig) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{}
	if c.ForwardWhenContentTypeIsUnknown != nil {
		out["forwardWhenContentTypeIsUnknown"] = *c.ForwardWhenContentTypeIsUnknown
	}
	profiles := []any{}
	if c.ContentTypeProfiles != nil {
		for _, p := range c.ContentTypeProfiles.Items {
			entry := map[string]any{}
			if p.ContentType != nil {
				entry["contentType"] = *p.ContentType
			}
			if p.ProfileId != nil {
				entry["profileId"] = *p.ProfileId
			}
			entry["format"] = string(p.Format)
			profiles = append(profiles, entry)
		}
	}
	out["profiles"] = profiles
	return out
}

// -- Field-level encryption profiles ----------------------------------------

func (a *mqlAwsCloudfrontFieldLevelEncryptionProfile) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsCloudfront) fieldLevelEncryptionProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudfront("")
	ctx := context.Background()

	res := []any{}
	var marker *string
	for {
		resp, err := svc.ListFieldLevelEncryptionProfiles(ctx, &cloudfront.ListFieldLevelEncryptionProfilesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, errors.Wrap(classifyAwsError(err, "cloudfront:ListFieldLevelEncryptionProfiles"), "could not gather aws cloudfront field level encryption profiles")
		}
		if resp.FieldLevelEncryptionProfileList == nil {
			break
		}
		for _, item := range resp.FieldLevelEncryptionProfileList.Items {
			args := map[string]*llx.RawData{
				"id":                 llx.StringDataPtr(item.Id),
				"name":               llx.StringDataPtr(item.Name),
				"comment":            llx.StringDataPtr(item.Comment),
				"lastModifiedTime":   llx.TimeDataPtr(item.LastModifiedTime),
				"encryptionEntities": llx.ArrayData(cloudfrontEncryptionEntitiesToDictSlice(item.EncryptionEntities), mqltypes.Any),
			}
			mqlResource, err := CreateResource(a.MqlRuntime, "aws.cloudfront.fieldLevelEncryptionProfile", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlResource)
		}
		if resp.FieldLevelEncryptionProfileList.NextMarker == nil {
			break
		}
		marker = resp.FieldLevelEncryptionProfileList.NextMarker
	}
	return res, nil
}

func cloudfrontEncryptionEntitiesToDictSlice(e *types.EncryptionEntities) []any {
	if e == nil || len(e.Items) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(e.Items))
	for _, item := range e.Items {
		entry := map[string]any{}
		if item.PublicKeyId != nil {
			entry["publicKeyId"] = *item.PublicKeyId
		}
		if item.ProviderId != nil {
			entry["providerId"] = *item.ProviderId
		}
		patterns := []any{}
		if item.FieldPatterns != nil {
			for _, p := range item.FieldPatterns.Items {
				patterns = append(patterns, p)
			}
		}
		entry["fieldPatterns"] = patterns
		out = append(out, entry)
	}
	return out
}
