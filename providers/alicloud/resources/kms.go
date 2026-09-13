// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	kmsclient "github.com/alibabacloud-go/kms-20160120/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// alicloudParseTime parses an Alibaba Cloud UTC timestamp (for example
// 2026-01-02T15:04:05Z), returning nil on a nil or unparseable input. It is
// shared by services that return RFC3339 timestamps (KMS, ActionTrail).
func alicloudParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}

// parseRotationIntervalSeconds converts a KMS rotation interval, a decimal
// number of seconds carrying an optional "s" suffix such as 31536000s, into
// seconds. It reports false when the input is empty or is not a whole,
// non-negative number of seconds, so the caller can leave the field null
// instead of claiming a measured interval of zero.
func parseRotationIntervalSeconds(v string) (int64, bool) {
	digits := strings.TrimSuffix(strings.TrimSpace(v), "s")
	if digits == "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return seconds, true
}

// kmsRotationIntervalSeconds returns the rotation interval in seconds, or nil
// when KMS reported no interval, which keeps the MQL field null.
func kmsRotationIntervalSeconds(v string) *int64 {
	seconds, ok := parseRotationIntervalSeconds(v)
	if !ok {
		return nil
	}
	return &seconds
}

func (r *mqlAlicloudKms) id() (string, error) {
	return "alicloud.kms", nil
}

// mqlAlicloudKmsKeyInternal caches the region and key id needed to resolve the
// key's alias list and to build its cache key.
type mqlAlicloudKmsKeyInternal struct {
	kmsKeyPolicyState
	region string
	keyId  string
}

// mqlAlicloudKmsSecretInternal caches the region and the id of the customer
// master key that encrypts the secret, for the typed encryptionKey() reference.
type mqlAlicloudKmsSecretInternal struct {
	region               string
	cacheEncryptionKeyId string
}

func (r *mqlAlicloudKms) keys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.KmsClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.ListKeys(&kmsclient.ListKeysRequest{
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(pageSize),
			})
			if err != nil {
				// A first-page error means the region has no KMS or the
				// credential lacks access there; skip it. A later-page error is
				// real (region reachable) — surface it rather than silently
				// truncating the key list.
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.Keys == nil {
				break
			}

			items := resp.Body.Keys.Key
			for _, k := range items {
				if k == nil || k.KeyId == nil {
					continue
				}
				// ListKeys returns only KeyId and KeyArn, so a DescribeKey call
				// per key is required to populate the key metadata. This is an
				// unavoidable N+1 for the number of keys in the region.
				meta, err := describeKmsKey(conn, region, tea.StringValue(k.KeyId))
				if err != nil {
					// Log rather than silently drop the key so a per-key
					// permission or throttle failure leaves a trace instead of a
					// gap in the key enumeration.
					log.Warn().Err(err).Str("region", region).Str("keyId", tea.StringValue(k.KeyId)).
						Msg("alicloud: failed to describe KMS key")
					continue
				}
				if meta == nil {
					continue
				}
				mqlKey, err := newKmsKey(r.MqlRuntime, region, meta)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlKey)
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if len(items) < int(pageSize) || (int(total) > 0 && int(pageNumber)*int(pageSize) >= int(total)) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// describeKmsKey fetches the full metadata for a single key within a region.
func describeKmsKey(conn *connection.AlicloudConnection, region, keyID string) (*kmsclient.DescribeKeyResponseBodyKeyMetadata, error) {
	client, err := conn.KmsClient(region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeKey(&kmsclient.DescribeKeyRequest{KeyId: tea.String(keyID)})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return resp.Body.KeyMetadata, nil
}

// newKmsKey builds a fully populated alicloud.kms.key from key metadata. It is
// shared by the keys list accessor and the by-id init so both produce identical
// resources.
func newKmsKey(runtime *plugin.Runtime, region string, meta *kmsclient.DescribeKeyResponseBodyKeyMetadata) (*mqlAlicloudKmsKey, error) {
	keyID := tea.StringValue(meta.KeyId)
	resource, err := CreateResource(runtime, "alicloud.kms.key", map[string]*llx.RawData{
		"__id":               llx.StringData(region + "/" + keyID),
		"regionId":           llx.StringData(region),
		"keyId":              llx.StringData(keyID),
		"arn":                llx.StringDataPtr(meta.Arn),
		"keyState":           llx.StringDataPtr(meta.KeyState),
		"keyUsage":           llx.StringDataPtr(meta.KeyUsage),
		"keySpec":            llx.StringDataPtr(meta.KeySpec),
		"origin":             llx.StringDataPtr(meta.Origin),
		"protectionLevel":    llx.StringDataPtr(meta.ProtectionLevel),
		"automaticRotation":  llx.StringDataPtr(meta.AutomaticRotation),
		"rotationInterval":   llx.IntDataPtr(kmsRotationIntervalSeconds(tea.StringValue(meta.RotationInterval))),
		"creationDate":       llx.TimeDataPtr(alicloudParseTime(meta.CreationDate)),
		"deleteDate":         llx.TimeDataPtr(alicloudParseTime(meta.DeleteDate)),
		"lastRotationDate":   llx.TimeDataPtr(alicloudParseTime(meta.LastRotationDate)),
		"nextRotationDate":   llx.TimeDataPtr(alicloudParseTime(meta.NextRotationDate)),
		"materialExpireTime": llx.TimeDataPtr(alicloudParseTime(meta.MaterialExpireTime)),
		"primaryKeyVersion":  llx.StringDataPtr(meta.PrimaryKeyVersion),
		"deletionProtection": llx.StringDataPtr(meta.DeletionProtection),
		"creator":            llx.StringDataPtr(meta.Creator),
		"description":        llx.StringDataPtr(meta.Description),
		"dkmsInstanceId":     llx.StringDataPtr(meta.DKMSInstanceId),
	})
	if err != nil {
		return nil, err
	}
	mqlKey := resource.(*mqlAlicloudKmsKey)
	mqlKey.region = region
	mqlKey.keyId = keyID
	return mqlKey, nil
}

// resolveKmsKey returns the typed KMS key for a native key id within a region,
// or (nil, nil) when keyID is empty (the caller sets StateIsNull). It backs the
// typed kmsKey()/encryptionKey() cross-references from disks, buckets, secrets,
// logstores, and database instances.
func resolveKmsKey(runtime *plugin.Runtime, region, keyID string) (*mqlAlicloudKmsKey, error) {
	if keyID == "" || region == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.kms.key", map[string]*llx.RawData{
		"keyId":    llx.StringData(keyID),
		"regionId": llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudKmsKey), nil
}

// initAlicloudKmsKey resolves a KMS key by its native key id within a region,
// reusing an already-listed key from the resource cache and otherwise fetching
// it via DescribeKey.
func initAlicloudKmsKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	keyID, err := requiredStringArg(args, "keyId", "alicloud.kms.key")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.kms.key")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.kms.key\x00" + region + "/" + keyID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	meta, err := describeKmsKey(conn, region, keyID)
	if err != nil {
		return nil, nil, err
	}
	if meta == nil || meta.KeyId == nil {
		return nil, nil, fmt.Errorf("alicloud.kms.key %q not found in region %q", keyID, region)
	}
	res, err := newKmsKey(runtime, region, meta)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudKmsKey) id() (string, error) {
	return r.region + "/" + r.keyId, nil
}

// aliases lazily lists the alias names that point at the key.
func (r *mqlAlicloudKmsKey) aliases() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.KmsClient(r.region)
	if err != nil {
		return []any{}, nil
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.ListAliasesByKeyId(&kmsclient.ListAliasesByKeyIdRequest{
			KeyId:      tea.String(r.keyId),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(pageSize),
		})
		if err != nil || resp == nil || resp.Body == nil || resp.Body.Aliases == nil {
			break
		}
		items := resp.Body.Aliases.Alias
		for _, a := range items {
			if a == nil || a.AliasName == nil {
				continue
			}
			res = append(res, tea.StringValue(a.AliasName))
		}
		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) < int(pageSize) || (int(total) > 0 && int(pageNumber)*int(pageSize) >= int(total)) {
			break
		}
		pageNumber++
	}
	return res, nil
}

func (r *mqlAlicloudKms) secrets() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.KmsClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		pageSize := int32(100)
		firstPage := true
		for {
			resp, err := client.ListSecrets(&kmsclient.ListSecretsRequest{
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(pageSize),
			})
			if err != nil {
				// First-page error = region has no KMS / no access (skip);
				// later-page error is real — surface rather than truncate.
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.SecretList == nil {
				break
			}

			items := resp.Body.SecretList.Secret
			for _, s := range items {
				if s == nil || s.SecretName == nil {
					continue
				}
				mqlSecret, err := newKmsSecret(r.MqlRuntime, conn, region, s)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlSecret)
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if len(items) < int(pageSize) || (int(total) > 0 && int(pageNumber)*int(pageSize) >= int(total)) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// newKmsSecret builds a fully populated alicloud.kms.secret. The list item
// carries the summary; DescribeSecret supplies the arn, rotation configuration,
// encryption key, and extended config.
func newKmsSecret(runtime *plugin.Runtime, conn *connection.AlicloudConnection, region string, s *kmsclient.ListSecretsResponseBodySecretListSecret) (*mqlAlicloudKmsSecret, error) {
	secretName := tea.StringValue(s.SecretName)

	var detail *kmsclient.DescribeSecretResponseBody
	if client, err := conn.KmsClient(region); err == nil {
		if resp, err := client.DescribeSecret(&kmsclient.DescribeSecretRequest{
			SecretName: tea.String(secretName),
			FetchTags:  tea.String("true"),
		}); err == nil && resp != nil {
			detail = resp.Body
		}
	}

	extended := parseExtendedConfig(detail)
	resource, err := CreateResource(runtime, "alicloud.kms.secret", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + secretName),
		"regionId":          llx.StringData(region),
		"secretName":        llx.StringData(secretName),
		"secretType":        llx.StringDataPtr(s.SecretType),
		"owingService":      llx.StringDataPtr(s.OwingService),
		"plannedDeleteTime": llx.TimeDataPtr(alicloudParseTime(s.PlannedDeleteTime)),
		"createTime":        llx.TimeDataPtr(alicloudParseTime(s.CreateTime)),
		"updateTime":        llx.TimeDataPtr(alicloudParseTime(s.UpdateTime)),
		"arn":               llx.StringData(secretDetailString(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.Arn })),
		"automaticRotation": llx.StringData(secretDetailString(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.AutomaticRotation })),
		"rotationInterval":  llx.IntDataPtr(kmsRotationIntervalSeconds(secretDetailString(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.RotationInterval }))),
		"description":       llx.StringData(secretDetailString(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.Description })),
		"dkmsInstanceId":    llx.StringData(secretDetailString(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.DKMSInstanceId })),
		"lastRotationDate":  llx.TimeDataPtr(secretDetailTime(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.LastRotationDate })),
		"nextRotationDate":  llx.TimeDataPtr(secretDetailTime(detail, func(d *kmsclient.DescribeSecretResponseBody) *string { return d.NextRotationDate })),
		"extendedConfig":    llx.DictData(extended),
		"tags":              llx.MapData(kmsSecretTags(detail), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlSecret := resource.(*mqlAlicloudKmsSecret)
	mqlSecret.region = region
	if detail != nil {
		mqlSecret.cacheEncryptionKeyId = tea.StringValue(detail.EncryptionKeyId)
	}
	return mqlSecret, nil
}

// secretDetailString safely reads a *string field from the DescribeSecret detail,
// returning "" when the detail is missing.
func secretDetailString(d *kmsclient.DescribeSecretResponseBody, get func(*kmsclient.DescribeSecretResponseBody) *string) string {
	if d == nil {
		return ""
	}
	return tea.StringValue(get(d))
}

func secretDetailTime(d *kmsclient.DescribeSecretResponseBody, get func(*kmsclient.DescribeSecretResponseBody) *string) *time.Time {
	if d == nil {
		return nil
	}
	return alicloudParseTime(get(d))
}

// parseExtendedConfig parses the secret's extended-config JSON into a dict,
// returning nil for Generic secrets or when parsing fails.
func parseExtendedConfig(d *kmsclient.DescribeSecretResponseBody) any {
	if d == nil || d.ExtendedConfig == nil || *d.ExtendedConfig == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(*d.ExtendedConfig), &out); err != nil {
		return nil
	}
	return out
}

func kmsSecretTags(d *kmsclient.DescribeSecretResponseBody) map[string]any {
	res := map[string]any{}
	if d == nil || d.Tags == nil {
		return res
	}
	for _, t := range d.Tags.Tag {
		if t == nil || t.TagKey == nil {
			continue
		}
		res[*t.TagKey] = tea.StringValue(t.TagValue)
	}
	return res
}

func (r *mqlAlicloudKmsSecret) id() (string, error) {
	return r.region + "/" + r.SecretName.Data, nil
}

func (r *mqlAlicloudKmsSecret) encryptionKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheEncryptionKeyId == "" {
		r.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, r.region, r.cacheEncryptionKeyId)
	if err != nil || key == nil {
		r.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}
