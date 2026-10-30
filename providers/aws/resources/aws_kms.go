// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	mqlTypes "go.mondoo.com/mql/types"
)

const (
	kmsKeyArnPattern       = "arn:aws:kms:%s:%s:key/%s"
	kmsAliasResourcePrefix = "alias/"
	kmsKeyResourcePrefix   = "key/"
	kmsMrkPrefix           = "mrk-"
)

// NormalizeKmsKeyRef normalizes KMS key identifiers that can be converted to a
// key or alias ARN without making an AWS API call.
func NormalizeKmsKeyRef(s, region, accountId string) (arn.ARN, error) {
	if strings.HasPrefix(s, "arn:") {
		parsed, err := arn.Parse(s)
		if err != nil {
			return arn.ARN{}, fmt.Errorf("invalid ARN %q: %w", s, err)
		}
		if parsed.Service != "kms" {
			return arn.ARN{}, fmt.Errorf("expected a KMS key or alias ARN but got %q (service=%q)", s, parsed.Service)
		}
		if !strings.HasPrefix(parsed.Resource, kmsKeyResourcePrefix) && !strings.HasPrefix(parsed.Resource, kmsAliasResourcePrefix) {
			return arn.ARN{}, fmt.Errorf("expected a KMS key or alias ARN but got %q (resource=%q)", s, parsed.Resource)
		}
		return parsed, nil
	}

	if !isKmsKeyID(s) {
		return arn.ARN{}, fmt.Errorf("invalid KMS key reference %q", s)
	}
	if region == "" {
		return arn.ARN{}, fmt.Errorf("cannot normalize KMS key ID %q without a region", s)
	}
	if accountId == "" {
		return arn.ARN{}, fmt.Errorf("cannot normalize KMS key ID %q without an account ID", s)
	}

	return arn.ARN{
		Partition: kmsPartitionForRegion(region),
		Service:   "kms",
		Region:    region,
		AccountID: accountId,
		Resource:  kmsKeyResourcePrefix + s,
	}, nil
}

// kmsKeyRefArgs builds the NewResource arguments for a reference to a KMS key.
//
// Services report their key in several shapes: a full key ARN, a full alias ARN,
// a bare key id, or a bare alias such as "alias/aws/sqs" - which is what SQS and
// SSM Parameter Store return for a resource encrypted with the service's default
// key. initAwsKmsKey normalizes all of them, so a reference already in one of
// those forms is passed through untouched.
//
// Only a bare key id is wrapped in kmsKeyArnPattern, because neither the region
// nor the account is recoverable from the id alone. Wrapping unconditionally
// produced "arn:aws:kms:<region>:<account>:key/alias/aws/sqs", which is not a KMS
// ARN, and DescribeKey rejected it with "Invalid keyId alias/aws/sqs" - so the
// key reference errored for every default-encrypted queue and parameter.
func kmsKeyRefArgs(region, accountID, keyRef string) map[string]*llx.RawData {
	ref := keyRef
	if !strings.HasPrefix(ref, "arn:") && !strings.HasPrefix(ref, kmsAliasResourcePrefix) {
		ref = fmt.Sprintf(kmsKeyArnPattern, region, accountID, ref)
	}
	return map[string]*llx.RawData{
		"arn":    llx.StringData(ref),
		"region": llx.StringData(region),
	}
}

func isKmsKeyID(s string) bool {
	return isUUIDKeyID(s) || isMultiRegionKeyID(s)
}

func isUUIDKeyID(s string) bool {
	if len(s) != 36 {
		return false
	}

	for i := range s {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}

	return true
}

func isMultiRegionKeyID(s string) bool {
	if !strings.HasPrefix(s, kmsMrkPrefix) || len(s) != len(kmsMrkPrefix)+32 {
		return false
	}

	for i := len(kmsMrkPrefix); i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}

	return true
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func kmsPartitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func (a *mqlAwsKms) id() (string, error) {
	return "aws.kms", nil
}

func (a *mqlAwsKms) keys() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "kms", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Msgf("kms>getKeys>calling aws with region %s", region)

		svc := conn.Kms(region)
		res := []any{}

		keys := make([]types.KeyListEntry, 0)
		params := &kms.ListKeysInput{}
		paginator := kms.NewListKeysPaginator(svc, params, func(o *kms.ListKeysPaginatorOptions) {
			o.Limit = 100
		})
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			keys = append(keys, output.Keys...)
		}

		// Pre-fetch tags in parallel when tag-based filters are configured. KMS
		// has no batch tags endpoint, so this turns a sequential per-key call
		// into bounded concurrent ones, and it stays entirely unpaid when no tag
		// filter is set.
		var tagsByArn map[string]map[string]string
		if conn.Filters.General.HasTags() {
			arns := make([]string, 0, len(keys))
			for i := range keys {
				arns = append(arns, convert.ToValue(keys[i].KeyArn))
			}
			tagsByArn = fetchTagsConcurrently(ctx, arns, func(ctx context.Context, keyArn string) (map[string]string, error) {
				return kmsKeyTags(ctx, svc, keyArn)
			})
		}

		for _, key := range keys {
			keyArn := convert.ToValue(key.KeyArn)
			tags, fetched := tagsByArn[keyArn]
			if conn.Filters.General.HasTags() &&
				conn.Filters.General.IsFilteredOutByTags(tags) {
				log.Debug().Str("key", keyArn).Msg("excluding kms key due to filters")
				continue
			}

			args := map[string]*llx.RawData{
				"id":     llx.StringDataPtr(key.KeyId),
				"arn":    llx.StringDataPtr(key.KeyArn),
				"region": llx.StringData(region),
			}
			// Seed the tags we already paid for, but only a set we actually read:
			// publishing an empty map for a key whose ListResourceTags call failed
			// would report "no tags" as fact. Leaving it unset keeps the field lazy.
			if fetched {
				args["tags"] = llx.MapData(stringMapToAny(tags), mqlTypes.String)
			}

			mqlKey, err := CreateResource(a.MqlRuntime, "aws.kms.key", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlKey)
		}

		return res, nil
	})
}

// kmsKeyTags reads one key's tags for filter evaluation.
//
// Every error is returned, including AccessDenied. Some AWS-managed keys grant
// kms:ListResourceTags and answer with an empty tag set, others refuse it, and
// only the first is "this key has no tags". fetchTagsConcurrently leaves a key
// whose read failed out of its result, so nothing is seeded onto the resource
// and the lazy tags accessor still reports the refusal as null via
// markTagsUnreadable. Returning an empty set here would publish "no tags" as fact
// for a key whose tags could not be read, and would make the same key report {}
// under a tag filter and null without one.
//
// Filtering is unaffected: an absent entry yields a nil map, and both
// MatchesIncludeTags and MatchesExcludeTags read a nil map exactly as they read
// an empty one.
func kmsKeyTags(ctx context.Context, svc *kms.Client, keyArn string) (map[string]string, error) {
	tags := map[string]string{}
	paginator := kms.NewListResourceTagsPaginator(svc, &kms.ListResourceTagsInput{KeyId: &keyArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for i := range page.Tags {
			tags[convert.ToValue(page.Tags[i].TagKey)] = convert.ToValue(page.Tags[i].TagValue)
		}
	}
	return tags, nil
}

func (a *mqlAwsKms) grants() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	rawKeys := a.GetKeys()
	if rawKeys.Error != nil {
		return nil, rawKeys.Error
	}

	log.Info().Int("keys", len(rawKeys.Data)).Msg("aws.kms.grants: listing grants for every key in every region (use aws.kms.key.grants for targeted queries)")
	res := []any{}
	tasks := make([]*jobpool.Job, 0, len(rawKeys.Data))
	for _, raw := range rawKeys.Data {
		key, ok := raw.(*mqlAwsKmsKey)
		if !ok || key == nil {
			continue
		}
		keyArn := key.Arn.Data
		keyRegion := key.Region.Data
		f := func() (jobpool.JobResult, error) {
			grants, err := listKmsGrantsForKey(a.MqlRuntime, conn, keyArn, keyRegion)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(grants), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}

	poolOfJobs := jobpool.CreatePool(tasks, 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		// A key whose grants we may not list leaves the account-wide list
		// incomplete, and this list has no way to say which part is missing.
		// Reporting the rest as the whole is the truncation
		// aws.kms.key.grants refuses one key at a time.
		return kmsGrantsOrUnreadable(&a.Grants, nil, poolOfJobs.GetErrors())
	}
	for i := range poolOfJobs.Jobs {
		result, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, result...)
	}
	return res, nil
}

func (a *mqlAwsKms) customKeyStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "kms", func(ctx context.Context, region string) ([]any, error) {
		log.Debug().Str("region", region).Msg("kms>getCustomKeyStores>describe")

		svc := conn.Kms(region)
		res := []any{}
		paginator := kms.NewDescribeCustomKeyStoresPaginator(svc, &kms.DescribeCustomKeyStoresInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, entry := range page.CustomKeyStores {
				mqlStore, err := newMqlAwsKmsCustomKeyStore(a.MqlRuntime, region, entry)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlStore)
			}
		}
		return res, nil
	})
}

// kmsCustomKeyStoreID returns the `__id` shape used by every aws.kms.customKeyStore
// instance. All callers that construct or look up a custom key store resource must
// route through this helper so cache lookups in initAwsKmsCustomKeyStore stay in
// sync with the IDs produced by newMqlAwsKmsCustomKeyStore and aws.kms.key.customKeyStore().
func kmsCustomKeyStoreID(region, storeID string) string {
	return region + "/" + storeID
}

func newMqlAwsKmsCustomKeyStore(runtime *plugin.Runtime, region string, entry types.CustomKeyStoresListEntry) (plugin.Resource, error) {
	id := kmsCustomKeyStoreID(region, convert.ToValue(entry.CustomKeyStoreId))
	xksProxy, err := kmsXksProxyConfigToDict(entry.XksProxyConfiguration)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "aws.kms.customKeyStore",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(id),
			"customKeyStoreId":       llx.StringDataPtr(entry.CustomKeyStoreId),
			"customKeyStoreName":     llx.StringDataPtr(entry.CustomKeyStoreName),
			"customKeyStoreType":     llx.StringData(string(entry.CustomKeyStoreType)),
			"region":                 llx.StringData(region),
			"connectionState":        llx.StringData(string(entry.ConnectionState)),
			"connectionErrorCode":    llx.StringData(string(entry.ConnectionErrorCode)),
			"creationDate":           llx.TimeDataPtr(entry.CreationDate),
			"cloudHsmClusterId":      llx.StringDataPtr(entry.CloudHsmClusterId),
			"trustAnchorCertificate": llx.StringDataPtr(entry.TrustAnchorCertificate),
			"xksProxyConfiguration":  llx.DictData(xksProxy),
		})
}

func kmsXksProxyConfigToDict(c *types.XksProxyConfigurationType) (any, error) {
	if c == nil {
		return nil, nil
	}
	// Surface only whether an access key id is configured, never the value
	// itself — the access key id is a long-lived credential identifier and
	// should not flow through audit output.
	out := map[string]any{
		"connectivity":            string(c.Connectivity),
		"accessKeyIdPresent":      c.AccessKeyId != nil && *c.AccessKeyId != "",
		"uriEndpoint":             convert.ToValue(c.UriEndpoint),
		"uriPath":                 convert.ToValue(c.UriPath),
		"vpcEndpointServiceName":  convert.ToValue(c.VpcEndpointServiceName),
		"vpcEndpointServiceOwner": convert.ToValue(c.VpcEndpointServiceOwner),
	}
	return out, nil
}

func (a *mqlAwsKmsKey) metadata() (any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(md)
}

// errKmsGrantsUnreadable marks a ListGrants call AWS refused. The grants a key
// carries are then unknown, which is not the same as a key with no grants.
var errKmsGrantsUnreadable = errors.New("kms: grants could not be listed")

// markKmsUnreadable publishes a field whose backing read AWS refused as null,
// the same way markTagsUnreadable does for tags.
//
// The zero value of a bool, an int or a string cannot say "we were not allowed
// to look": keyRotationEnabled:false is a claim that rotation is off, and
// policy:"" a claim a key has no key policy, neither of which a denial
// establishes. Setting the state before returning is what makes GetOrCompute
// keep the null instead of caching the zero value it is handed.
func markKmsUnreadable[T any](field *plugin.TValue[T]) (T, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	var zero T
	return zero, nil
}

// kmsRotationReading is what the four rotation fields publish for one key.
type kmsRotationReading struct {
	// known is false when AWS refused GetKeyRotationStatus. Every rotation
	// field then publishes null.
	known bool
	// enabled is meaningful only when known.
	enabled bool
	// periodDays is nil when AWS omitted RotationPeriodInDays, which it does on
	// every key with rotation off. Zero is not a rotation period.
	periodDays                *int64
	nextRotationAt            *time.Time
	onDemandRotationStartedAt *time.Time
}

// kmsRotationReadingFrom turns a GetKeyRotationStatus answer into the reading
// the rotation fields publish, and is where the refusal is classified.
//
// A key policy can withhold kms:GetKeyRotationStatus from a caller that holds
// it in IAM, and AWS-managed keys do exactly that: alias/aws/acm refuses the
// call even to an account administrator, and it rotates. Folding that refusal
// into keyRotationEnabled:false states the opposite of the truth about such a
// key, so it is reported as unknown instead.
func kmsRotationReadingFrom(resp *kms.GetKeyRotationStatusOutput, err error) (kmsRotationReading, error) {
	if err != nil {
		if Is400AccessDeniedError(err) {
			return kmsRotationReading{}, nil
		}
		return kmsRotationReading{}, err
	}
	if resp == nil {
		return kmsRotationReading{}, nil
	}

	reading := kmsRotationReading{
		known:                     true,
		enabled:                   resp.KeyRotationEnabled,
		nextRotationAt:            resp.NextRotationDate,
		onDemandRotationStartedAt: resp.OnDemandRotationStartDate,
	}
	if resp.RotationPeriodInDays != nil {
		days := int64(*resp.RotationPeriodInDays)
		reading.periodDays = &days
	}
	return reading, nil
}

func (a *mqlAwsKmsKey) getRotationStatus() (kmsRotationReading, error) {
	if a.rotationStatusFetched {
		return a.cachedRotationStatus, nil
	}
	a.rotationStatusLock.Lock()
	defer a.rotationStatusLock.Unlock()
	if a.rotationStatusFetched {
		return a.cachedRotationStatus, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &keyArn})
	reading, err := kmsRotationReadingFrom(resp, err)
	if err != nil {
		return kmsRotationReading{}, err
	}
	if !reading.known {
		log.Debug().Str("key", keyArn).Msg("access denied reading KMS key rotation status")
	}
	a.cachedRotationStatus = reading
	a.rotationStatusFetched = true
	return reading, nil
}

func (a *mqlAwsKmsKey) keyRotationEnabled() (bool, error) {
	reading, err := a.getRotationStatus()
	if err != nil {
		return false, err
	}
	if !reading.known {
		return markKmsUnreadable(&a.KeyRotationEnabled)
	}
	return reading.enabled, nil
}

func (a *mqlAwsKmsKey) rotationPeriodInDays() (int64, error) {
	reading, err := a.getRotationStatus()
	if err != nil {
		return 0, err
	}
	if !reading.known || reading.periodDays == nil {
		return markKmsUnreadable(&a.RotationPeriodInDays)
	}
	return *reading.periodDays, nil
}

func (a *mqlAwsKmsKey) nextRotationAt() (*time.Time, error) {
	reading, err := a.getRotationStatus()
	if err != nil {
		return nil, err
	}
	if !reading.known {
		return markKmsUnreadable(&a.NextRotationAt)
	}
	return reading.nextRotationAt, nil
}

func (a *mqlAwsKmsKey) onDemandRotationStartedAt() (*time.Time, error) {
	reading, err := a.getRotationStatus()
	if err != nil {
		return nil, err
	}
	if !reading.known {
		return markKmsUnreadable(&a.OnDemandRotationStartedAt)
	}
	return reading.onDemandRotationStartedAt, nil
}

// kmsLastUsageReading is what lastUsageOperation and lastUsedAt publish.
//
// Both fields are null when the key has never been used and when the read was
// refused. The two reasons stay separate here so callers, and a future field
// that wants to report them apart, can still tell them apart.
type kmsLastUsageReading struct {
	// known is false when AWS refused GetKeyLastUsage.
	known bool
	// operation is nil when the key has not been used since KMS began tracking.
	operation  *string
	lastUsedAt *time.Time
}

// kmsLastUsageReadingFrom turns a GetKeyLastUsage answer into the reading the
// last-usage fields publish.
func kmsLastUsageReadingFrom(resp *kms.GetKeyLastUsageOutput, err error) (kmsLastUsageReading, error) {
	if err != nil {
		if Is400AccessDeniedError(err) {
			return kmsLastUsageReading{}, nil
		}
		return kmsLastUsageReading{}, err
	}
	if resp == nil {
		return kmsLastUsageReading{}, nil
	}

	reading := kmsLastUsageReading{known: true}
	if resp.KeyLastUsage == nil {
		return reading, nil
	}
	reading.lastUsedAt = resp.KeyLastUsage.Timestamp
	if op := string(resp.KeyLastUsage.Operation); op != "" {
		reading.operation = &op
	}
	return reading, nil
}

func (a *mqlAwsKmsKey) getLastUsage() (kmsLastUsageReading, error) {
	if a.lastUsageFetched {
		return a.cachedLastUsage, nil
	}
	a.lastUsageLock.Lock()
	defer a.lastUsageLock.Unlock()
	if a.lastUsageFetched {
		return a.cachedLastUsage, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.GetKeyLastUsage(ctx, &kms.GetKeyLastUsageInput{KeyId: &keyArn})
	reading, err := kmsLastUsageReadingFrom(resp, err)
	if err != nil {
		return kmsLastUsageReading{}, err
	}
	if !reading.known {
		log.Debug().Str("key", keyArn).Msg("access denied reading KMS key last usage")
	}
	a.cachedLastUsage = reading
	a.lastUsageFetched = true
	return reading, nil
}

func (a *mqlAwsKmsKey) lastUsageOperation() (string, error) {
	reading, err := a.getLastUsage()
	if err != nil {
		return "", err
	}
	if !reading.known {
		// GetKeyLastUsage was refused, so the last operation is unknown.
		return markKmsUnreadable(&a.LastUsageOperation)
	}
	if reading.operation == nil {
		// The key has not been used since KMS began tracking. There is no
		// operation to name, and "" is outside the documented value set, so
		// this reads null the way lastUsedAt already does.
		return markKmsUnreadable(&a.LastUsageOperation)
	}
	return *reading.operation, nil
}

func (a *mqlAwsKmsKey) lastUsedAt() (*time.Time, error) {
	reading, err := a.getLastUsage()
	if err != nil {
		return nil, err
	}
	if !reading.known {
		return markKmsUnreadable(&a.LastUsedAt)
	}
	return reading.lastUsedAt, nil
}

func (a *mqlAwsKmsKey) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	res := map[string]any{}
	paginator := kms.NewListResourceTagsPaginator(svc, &kms.ListResourceTagsInput{KeyId: &keyArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// AWS-managed keys reject ListResourceTags with AccessDenied;
			// treat that as no tags rather than failing managedBy/tags.
			if Is400AccessDeniedError(err) {
				return markTagsUnreadable(&a.Tags)
			}
			return nil, err
		}
		for i := range page.Tags {
			tag := page.Tags[i]
			res[convert.ToValue(tag.TagKey)] = convert.ToValue(tag.TagValue)
		}
	}

	return res, nil
}

func (a *mqlAwsKmsKey) aliases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	aliases := []any{}
	paginator := kms.NewListAliasesPaginator(svc, &kms.ListAliasesInput{KeyId: &keyArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, alias := range page.Aliases {
			aliases = append(aliases, convert.ToValue(alias.AliasName))
		}
	}

	return aliases, nil
}

func (a *mqlAwsKmsKey) keyState() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.KeyState), nil
}

type mqlAwsKmsKeyInternal struct {
	cachedKeyMetadata     *types.KeyMetadata
	metadataLock          sync.Mutex
	cachedRotationStatus  kmsRotationReading
	rotationStatusFetched bool
	rotationStatusLock    sync.Mutex
	cachedLastUsage       kmsLastUsageReading
	lastUsageFetched      bool
	lastUsageLock         sync.Mutex
}

func (a *mqlAwsKmsKey) getKeyMetadata() (*types.KeyMetadata, error) {
	if a.cachedKeyMetadata != nil {
		return a.cachedKeyMetadata, nil
	}
	a.metadataLock.Lock()
	defer a.metadataLock.Unlock()
	if a.cachedKeyMetadata != nil {
		return a.cachedKeyMetadata, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &keyArn})
	if err != nil {
		return nil, err
	}
	a.cachedKeyMetadata = resp.KeyMetadata
	return a.cachedKeyMetadata, nil
}

func (a *mqlAwsKmsKey) createdAt() (*time.Time, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	return md.CreationDate, nil
}

func (a *mqlAwsKmsKey) deletedAt() (*time.Time, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	return md.DeletionDate, nil
}

func (a *mqlAwsKmsKey) enabled() (bool, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return false, err
	}
	return md.Enabled, nil
}

func (a *mqlAwsKmsKey) description() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return convert.ToValue(md.Description), nil
}

func (a *mqlAwsKmsKey) keyManager() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.KeyManager), nil
}

func (a *mqlAwsKmsKey) keySpec() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.KeySpec), nil
}

func (a *mqlAwsKmsKey) keyUsage() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.KeyUsage), nil
}

func (a *mqlAwsKmsKey) multiRegion() (bool, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return false, err
	}
	return convert.ToValue(md.MultiRegion), nil
}

func (a *mqlAwsKmsKey) multiRegionConfiguration() (*mqlAwsKmsKeyMultiRegionConfiguration, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	if md.MultiRegionConfiguration == nil {
		a.MultiRegionConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cfg := md.MultiRegionConfiguration
	primaryArn := ""
	primaryRegion := ""
	if cfg.PrimaryKey != nil {
		primaryArn = convert.ToValue(cfg.PrimaryKey.Arn)
		primaryRegion = convert.ToValue(cfg.PrimaryKey.Region)
	}
	replicaArns := make([]any, 0, len(cfg.ReplicaKeys))
	cachedReplicas := make([]types.MultiRegionKey, 0, len(cfg.ReplicaKeys))
	for _, replica := range cfg.ReplicaKeys {
		replicaArns = append(replicaArns, convert.ToValue(replica.Arn))
		cachedReplicas = append(cachedReplicas, replica)
	}

	id := a.Arn.Data + "/multiRegionConfiguration"
	res, err := CreateResource(a.MqlRuntime, "aws.kms.key.multiRegionConfiguration",
		map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"multiRegionKeyType": llx.StringData(string(cfg.MultiRegionKeyType)),
			"primaryKeyArn":      llx.StringData(primaryArn),
			"primaryKeyRegion":   llx.StringData(primaryRegion),
			"replicaKeyArns":     llx.ArrayData(replicaArns, mqlTypes.String),
		})
	if err != nil {
		return nil, err
	}
	mqlCfg := res.(*mqlAwsKmsKeyMultiRegionConfiguration)
	mqlCfg.cachePrimary = cfg.PrimaryKey
	mqlCfg.cacheReplicas = cachedReplicas
	return mqlCfg, nil
}

func (a *mqlAwsKmsKey) origin() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.Origin), nil
}

func (a *mqlAwsKmsKey) currentKeyMaterialId() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return convert.ToValue(md.CurrentKeyMaterialId), nil
}

func (a *mqlAwsKmsKey) cloudHsmCluster() (*mqlAwsCloudhsmCluster, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	if md.CloudHsmClusterId == nil || *md.CloudHsmClusterId == "" {
		a.CloudHsmCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cluster, err := NewResource(a.MqlRuntime, "aws.cloudhsm.cluster",
		map[string]*llx.RawData{
			"clusterId": llx.StringDataPtr(md.CloudHsmClusterId),
		})
	if err != nil {
		return nil, err
	}
	return cluster.(*mqlAwsCloudhsmCluster), nil
}

func (a *mqlAwsKmsKey) customKeyStore() (*mqlAwsKmsCustomKeyStore, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	if md.CustomKeyStoreId == nil || *md.CustomKeyStoreId == "" {
		a.CustomKeyStore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	store, err := NewResource(a.MqlRuntime, "aws.kms.customKeyStore",
		map[string]*llx.RawData{
			"__id":             llx.StringData(kmsCustomKeyStoreID(a.Region.Data, *md.CustomKeyStoreId)),
			"customKeyStoreId": llx.StringDataPtr(md.CustomKeyStoreId),
			"region":           llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return store.(*mqlAwsKmsCustomKeyStore), nil
}

func (a *mqlAwsKmsKey) xksKeyConfiguration() (any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	if md.XksKeyConfiguration == nil {
		return nil, nil
	}
	return map[string]any{
		"id": convert.ToValue(md.XksKeyConfiguration.Id),
	}, nil
}

func (a *mqlAwsKmsKey) encryptionAlgorithms() ([]any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	res := make([]any, len(md.EncryptionAlgorithms))
	for i, alg := range md.EncryptionAlgorithms {
		res[i] = string(alg)
	}
	return res, nil
}

func (a *mqlAwsKmsKey) signingAlgorithms() ([]any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	res := make([]any, len(md.SigningAlgorithms))
	for i, alg := range md.SigningAlgorithms {
		res[i] = string(alg)
	}
	return res, nil
}

func (a *mqlAwsKmsKey) macAlgorithms() ([]any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	res := make([]any, len(md.MacAlgorithms))
	for i, alg := range md.MacAlgorithms {
		res[i] = string(alg)
	}
	return res, nil
}

func (a *mqlAwsKmsKey) keyAgreementAlgorithms() ([]any, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	res := make([]any, len(md.KeyAgreementAlgorithms))
	for i, alg := range md.KeyAgreementAlgorithms {
		res[i] = string(alg)
	}
	return res, nil
}

func (a *mqlAwsKmsKey) expirationModel() (string, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return "", err
	}
	return string(md.ExpirationModel), nil
}

func (a *mqlAwsKmsKey) validTo() (*time.Time, error) {
	md, err := a.getKeyMetadata()
	if err != nil {
		return nil, err
	}
	return md.ValidTo, nil
}

func (a *mqlAwsKmsKey) policy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	keyArn := a.Arn.Data

	svc := conn.Kms(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: &keyArn})
	return kmsPolicyOrUnreadable(&a.Policy, keyArn, resp, err)
}

// kmsPolicyOrUnreadable publishes a key policy document, or null when AWS
// refused to disclose it.
//
// Every KMS key has a key policy, so "" can never be a truthful reading of one:
// it is indistinguishable from a key whose policy grants a wildcard principal,
// and it collapses through an empty statement list into isPublic:false. Any
// other failure is a failure, not an answer.
func kmsPolicyOrUnreadable(field *plugin.TValue[string], keyArn string, resp *kms.GetKeyPolicyOutput, err error) (string, error) {
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Debug().Str("key", keyArn).Msg("access denied when retrieving KMS key policy")
			return markKmsUnreadable(field)
		}
		return "", err
	}
	if resp == nil {
		return markKmsUnreadable(field)
	}
	return convert.ToValue(resp.Policy), nil
}

func (a *mqlAwsKmsKey) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsKmsKey) grants() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	grants, err := listKmsGrantsForKey(a.MqlRuntime, conn, a.Arn.Data, a.Region.Data)
	return kmsGrantsOrUnreadable(&a.Grants, grants, err)
}

// kmsGrantsOrUnreadable publishes a grant list, or null when ListGrants was
// refused for any key it covers.
//
// The grants such a key carries are unknown, and publishing the partial list
// presents it as the complete one: a check reading "no grant allows X" would
// pass on a key nobody was allowed to enumerate. Any other failure is returned
// as the failure it is.
func kmsGrantsOrUnreadable(field *plugin.TValue[[]any], grants []any, err error) ([]any, error) {
	if errors.Is(err, errKmsGrantsUnreadable) {
		return markKmsUnreadable(field)
	}
	return grants, err
}

// kmsListGrantsError classifies a ListGrants failure. A refusal becomes
// errKmsGrantsUnreadable, which the grant accessors publish as null; anything
// else stays the error it is, so a throttle or a network blip cannot be read as
// a statement about the key.
func kmsListGrantsError(keyArn string, err error) error {
	if Is400AccessDeniedError(err) {
		log.Debug().Str("keyArn", keyArn).Msg("access denied listing KMS grants")
		return fmt.Errorf("%w for key %s: %w", errKmsGrantsUnreadable, keyArn, err)
	}
	return err
}

func listKmsGrantsForKey(runtime *plugin.Runtime, conn *connection.AwsConnection, keyArn, region string) ([]any, error) {
	if keyArn == "" || region == "" {
		return nil, nil
	}

	svc := conn.Kms(region)
	ctx := context.Background()

	res := []any{}
	params := &kms.ListGrantsInput{KeyId: &keyArn}
	paginator := kms.NewListGrantsPaginator(svc, params)
	for paginator.HasMorePages() {
		grantsResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, kmsListGrantsError(keyArn, err)
		}
		for _, grant := range grantsResp.Grants {
			operations := make([]any, len(grant.Operations))
			for i, op := range grant.Operations {
				operations[i] = string(op)
			}
			constraints, err := kmsGrantConstraintsToDict(grant.Constraints)
			if err != nil {
				return nil, err
			}
			mqlGrant, err := CreateResource(runtime, "aws.kms.grant",
				map[string]*llx.RawData{
					"__id":              llx.StringData(keyArn + "/grant/" + convert.ToValue(grant.GrantId)),
					"grantId":           llx.StringDataPtr(grant.GrantId),
					"name":              llx.StringDataPtr(grant.Name),
					"granteePrincipal":  llx.StringDataPtr(grant.GranteePrincipal),
					"retiringPrincipal": llx.StringDataPtr(grant.RetiringPrincipal),
					"issuingAccount":    llx.StringDataPtr(grant.IssuingAccount),
					"operations":        llx.ArrayData(operations, mqlTypes.String),
					"constraints":       llx.DictData(constraints),
					"createdAt":         llx.TimeDataPtr(grant.CreationDate),
				})
			if err != nil {
				return nil, err
			}
			mqlGrant.(*mqlAwsKmsGrant).cacheKeyArn = keyArn
			res = append(res, mqlGrant)
		}
	}
	return res, nil
}

func kmsGrantConstraintsToDict(c *types.GrantConstraints) (any, error) {
	if c == nil {
		return nil, nil
	}
	out := map[string]any{}
	if len(c.EncryptionContextEquals) > 0 {
		eq := make(map[string]any, len(c.EncryptionContextEquals))
		for k, v := range c.EncryptionContextEquals {
			eq[k] = v
		}
		out["encryptionContextEquals"] = eq
	}
	if len(c.EncryptionContextSubset) > 0 {
		sub := make(map[string]any, len(c.EncryptionContextSubset))
		for k, v := range c.EncryptionContextSubset {
			sub[k] = v
		}
		out["encryptionContextSubset"] = sub
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (a *mqlAwsKmsGrant) id() (string, error) {
	return a.cacheKeyArn + "/grant/" + a.GrantId.Data, nil
}

func (a *mqlAwsKmsGrant) key() (*mqlAwsKmsKey, error) {
	keyArn := a.cacheKeyArn
	if keyArn == "" {
		a.Key.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringData(keyArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func initAwsKmsKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// Already materialized by an earlier reference or by the list that
	// built it: NewResource consults the cache only after this init
	// returns, so without this the same target is fetched once per
	// referring resource and the result thrown away.
	if cached := cachedArgByArn(runtime, ResourceAwsKmsKey, args); cached != nil {
		return args, cached, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformKmsKey); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	r := args["arn"]
	if r == nil {
		return nil, nil, errors.New("arn required to fetch aws kms key")
	}
	keyRef, ok := r.Value.(string)
	if !ok {
		return nil, nil, errors.New("invalid arn")
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	region := rawStringArg(args["region"])

	if strings.HasPrefix(keyRef, "arn:") {
		normalized, err := NormalizeKmsKeyRef(keyRef, region, conn.AccountId())
		if err != nil {
			return nil, nil, err
		}

		if strings.HasPrefix(normalized.Resource, kmsAliasResourcePrefix) {
			metadata, err := resolveKmsKeyMetadata(conn, keyRef, normalized.Region)
			if err != nil {
				return nil, nil, err
			}
			resolved, err := arn.Parse(convert.ToValue(metadata.Arn))
			if err != nil {
				return nil, nil, fmt.Errorf("invalid KMS key ARN %q returned by DescribeKey: %w", convert.ToValue(metadata.Arn), err)
			}
			if key, err := findKmsKeyInCache(runtime, keyRef, resolved.String(), resolved.Region); err != nil {
				return nil, nil, err
			} else if key != nil {
				applyCachedKmsKeyArgs(args, key)
				return args, key, nil
			}
			applyKmsKeyArnArgs(args, resolved, conn.AccountId())
			return args, nil, nil
		}

		if key, err := findKmsKeyInCache(runtime, keyRef, normalized.String(), normalized.Region); err != nil {
			return nil, nil, err
		} else if key != nil {
			applyCachedKmsKeyArgs(args, key)
			return args, key, nil
		}

		applyKmsKeyArnArgs(args, normalized, conn.AccountId())
		return args, nil, nil
	}

	if strings.HasPrefix(keyRef, kmsAliasResourcePrefix) {
		metadata, err := resolveKmsKeyMetadata(conn, keyRef, region)
		if err != nil {
			return nil, nil, err
		}
		resolved, err := arn.Parse(convert.ToValue(metadata.Arn))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid KMS key ARN %q returned by DescribeKey: %w", convert.ToValue(metadata.Arn), err)
		}
		if key, err := findKmsKeyInCache(runtime, keyRef, resolved.String(), resolved.Region); err != nil {
			return nil, nil, err
		} else if key != nil {
			applyCachedKmsKeyArgs(args, key)
			return args, key, nil
		}
		applyKmsKeyArnArgs(args, resolved, conn.AccountId())
		return args, nil, nil
	}

	if !isKmsKeyID(keyRef) {
		return nil, nil, fmt.Errorf("invalid KMS key reference %q", keyRef)
	}

	if key, err := findKmsKeyInCache(runtime, keyRef, "", region); err != nil {
		return nil, nil, err
	} else if key != nil {
		applyCachedKmsKeyArgs(args, key)
		return args, key, nil
	}

	metadata, err := resolveKmsKeyMetadata(conn, keyRef, region)
	if err != nil {
		if region == "" {
			return nil, nil, err
		}
		normalized, normalizeErr := NormalizeKmsKeyRef(keyRef, region, conn.AccountId())
		if normalizeErr != nil {
			return nil, nil, normalizeErr
		}
		if Is400AccessDeniedError(err) {
			applyKmsKeyArnArgs(args, normalized, conn.AccountId())
			return args, nil, nil
		}
		return nil, nil, err
	}

	resolved, err := arn.Parse(convert.ToValue(metadata.Arn))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid KMS key ARN %q returned by DescribeKey: %w", convert.ToValue(metadata.Arn), err)
	}

	if key, err := findKmsKeyInCache(runtime, keyRef, resolved.String(), resolved.Region); err != nil {
		return nil, nil, err
	} else if key != nil {
		applyCachedKmsKeyArgs(args, key)
		return args, key, nil
	}

	applyKmsKeyArnArgs(args, resolved, conn.AccountId())
	return args, nil, nil
}

// resolveKmsKeyRef turns an optional KMS key reference carried on another
// resource into a key resource, marking the field null when no key is
// configured. The reference may be an ARN, an alias, or a bare key ID; the
// last of those cannot name its own region, so the caller supplies the region
// of the resource holding the reference. The caller also passes the address of
// its own field state, because a singular resource accessor that returns nil
// without setting one panics the runtime.
func resolveKmsKeyRef(runtime *plugin.Runtime, keyRef *string, region string, state *plugin.State) (*mqlAwsKmsKey, error) {
	if keyRef == nil || *keyRef == "" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args := map[string]*llx.RawData{"arn": llx.StringDataPtr(keyRef)}
	if region != "" {
		args["region"] = llx.StringData(region)
	}
	res, err := NewResource(runtime, "aws.kms.key", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func resolveKmsKeyMetadata(conn *connection.AwsConnection, keyRef, region string) (*types.KeyMetadata, error) {
	if region != "" {
		return describeKmsKeyInRegion(conn, keyRef, region)
	}

	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}

	matches := make(map[string]*types.KeyMetadata)
	for _, region := range regions {
		metadata, err := describeKmsKeyInRegion(conn, keyRef, region)
		if err != nil {
			if Is400AccessDeniedError(err) || isKmsNotFoundError(err) {
				continue
			}
			return nil, err
		}
		if metadata == nil || metadata.Arn == nil {
			continue
		}
		matches[*metadata.Arn] = metadata
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("could not resolve KMS key reference %q in accessible regions", keyRef)
	case 1:
		for _, metadata := range matches {
			return metadata, nil
		}
	}

	return nil, fmt.Errorf("KMS key reference %q matches multiple regions; provide a region to disambiguate it", keyRef)
}

func describeKmsKeyInRegion(conn *connection.AwsConnection, keyRef, region string) (*types.KeyMetadata, error) {
	svc := conn.Kms(region)
	resp, err := svc.DescribeKey(context.Background(), &kms.DescribeKeyInput{KeyId: &keyRef})
	if err != nil {
		return nil, err
	}
	return resp.KeyMetadata, nil
}

func findKmsKeyInCache(runtime *plugin.Runtime, rawRef, normalizedArn, region string) (*mqlAwsKmsKey, error) {
	obj, err := CreateResource(runtime, ResourceAwsKms, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	kmsResource := obj.(*mqlAwsKms)

	rawResources := kmsResource.GetKeys()
	if rawResources.Error != nil {
		return nil, rawResources.Error
	}

	matches := make([]*mqlAwsKmsKey, 0)
	for _, rawResource := range rawResources.Data {
		key := rawResource.(*mqlAwsKmsKey)
		if key.Arn.Data == rawRef || key.Arn.Data == normalizedArn || key.Id.Data == rawRef {
			matches = append(matches, key)
		}
	}

	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return matches[0], nil
	}

	if region != "" {
		for _, key := range matches {
			if key.Region.Data == region {
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("KMS key reference %q matches multiple regions; provide a region to disambiguate it", rawRef)
}

func applyKmsKeyArnArgs(args map[string]*llx.RawData, keyArn arn.ARN, connAccountId string) {
	if keyArn.AccountID != "" && keyArn.AccountID != connAccountId {
		log.Warn().Str("arn", keyArn.String()).Str("currentAccount", connAccountId).Str("keyAccount", keyArn.AccountID).Msg("cross-account KMS key reference, returning ARN only")
	}
	args["arn"] = llx.StringData(keyArn.String())
	args["region"] = llx.StringData(keyArn.Region)
	if strings.HasPrefix(keyArn.Resource, kmsKeyResourcePrefix) {
		args["id"] = llx.StringData(extractKmsKeyId(keyArn.Resource))
	}
}

func applyCachedKmsKeyArgs(args map[string]*llx.RawData, key *mqlAwsKmsKey) {
	args["arn"] = llx.StringData(key.Arn.Data)
	args["region"] = llx.StringData(key.Region.Data)
	args["id"] = llx.StringData(key.Id.Data)
}

func rawStringArg(arg *llx.RawData) string {
	if arg == nil {
		return ""
	}
	v, ok := arg.Value.(string)
	if !ok {
		return ""
	}
	return v
}

func isKmsNotFoundError(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NotFoundException"
}

type mqlAwsKmsKeyMultiRegionConfigurationInternal struct {
	cachePrimary  *types.MultiRegionKey
	cacheReplicas []types.MultiRegionKey
}

func (a *mqlAwsKmsKeyMultiRegionConfiguration) primaryKey() (*mqlAwsKmsKey, error) {
	if a.cachePrimary == nil || a.cachePrimary.Arn == nil || *a.cachePrimary.Arn == "" {
		a.PrimaryKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args := map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cachePrimary.Arn),
	}
	if a.cachePrimary.Region != nil && *a.cachePrimary.Region != "" {
		args["region"] = llx.StringDataPtr(a.cachePrimary.Region)
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, args)
	if err != nil {
		// best-effort: the primary key may live in a region the caller doesn't have access to.
		if Is400AccessDeniedError(err) {
			log.Debug().Str("arn", *a.cachePrimary.Arn).Msg("access denied resolving primary KMS key")
			a.PrimaryKey.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsKmsKeyMultiRegionConfiguration) replicaKeys() ([]any, error) {
	res := make([]any, 0, len(a.cacheReplicas))
	for _, replica := range a.cacheReplicas {
		if replica.Arn == nil || *replica.Arn == "" {
			continue
		}
		args := map[string]*llx.RawData{
			"arn": llx.StringDataPtr(replica.Arn),
		}
		if replica.Region != nil && *replica.Region != "" {
			args["region"] = llx.StringDataPtr(replica.Region)
		}
		mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, args)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Debug().Str("arn", *replica.Arn).Msg("access denied resolving replica KMS key")
				continue
			}
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

func initAwsKmsCustomKeyStore(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["customKeyStoreId"]
	if !ok || idArg == nil {
		return args, nil, nil
	}
	customKeyStoreId, ok := idArg.Value.(string)
	if !ok || customKeyStoreId == "" {
		return args, nil, nil
	}

	region := rawStringArg(args["region"])
	if region == "" {
		return args, nil, errors.New("region required to fetch aws kms custom key store")
	}

	// Skip the DescribeCustomKeyStores call when the store was already
	// materialized via aws.kms.customKeyStores() — that path puts it in
	// the runtime cache under the same `__id` shape.
	cacheID := "aws.kms.customKeyStore\x00" + kmsCustomKeyStoreID(region, customKeyStoreId)
	if cached, ok := runtime.Resources.Get(cacheID); ok {
		return args, cached, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Kms(region)

	resp, err := svc.DescribeCustomKeyStores(context.Background(),
		&kms.DescribeCustomKeyStoresInput{CustomKeyStoreId: &customKeyStoreId})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return args, nil, nil
		}
		return nil, nil, err
	}
	if len(resp.CustomKeyStores) == 0 {
		return args, nil, nil
	}

	mqlStore, err := newMqlAwsKmsCustomKeyStore(runtime, region, resp.CustomKeyStores[0])
	if err != nil {
		return nil, nil, err
	}
	return args, mqlStore, nil
}

// extractKmsKeyId extracts the key ID from an ARN resource string like "key/uuid".
func extractKmsKeyId(resource string) string {
	return strings.TrimPrefix(resource, kmsKeyResourcePrefix)
}

// encryptedVolumes returns the EBS volumes encrypted with this key. AWS exposes
// no "list resources by KMS key" API, so this scans the account's volumes (a
// cross-region list that is cached after first use) and matches on the volume's
// KMS key ARN.
func (a *mqlAwsKmsKey) encryptedVolumes() ([]any, error) {
	keyArn := a.Arn.Data
	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	volumes := obj.(*mqlAwsEc2).GetVolumes()
	if volumes.Error != nil {
		return nil, volumes.Error
	}
	res := []any{}
	for _, v := range volumes.Data {
		vol, ok := v.(*mqlAwsEc2Volume)
		if !ok {
			continue
		}
		// KmsKeyId from the EC2 API is already a full key ARN.
		if vol.cacheKmsKeyId != nil && *vol.cacheKmsKeyId == keyArn {
			res = append(res, vol)
		}
	}
	return res, nil
}

type mqlAwsKmsGrantInternal struct {
	cacheKeyArn string
}
