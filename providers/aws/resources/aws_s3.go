// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/providers/aws/resources/awspolicy"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsS3control) id() (string, error) {
	return ResourceAwsS3control, nil
}

type mqlAwsS3controlInternal struct {
	publicAccessOnce   sync.Once
	publicAccessConfig *s3controltypes.PublicAccessBlockConfiguration
	publicAccessErr    error
}

// fetchAccountPublicAccessBlock reads the account-level Block Public Access
// configuration once and hands it to every field derived from it. An account
// that has never configured one is not an error: the API reports
// NoSuchPublicAccessBlockConfiguration, and the configuration is simply absent.
func (a *mqlAwsS3control) fetchAccountPublicAccessBlock() (*s3controltypes.PublicAccessBlockConfiguration, error) {
	a.publicAccessOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3Control("")
		resp, err := svc.GetPublicAccessBlock(context.Background(), &s3control.GetPublicAccessBlockInput{
			AccountId: aws.String(conn.AccountId()),
		})
		if err != nil {
			var notFoundErr *s3controltypes.NoSuchPublicAccessBlockConfiguration
			if errors.As(err, &notFoundErr) {
				return
			}
			a.publicAccessErr = err
			return
		}
		a.publicAccessConfig = resp.PublicAccessBlockConfiguration
	})
	return a.publicAccessConfig, a.publicAccessErr
}

// newMqlS3PublicAccessBlock builds the four Block Public Access settings shared
// by the account, a bucket, and an access point. They come back from three
// different SDK structs carrying the same four members, which is why this
// takes the pointers rather than a struct.
func newMqlS3PublicAccessBlock(runtime *plugin.Runtime, ownerID string, blockPublicAcls, blockPublicPolicy, ignorePublicAcls, restrictPublicBuckets *bool) (*mqlAwsS3PublicAccessBlock, error) {
	res, err := CreateResource(runtime, "aws.s3.publicAccessBlock", map[string]*llx.RawData{
		"__id":                  llx.StringData(ownerID + "/publicAccessBlock"),
		"blockPublicAcls":       llx.BoolData(convert.ToValue(blockPublicAcls)),
		"blockPublicPolicy":     llx.BoolData(convert.ToValue(blockPublicPolicy)),
		"ignorePublicAcls":      llx.BoolData(convert.ToValue(ignorePublicAcls)),
		"restrictPublicBuckets": llx.BoolData(convert.ToValue(restrictPublicBuckets)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3PublicAccessBlock), nil
}

func (a *mqlAwsS3control) accountBlockPublicAccess() (*mqlAwsS3PublicAccessBlock, error) {
	config, err := a.fetchAccountPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		a.AccountBlockPublicAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return newMqlS3PublicAccessBlock(a.MqlRuntime, ResourceAwsS3control+"/"+conn.AccountId(),
		config.BlockPublicAcls, config.BlockPublicPolicy, config.IgnorePublicAcls, config.RestrictPublicBuckets)
}

func (a *mqlAwsS3control) accountPublicAccessBlock() (any, error) {
	config, err := a.fetchAccountPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return convert.JsonToDict(config)
}

func (a *mqlAwsS3) id() (string, error) {
	return ResourceAwsS3, nil
}

func (a *mqlAwsS3) buckets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "s3", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.S3(region)
		log.Debug().Str("region", region).Msg("listing S3 buckets in region")
		params := &s3.ListBucketsInput{BucketRegion: aws.String(region)}
		paginator := s3.NewListBucketsPaginator(svc, params, func(o *s3.ListBucketsPaginatorOptions) {
			o.Limit = 100
		})

		res := []any{}
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, bucket := range output.Buckets {
				if conn.Filters.S3.IsFilteredOut(convert.ToValue(bucket.Name)) {
					continue
				}

				mqlS3Bucket, err := CreateResource(a.MqlRuntime, ResourceAwsS3Bucket,
					map[string]*llx.RawData{
						"name":      llx.StringDataPtr(bucket.Name),
						"arn":       llx.StringData(fmt.Sprintf(s3ArnPattern, convert.ToValue(bucket.Name))),
						"exists":    llx.BoolData(true),
						"location":  llx.StringData(region),
						"createdAt": llx.TimeDataPtr(bucket.CreationDate),
					})
				if err != nil {
					return nil, err
				}

				// keeps the tags lazy unless the filters need to be evaluated
				if conn.Filters.General.HasTags() {
					tags, err := mqlS3Bucket.(*mqlAwsS3Bucket).tags()
					if err != nil {
						return nil, err
					}

					if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
						continue
					}
				}

				res = append(res, mqlS3Bucket)
			}
		}

		return res, nil
	})
}

func initAwsS3BucketPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// reuse the init func for the bucket
	_, s3bucketResource, err := initAwsS3Bucket(runtime, args)
	if err != nil {
		return args, nil, err
	}
	bucket, ok := s3bucketResource.(*mqlAwsS3Bucket)
	if !ok {
		return args, nil, errors.New("unexpected resource type for s3 bucket")
	}
	// then use it to get its policy
	policyResource := bucket.GetPolicy()
	if policyResource != nil && policyResource.State == plugin.StateIsSet && policyResource.Data != nil {
		return args, policyResource.Data, nil
	}

	// no policy found
	resource := &mqlAwsS3BucketPolicy{}
	resource.Name.State = plugin.StateIsNull | plugin.StateIsSet
	resource.Document.State = plugin.StateIsNull | plugin.StateIsSet
	resource.Version.State = plugin.StateIsNull | plugin.StateIsSet
	resource.BucketName = plugin.TValue[string]{
		Data: bucket.GetName().Data, State: plugin.StateIsSet,
	}
	return args, resource, nil
}

func initAwsS3Bucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// NOTE: bucket only initializes with arn and name
	if len(args) >= 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformS3Bucket); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws s3 bucket")
	}

	// Resolve the bucket name and ARN. The bucket name is encoded directly in
	// the ARN (arn:aws:s3:::<name>), so we can build the resource without
	// listing every bucket in every region. Per-bucket fields lazy-load.
	var arnVal, name string
	if args["arn"] != nil {
		arnVal = args["arn"].Value.(string)
		parsed, err := arn.Parse(arnVal)
		if err != nil || parsed.Service != "s3" {
			return nil, nil, errors.Newf("not a valid bucket ARN '%s'", arnVal)
		}
		name = parsed.Resource
	} else {
		name = args["name"].Value.(string)
		arnVal = fmt.Sprintf(s3ArnPattern, name)
	}
	log.Debug().Str("arn", arnVal).Msg("init s3 bucket with arn")

	// A single HeadBucket confirms existence without listing every bucket in
	// every region. It is possible for a resource to reference a
	// non-existent/deleted bucket; recording exists=false lets per-bucket field
	// accessors short-circuit instead of erroring. A non-404 error (e.g. a
	// cross-region redirect or access-denied) still means the bucket exists.
	exists := true
	conn := runtime.Connection.(*connection.AwsConnection)
	if _, err := conn.S3("").HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: aws.String(name),
	}); err != nil && isNotFoundForS3(err) {
		exists = false
		log.Debug().Msgf("no bucket found for %s", arnVal)
	}

	mqlAwsS3Bucket, err := CreateResource(runtime, ResourceAwsS3Bucket,
		map[string]*llx.RawData{
			"arn":    llx.StringData(arnVal),
			"name":   llx.StringData(name),
			"exists": llx.BoolData(exists),
		})
	if err != nil {
		return nil, nil, err
	}
	return args, mqlAwsS3Bucket, nil
}

func (a *mqlAwsS3Bucket) id() (string, error) {
	// assumes bucket names are globally unique, which they are right now
	return a.Arn.Data, nil
}

type mqlAwsS3BucketAccessPointInternal struct {
	region          string
	accountID       string
	cacheBucketName string
	cacheVpcId      string

	publicAccessOnce   sync.Once
	publicAccessConfig *s3controltypes.PublicAccessBlockConfiguration
	publicAccessErr    error
}

func (a *mqlAwsS3BucketAccessPoint) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsS3Bucket) accessPoints() ([]any, error) {
	res := []any{}
	// placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return res, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketName := a.Name.Data
	// surface a location lookup failure instead of silently defaulting to
	// us-east-1, which would list access points in the wrong region and miss
	// them for buckets that actually live elsewhere. An empty (but error-free)
	// location is legitimately us-east-1.
	location := a.GetLocation()
	if location.Error != nil {
		return nil, location.Error
	}
	region := location.Data
	if region == "" {
		region = "us-east-1"
	}
	accountID := conn.AccountId()
	svc := conn.S3Control(region)
	ctx := context.Background()

	params := &s3control.ListAccessPointsInput{
		AccountId: aws.String(accountID),
		Bucket:    aws.String(bucketName),
	}
	paginator := s3control.NewListAccessPointsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ap := range page.AccessPointList {
			vpcId := ""
			if ap.VpcConfiguration != nil {
				vpcId = convert.ToValue(ap.VpcConfiguration.VpcId)
			}
			mqlAp, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.accessPoint",
				map[string]*llx.RawData{
					"__id":            llx.StringDataPtr(ap.AccessPointArn),
					"arn":             llx.StringDataPtr(ap.AccessPointArn),
					"name":            llx.StringDataPtr(ap.Name),
					"bucketAccountId": llx.StringDataPtr(ap.BucketAccountId),
					"networkOrigin":   llx.StringData(string(ap.NetworkOrigin)),
					"alias":           llx.StringDataPtr(ap.Alias),
				})
			if err != nil {
				return nil, err
			}
			apResource := mqlAp.(*mqlAwsS3BucketAccessPoint)
			apResource.region = region
			apResource.accountID = accountID
			apResource.cacheBucketName = convert.ToValue(ap.Bucket)
			apResource.cacheVpcId = vpcId
			res = append(res, mqlAp)
		}
	}
	return res, nil
}

func (a *mqlAwsS3BucketAccessPoint) bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheBucketName == "" {
		a.Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(a.cacheBucketName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsS3BucketAccessPoint) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// fetchPublicAccessBlock reads the access point's Block Public Access
// configuration once and hands it to every field derived from it.
func (a *mqlAwsS3BucketAccessPoint) fetchPublicAccessBlock() (*s3controltypes.PublicAccessBlockConfiguration, error) {
	a.publicAccessOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3Control(a.region)
		name := a.Name.Data
		resp, err := svc.GetAccessPoint(context.Background(), &s3control.GetAccessPointInput{
			AccountId: aws.String(a.accountID),
			Name:      aws.String(name),
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Debug().Str("accessPoint", a.Arn.Data).Err(err).Msg("access denied reading s3 access point public access block")
				return
			}
			a.publicAccessErr = err
			return
		}
		if resp.PublicAccessBlockConfiguration == nil {
			log.Debug().Str("accessPoint", a.Arn.Data).Msg("s3 access point has no public access block configured")
			return
		}
		a.publicAccessConfig = resp.PublicAccessBlockConfiguration
	})
	return a.publicAccessConfig, a.publicAccessErr
}

func (a *mqlAwsS3BucketAccessPoint) blockPublicAccess() (*mqlAwsS3PublicAccessBlock, error) {
	config, err := a.fetchPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		a.BlockPublicAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlS3PublicAccessBlock(a.MqlRuntime, a.Arn.Data,
		config.BlockPublicAcls, config.BlockPublicPolicy, config.IgnorePublicAcls, config.RestrictPublicBuckets)
}

func (a *mqlAwsS3BucketAccessPoint) publicAccessBlock() (any, error) {
	config, err := a.fetchPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return convert.JsonToDict(config)
}

func (a *mqlAwsS3BucketAccessPoint) policy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3Control(a.region)
	ctx := context.Background()

	name := a.Name.Data
	resp, err := svc.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{
		AccountId: aws.String(a.accountID),
		Name:      aws.String(name),
	})
	if err != nil {
		// access points without a resource policy return NoSuchAccessPointPolicy
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchAccessPointPolicy" {
			return "", nil
		}
		if Is400AccessDeniedError(err) {
			log.Debug().Str("accessPoint", a.Arn.Data).Err(err).Msg("access denied reading s3 access point policy")
			return "", nil
		}
		return "", err
	}
	return convert.ToValue(resp.Policy), nil
}

func (a *mqlAwsS3Bucket) policy() (*mqlAwsS3BucketPolicy, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketname := a.Name.Data
	svc := conn.S3(region)
	ctx := context.Background()

	policy, err := svc.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isS3BucketInaccessible(err) {
			a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	if policy != nil && policy.Policy != nil {
		parsedPolicy, err := parseS3BucketPolicy(*policy.Policy)
		if err != nil {
			return nil, err
		}
		// create the policy resource
		mqlS3BucketPolicy, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.policy",
			map[string]*llx.RawData{
				"name":       llx.StringData(bucketname),
				"bucketName": llx.StringData(bucketname),
				"version":    llx.StringData(parsedPolicy.Version),
				"document":   llx.StringDataPtr(policy.Policy),
			})
		if err != nil {
			return nil, err
		}

		return mqlS3BucketPolicy.(*mqlAwsS3BucketPolicy), nil
	}

	// no bucket policy found, return nil for the policy
	a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// enforceSslOnly reports whether the bucket policy denies any request that does
// not use TLS, i.e. it contains a Deny statement conditioned on
// `aws:SecureTransport` being false. It is false when the bucket has no policy.
func (a *mqlAwsS3Bucket) enforceSslOnly() (bool, error) {
	statements, err := a.policyStatements()
	if err != nil {
		return false, err
	}
	for _, raw := range statements {
		stmt := raw.(*mqlAwsIamPolicyStatement)
		effect := stmt.GetEffect()
		if effect.Error != nil {
			return false, effect.Error
		}
		if !strings.EqualFold(effect.Data, "Deny") {
			continue
		}
		conditions := stmt.GetConditions()
		if conditions.Error != nil {
			return false, conditions.Error
		}
		if conditionDeniesInsecureTransport(conditions.Data) {
			return true, nil
		}
	}
	return false, nil
}

// conditionDeniesInsecureTransport reports whether a statement condition map
// contains a `Bool` operator that requires `aws:SecureTransport` to be false.
// The condition value may be a JSON bool, a string ("false"), or a list of
// either, so each form is checked.
func conditionDeniesInsecureTransport(conditions any) bool {
	condMap, ok := conditions.(map[string]any)
	if !ok {
		return false
	}
	for op, raw := range condMap {
		if !strings.EqualFold(op, "Bool") {
			continue
		}
		keys, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range keys {
			if strings.EqualFold(k, "aws:SecureTransport") && isFalseConditionValue(v) {
				return true
			}
		}
	}
	return false
}

func isFalseConditionValue(v any) bool {
	switch val := v.(type) {
	case bool:
		return !val
	case string:
		return strings.EqualFold(val, "false")
	case []any:
		for _, item := range val {
			if isFalseConditionValue(item) {
				return true
			}
		}
	}
	return false
}

func (a *mqlAwsS3Bucket) tags() (map[string]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil || !ok {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketname := a.Name.Data
	svc := conn.S3(region)
	ctx := context.Background()

	tags, err := svc.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: &bucketname,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchTagSet" {
				return nil, nil
			}
		}
		if isS3BucketInaccessible(err) {
			return nil, nil
		}

		return nil, err
	}

	res := map[string]any{}
	for _, tag := range tags.TagSet {
		res[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
	}

	return res, nil
}

func (a *mqlAwsS3Bucket) location() (string, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried for location
	if !a.Exists.Data {
		return "", nil
	}

	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.S3("")
	ctx := context.Background()

	location, err := svc.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isS3BucketInaccessible(err) {
			return "", nil
		}
		return "", err
	}

	region := string(location.LocationConstraint)
	// us-east-1 returns "" therefore we set it explicitly
	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html#API_GetBucketLocation_ResponseSyntax
	if region == "" {
		region = "us-east-1"
	}
	return region, nil
}

// bucketRegion resolves the bucket's home region for per-bucket data calls
// (logging, ACL, policy, ...). Those must target the bucket's own region; a
// client pointed at the wrong region answers with an HTTP 301 redirect. Buckets
// discovered through the listing path carry their region, but a bucket reached by
// name (e.g. aws.cloudtrail.trail.s3bucket) resolves it lazily here.
//
// ok is false — and the caller returns the field's empty value — when the bucket
// can't be reached from the account being scanned: it's a placeholder for a
// deleted bucket, or its region can't be determined because it lives in another
// account we have no permission to read. A CloudTrail organization trail delivers
// logs to a bucket owned by the management account, so a member-account scan
// can't read it.
func (a *mqlAwsS3Bucket) bucketRegion() (string, bool, error) {
	if !a.Exists.Data {
		return "", false, nil
	}
	loc := a.GetLocation()
	if loc.Error != nil {
		return "", false, loc.Error
	}
	if loc.Data == "" {
		return "", false, nil
	}
	return loc.Data, true, nil
}

func (a *mqlAwsS3Bucket) cloudformationStack() (*mqlAwsCloudformationStack, error) {
	tags := a.GetTags()
	if tags.Error != nil {
		return nil, tags.Error
	}
	loc := a.GetLocation()
	if loc.Error != nil {
		return nil, loc.Error
	}
	stack, err := cloudformationStackForTags(a.MqlRuntime, loc.Data, tags.Data)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		a.CloudformationStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func (a *mqlAwsS3Bucket) managedBy() (string, error) {
	tags := a.GetTags()
	if tags.Error != nil {
		return "", tags.Error
	}
	return managedByFromTags(tags.Data), nil
}

func (a *mqlAwsS3Bucket) gatherAcl() (*s3.GetBucketAclOutput, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return nil, nil
	}
	a.aclOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.aclErr = err
			return
		}
		if !ok {
			// A cross-account or deleted bucket yields no ACL rather than an
			// error; callers treat a nil result as "no grants".
			return
		}
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		bucketname := a.Name.Data
		svc := conn.S3(region)
		ctx := context.Background()

		out, err := svc.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: &bucketname,
		})
		if err != nil {
			if isS3BucketInaccessible(err) {
				return
			}
			a.aclErr = err
			return
		}
		a.aclOutput = out
	})
	return a.aclOutput, a.aclErr
}

func (a *mqlAwsS3Bucket) acl() ([]any, error) {
	bucketname := a.Name.Data

	acl, err := a.gatherAcl()
	if err != nil {
		return nil, err
	}
	if acl == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, grant := range acl.Grants {
		// NOTE: not all grantees have URI and IDs, canonical users have id, groups have URIs and the
		// display name may not be unique
		if grant.Grantee == nil || (grant.Grantee.URI == nil && grant.Grantee.ID == nil) {
			return nil, fmt.Errorf("unsupported grant: %v", grant)
		}

		grantee := map[string]any{
			"id":           convert.ToValue(grant.Grantee.ID),
			"name":         convert.ToValue(grant.Grantee.DisplayName),
			"emailAddress": convert.ToValue(grant.Grantee.EmailAddress),
			"type":         string(grant.Grantee.Type),
			"uri":          convert.ToValue(grant.Grantee.URI),
		}

		id := bucketname + "/" + string(grant.Permission)
		if grant.Grantee.URI != nil {
			id = id + "/" + *grant.Grantee.URI
		} else {
			id = id + "/" + *grant.Grantee.ID
		}

		mqlBucketGrant, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.grant",
			map[string]*llx.RawData{
				"id":         llx.StringData(id),
				"name":       llx.StringData(bucketname),
				"permission": llx.StringData(string(grant.Permission)),
				"grantee":    llx.MapData(grantee, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBucketGrant)
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) fetchPublicAccessBlock() (*s3types.PublicAccessBlockConfiguration, error) {
	a.publicAccessOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.publicAccessErr = err
			return
		}
		if !ok {
			return
		}
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		bucketname := a.Name.Data
		svc := conn.S3(region)
		ctx := context.Background()

		resp, err := svc.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: &bucketname,
		})
		if err != nil {
			if isS3BucketInaccessible(err) {
				return
			}
			a.publicAccessErr = err
			return
		}
		a.publicAccessConfig = resp.PublicAccessBlockConfiguration
	})
	return a.publicAccessConfig, a.publicAccessErr
}

// s3PublicAccessBlockFlag resolves one block-public-access setting. When no
// public access block configuration exists on the bucket, the protection is
// not in effect, so each flag reports false.
func (a *mqlAwsS3Bucket) s3PublicAccessBlockFlag(get func(*s3types.PublicAccessBlockConfiguration) *bool) (bool, error) {
	config, err := a.fetchPublicAccessBlock()
	if err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	return convert.ToValue(get(config)), nil
}

func (a *mqlAwsS3Bucket) blockPublicAcls() (bool, error) {
	return a.s3PublicAccessBlockFlag(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicAcls })
}

func (a *mqlAwsS3Bucket) blockPublicPolicy() (bool, error) {
	return a.s3PublicAccessBlockFlag(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.BlockPublicPolicy })
}

func (a *mqlAwsS3Bucket) ignorePublicAcls() (bool, error) {
	return a.s3PublicAccessBlockFlag(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.IgnorePublicAcls })
}

func (a *mqlAwsS3Bucket) restrictPublicBuckets() (bool, error) {
	return a.s3PublicAccessBlockFlag(func(c *s3types.PublicAccessBlockConfiguration) *bool { return c.RestrictPublicBuckets })
}

func (a *mqlAwsS3Bucket) blockPublicAccess() (*mqlAwsS3PublicAccessBlock, error) {
	config, err := a.fetchPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		a.BlockPublicAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlS3PublicAccessBlock(a.MqlRuntime, a.Arn.Data,
		config.BlockPublicAcls, config.BlockPublicPolicy, config.IgnorePublicAcls, config.RestrictPublicBuckets)
}

func (a *mqlAwsS3Bucket) publicAccessBlock() (any, error) {
	config, err := a.fetchPublicAccessBlock()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return convert.JsonToDict(config)
}

func (a *mqlAwsS3Bucket) owner() (map[string]any, error) {
	acl, err := a.gatherAcl()
	if err != nil {
		return nil, err
	}
	if acl == nil {
		return nil, nil
	}

	if acl.Owner == nil {
		return nil, errors.New("could not gather aws s3 bucket's owner information")
	}

	res := map[string]any{}
	res["id"] = convert.ToValue(acl.Owner.ID)
	res["name"] = convert.ToValue(acl.Owner.DisplayName)

	return res, nil
}

// see https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html
const (
	s3AuthenticatedUsersGroup = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	s3AllUsersGroup           = "http://acs.amazonaws.com/groups/global/AllUsers"
)

// s3BucketIsPublic applies AWS's actual Block Public Access semantics to a
// policy signal and an ACL signal.
//
// BlockPublicAcls and BlockPublicPolicy only reject *new* public ACLs and
// policies; AWS documents that enabling them does not affect grants that
// already exist. Only IgnorePublicAcls neutralizes an existing public ACL, and
// only RestrictPublicBuckets neutralizes an existing public policy. Treating
// any of the four as "not public" reported a world-readable bucket as private
// whenever, say, BlockPublicAcls was on and a `Principal: "*"` policy was
// attached -- the standard static-site/CDN configuration.
func s3BucketIsPublic(pab *s3types.PublicAccessBlockConfiguration, policyIsPublic, aclIsPublic bool) bool {
	ignorePublicAcls := pab != nil && pab.IgnorePublicAcls != nil && *pab.IgnorePublicAcls
	restrictPublicBuckets := pab != nil && pab.RestrictPublicBuckets != nil && *pab.RestrictPublicBuckets

	if policyIsPublic && !restrictPublicBuckets {
		return true
	}
	if aclIsPublic && !ignorePublicAcls {
		return true
	}
	return false
}

// s3PolicyGrantsPublicAccess reports whether any Allow statement names the
// wildcard principal.
func s3PolicyGrantsPublicAccess(policy *awspolicy.S3BucketPolicy) bool {
	if policy == nil {
		return false
	}
	for _, statement := range policy.Statements {
		if !strings.EqualFold(statement.Effect, "Allow") {
			continue
		}
		if awsPrincipal, ok := statement.Principal["AWS"]; ok {
			if slices.Contains(awsPrincipal, "*") {
				return true
			}
		}
	}
	return false
}

// s3GrantsArePublic reports whether any ACL grant targets the AllUsers or
// AuthenticatedUsers group.
func s3GrantsArePublic(grants []s3types.Grant) bool {
	for i := range grants {
		grant := grants[i]
		if grant.Grantee == nil {
			continue
		}
		if grant.Grantee.Type == s3types.TypeGroup &&
			(convert.ToValue(grant.Grantee.URI) == s3AuthenticatedUsersGroup ||
				convert.ToValue(grant.Grantee.URI) == s3AllUsersGroup) {
			return true
		}
	}
	return false
}

func (a *mqlAwsS3Bucket) public() (bool, error) {
	// markUnknown reports null rather than a confident `false` when neither the
	// policy nor the ACL could be read. `false` here is indistinguishable from
	// "verified not public", which is the dangerous direction for an exposure
	// check on an under-scoped token.
	markUnknown := func() (bool, error) {
		a.Public.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}

	region, ok, err := a.bucketRegion()
	if err != nil {
		return false, err
	}
	if !ok {
		return markUnknown()
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketname := a.Name.Data
	svc := conn.S3(region)
	ctx := context.Background()

	accessBlock, err := a.fetchPublicAccessBlock()
	if err != nil {
		return false, err
	}

	policyIsPublic := false
	policyKnown := false

	// GetBucketPolicyStatus is AWS's own verdict on the policy. A `false` here
	// is a real answer about the *policy*, but it says nothing about the ACL --
	// so it must not short-circuit the ACL check below.
	statusOutput, err := svc.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: &bucketname,
	})
	if err != nil && !isS3BucketInaccessible(err) {
		return false, err
	}
	if statusOutput != nil && statusOutput.PolicyStatus != nil && statusOutput.PolicyStatus.IsPublic != nil {
		policyIsPublic = *statusOutput.PolicyStatus.IsPublic
		policyKnown = true
	}

	// Fall back to parsing the policy ourselves when the status call was denied.
	if !policyKnown {
		bucketPolicyResource := a.GetPolicy()
		if bucketPolicyResource.State == plugin.StateIsSet && bucketPolicyResource.Data != nil {
			bucketPolicy, err := bucketPolicyResource.Data.parsePolicyDocument()
			if err != nil {
				return false, err
			}
			policyIsPublic = s3PolicyGrantsPublicAccess(bucketPolicy)
			policyKnown = true
		}
	}

	aclIsPublic := false
	aclKnown := false
	acl, err := a.gatherAcl()
	if err != nil {
		return false, err
	}
	if acl != nil {
		aclIsPublic = s3GrantsArePublic(acl.Grants)
		aclKnown = true
	}

	if !policyKnown && !aclKnown {
		return markUnknown()
	}

	return s3BucketIsPublic(accessBlock, policyIsPublic, aclIsPublic), nil
}

func (a *mqlAwsS3Bucket) cors() ([]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil || !ok {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketname := a.Name.Data
	svc := conn.S3(region)
	ctx := context.Background()

	cors, err := svc.GetBucketCors(ctx, &s3.GetBucketCorsInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isS3BucketInaccessible(err) {
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	for i := range cors.CORSRules {
		corsrule := cors.CORSRules[i]
		mqlBucketCors, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.corsrule",
			map[string]*llx.RawData{
				"__id":           llx.StringData(fmt.Sprintf("%s/cors/%d", a.Arn.Data, i)),
				"name":           llx.StringData(bucketname),
				"allowedHeaders": llx.ArrayData(toInterfaceArr(corsrule.AllowedHeaders), types.String),
				"allowedMethods": llx.ArrayData(toInterfaceArr(corsrule.AllowedMethods), types.String),
				"allowedOrigins": llx.ArrayData(toInterfaceArr(corsrule.AllowedOrigins), types.String),
				"exposeHeaders":  llx.ArrayData(toInterfaceArr(corsrule.ExposeHeaders), types.String),
				"maxAgeSeconds":  llx.IntDataDefault(corsrule.MaxAgeSeconds, 0),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBucketCors)
	}

	return res, nil
}

func (a *mqlAwsS3Bucket) logging() (map[string]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil || !ok {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketname := a.Name.Data
	svc := conn.S3(region)
	ctx := context.Background()

	logging, err := svc.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isS3BucketInaccessible(err) {
			return nil, nil
		}
		return nil, err
	}

	res := map[string]any{}

	if logging != nil && logging.LoggingEnabled != nil {
		if logging.LoggingEnabled.TargetPrefix != nil {
			res["TargetPrefix"] = convert.ToValue(logging.LoggingEnabled.TargetPrefix)
		}

		if logging.LoggingEnabled.TargetBucket != nil {
			res["TargetBucket"] = convert.ToValue(logging.LoggingEnabled.TargetBucket)
		}

		// it is becoming a more complex object similar to aws.s3.bucket.grant
		// if logging.LoggingEnabled.TargetGrants != nil {
		// 	res["TargetGrants"] = *logging.LoggingEnabled.TargetGrants
		// }
	}

	return res, nil
}

func (a *mqlAwsS3Bucket) versioning() (map[string]any, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.S3(region)
	ctx := context.Background()

	versioning, err := svc.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: &bucketname,
	})
	if err != nil {
		return nil, err
	}

	res := map[string]any{}

	if versioning != nil {
		res["MFADelete"] = string(versioning.MFADelete)
		res["Status"] = string(versioning.Status)
	}

	return res, nil
}

type mqlAwsS3BucketInternal struct {
	replicationOnce    sync.Once
	replicationConfig  *s3types.ReplicationConfiguration
	replicationErr     error
	encryptionOnce     sync.Once
	encryptionConfig   *s3types.ServerSideEncryptionConfiguration
	encryptionErr      error
	aclOnce            sync.Once
	aclOutput          *s3.GetBucketAclOutput
	aclErr             error
	publicAccessOnce   sync.Once
	publicAccessConfig *s3types.PublicAccessBlockConfiguration
	publicAccessErr    error
	objectLockOnce     sync.Once
	objectLockConfig   *s3types.ObjectLockConfiguration
	objectLockErr      error
	lifecycleOnce      sync.Once
	lifecycleRulesData []s3types.LifecycleRule
	lifecycleErr       error
}

func (a *mqlAwsS3Bucket) fetchReplicationConfig() (*s3types.ReplicationConfiguration, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return nil, nil
	}
	a.replicationOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.replicationErr = err
			return
		}
		if !ok {
			return
		}
		bucketname := a.Name.Data
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3(region)
		ctx := context.Background()

		resp, err := svc.GetBucketReplication(ctx, &s3.GetBucketReplicationInput{
			Bucket: &bucketname,
		})
		if err != nil {
			if isNotFoundForS3(err) {
				return
			}
			a.replicationErr = err
			return
		}
		a.replicationConfig = resp.ReplicationConfiguration
	})
	return a.replicationConfig, a.replicationErr
}

func (a *mqlAwsS3Bucket) fetchEncryptionConfig() (*s3types.ServerSideEncryptionConfiguration, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return nil, nil
	}
	a.encryptionOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.encryptionErr = err
			return
		}
		if !ok {
			return
		}
		bucketname := a.Name.Data
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3(region)
		ctx := context.Background()

		resp, err := svc.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: &bucketname,
		})
		if err != nil {
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
					return
				}
			}
			a.encryptionErr = err
			return
		}
		a.encryptionConfig = resp.ServerSideEncryptionConfiguration
	})
	return a.encryptionConfig, a.encryptionErr
}

func (a *mqlAwsS3Bucket) replication() (any, error) {
	config, err := a.fetchReplicationConfig()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return convert.JsonToDict(config)
}

func (a *mqlAwsS3BucketReplicationRule) id() (string, error) {
	return a.ResourceId.Data, nil
}

func (a *mqlAwsS3Bucket) replicationRules() ([]any, error) {
	bucketArn := a.Arn.Data

	config, err := a.fetchReplicationConfig()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return []any{}, nil
	}

	res := []any{}
	for i, rule := range config.Rules {
		ruleId := ""
		if rule.ID != nil {
			ruleId = *rule.ID
		}

		resourceId := fmt.Sprintf("%s/replication/%d", bucketArn, i)
		if ruleId != "" {
			resourceId = fmt.Sprintf("%s/replication/%s", bucketArn, ruleId)
		}

		destBucket := ""
		destAccount := ""
		destStorageClass := ""
		if rule.Destination != nil {
			if rule.Destination.Bucket != nil {
				destBucket = *rule.Destination.Bucket
			}
			if rule.Destination.Account != nil {
				destAccount = *rule.Destination.Account
			}
			destStorageClass = string(rule.Destination.StorageClass)
		}

		deleteMarkerEnabled := false
		if rule.DeleteMarkerReplication != nil {
			deleteMarkerEnabled = rule.DeleteMarkerReplication.Status == s3types.DeleteMarkerReplicationStatusEnabled
		}

		priority := int64(0)
		if rule.Priority != nil {
			priority = int64(*rule.Priority)
		}

		args := map[string]*llx.RawData{
			"resourceId":                     llx.StringData(resourceId),
			"id":                             llx.StringData(ruleId),
			"status":                         llx.StringData(string(rule.Status)),
			"priority":                       llx.IntData(priority),
			"destinationBucket":              llx.StringData(destBucket),
			"destinationAccount":             llx.StringData(destAccount),
			"destinationStorageClass":        llx.StringData(destStorageClass),
			"deleteMarkerReplicationEnabled": llx.BoolData(deleteMarkerEnabled),
		}

		mqlRule, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.replicationRule", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAwsS3BucketEncryptionRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsS3Bucket) encrypted() (bool, error) {
	config, err := a.fetchEncryptionConfig()
	if err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	for _, rule := range config.Rules {
		if rule.ApplyServerSideEncryptionByDefault != nil && rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != "" {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsS3Bucket) kmsKey() (*mqlAwsKmsKey, error) {
	config, err := a.fetchEncryptionConfig()
	if err != nil {
		return nil, err
	}
	keyRef := ""
	if config != nil {
		for _, rule := range config.Rules {
			d := rule.ApplyServerSideEncryptionByDefault
			if d != nil && d.KMSMasterKeyID != nil && *d.KMSMasterKeyID != "" {
				keyRef = *d.KMSMasterKeyID
				break
			}
		}
	}
	if keyRef == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn":    llx.StringData(keyRef),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsS3Bucket) encryptionRules() ([]any, error) {
	bucketArn := a.Arn.Data

	config, err := a.fetchEncryptionConfig()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return []any{}, nil
	}

	res := []any{}
	for i, rule := range config.Rules {
		sseAlgorithm := ""
		kmsMasterKeyId := ""
		if rule.ApplyServerSideEncryptionByDefault != nil {
			sseAlgorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
			if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
				kmsMasterKeyId = *rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
			}
		}
		bucketKeyEnabled := false
		if rule.BucketKeyEnabled != nil {
			bucketKeyEnabled = *rule.BucketKeyEnabled
		}

		args := map[string]*llx.RawData{
			"id":               llx.StringData(fmt.Sprintf("%s/encryption/%d", bucketArn, i)),
			"sseAlgorithm":     llx.StringData(sseAlgorithm),
			"kmsMasterKeyId":   llx.StringData(kmsMasterKeyId),
			"bucketKeyEnabled": llx.BoolData(bucketKeyEnabled),
		}

		mqlRule, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.encryptionRule", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAwsS3BucketMetricsConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsS3Bucket) metricsConfigurations() ([]any, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	res := []any{}
	var token *string
	for {
		resp, err := svc.ListBucketMetricsConfigurations(ctx, &s3.ListBucketMetricsConfigurationsInput{
			Bucket:            &bucketName,
			ContinuationToken: token,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}

		for _, mc := range resp.MetricsConfigurationList {
			filterDict, err := convert.JsonToDict(mc.Filter)
			if err != nil {
				return nil, err
			}
			mcId := aws.ToString(mc.Id)
			mqlMC, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.metricsConfiguration",
				map[string]*llx.RawData{
					"__id":   llx.StringData(fmt.Sprintf("%s/metricsConfiguration/%s", a.Arn.Data, mcId)),
					"id":     llx.StringData(mcId),
					"filter": llx.MapData(filterDict, types.Any),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlMC)
		}

		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		token = resp.NextContinuationToken
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) fetchObjectLockConfig() (*s3types.ObjectLockConfiguration, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return nil, nil
	}
	a.objectLockOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.objectLockErr = err
			return
		}
		if !ok {
			return
		}
		bucketname := a.Name.Data
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3(region)
		ctx := context.Background()

		resp, err := svc.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: &bucketname,
		})
		if err != nil {
			if isNotFoundForS3(err) {
				return
			}
			a.objectLockErr = err
			return
		}
		a.objectLockConfig = resp.ObjectLockConfiguration
	})
	return a.objectLockConfig, a.objectLockErr
}

func (a *mqlAwsS3Bucket) defaultLock() (string, error) {
	config, err := a.fetchObjectLockConfig()
	if err != nil {
		return "", err
	}
	if config == nil {
		return "", nil
	}
	return string(config.ObjectLockEnabled), nil
}

func (a *mqlAwsS3Bucket) objectLockEnabled() (bool, error) {
	config, err := a.fetchObjectLockConfig()
	if err != nil {
		return false, err
	}
	if config == nil {
		return false, nil
	}
	return config.ObjectLockEnabled == "Enabled", nil
}

// defaultObjectLockRetention returns the bucket's default Object Lock
// retention rule, or nil when Object Lock is configured without one. A bucket
// can have ObjectLockEnabled without a default rule, in which case objects are
// only protected when the writer sets retention on each PUT.
func (a *mqlAwsS3Bucket) defaultObjectLockRetention() (*s3types.DefaultRetention, error) {
	config, err := a.fetchObjectLockConfig()
	if err != nil {
		return nil, err
	}
	if config == nil || config.Rule == nil {
		return nil, nil
	}
	return config.Rule.DefaultRetention, nil
}

func (a *mqlAwsS3Bucket) objectLockRetentionMode() (string, error) {
	retention, err := a.defaultObjectLockRetention()
	if err != nil {
		return "", err
	}
	if retention == nil {
		a.ObjectLockRetentionMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(retention.Mode), nil
}

func (a *mqlAwsS3Bucket) objectLockRetentionDays() (int64, error) {
	retention, err := a.defaultObjectLockRetention()
	if err != nil {
		return 0, err
	}
	if retention == nil || retention.Days == nil {
		a.ObjectLockRetentionDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*retention.Days), nil
}

func (a *mqlAwsS3Bucket) objectLockRetentionYears() (int64, error) {
	retention, err := a.defaultObjectLockRetention()
	if err != nil {
		return 0, err
	}
	if retention == nil || retention.Years == nil {
		a.ObjectLockRetentionYears.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*retention.Years), nil
}

// defaultObjectLockEventHold returns the bucket's default event hold
// duration, or nil when the default retention rule does not configure one.
func (a *mqlAwsS3Bucket) defaultObjectLockEventHold() (*s3types.EventHoldDuration, error) {
	retention, err := a.defaultObjectLockRetention()
	if err != nil {
		return nil, err
	}
	if retention == nil {
		return nil, nil
	}
	return retention.DefaultEventHold, nil
}

func (a *mqlAwsS3Bucket) objectLockEventHoldDays() (int64, error) {
	hold, err := a.defaultObjectLockEventHold()
	if err != nil {
		return 0, err
	}
	if hold == nil || hold.Days == nil {
		a.ObjectLockEventHoldDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*hold.Days), nil
}

func (a *mqlAwsS3Bucket) objectLockEventHoldYears() (int64, error) {
	hold, err := a.defaultObjectLockEventHold()
	if err != nil {
		return 0, err
	}
	if hold == nil || hold.Years == nil {
		a.ObjectLockEventHoldYears.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*hold.Years), nil
}

func (a *mqlAwsS3Bucket) website() (*mqlAwsS3BucketWebsiteConfiguration, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		a.Website.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.S3(region)
	ctx := context.Background()

	website, err := svc.GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isNotFoundForS3(err) {
			a.Website.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if website == nil {
		a.Website.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":                  llx.StringData(a.Arn.Data + "/website"),
		"errorDocument":         llx.NilData,
		"indexDocument":         llx.NilData,
		"redirectAllRequestsTo": llx.NilData,
	}
	if website.ErrorDocument != nil {
		args["errorDocument"] = llx.StringData(convert.ToValue(website.ErrorDocument.Key))
	}
	if website.IndexDocument != nil {
		args["indexDocument"] = llx.StringData(convert.ToValue(website.IndexDocument.Suffix))
	}
	if website.RedirectAllRequestsTo != nil {
		res, err := CreateResource(a.MqlRuntime, ResourceAwsS3BucketWebsiteConfigurationRedirectAllRequestsToConf, map[string]*llx.RawData{
			"__id":     llx.StringData(a.Arn.Data + "/website/redirectAllRequestsTo"),
			"hostname": llx.StringData(convert.ToValue(website.RedirectAllRequestsTo.HostName)),
			"protocol": llx.StringData(string(website.RedirectAllRequestsTo.Protocol)),
		})
		if err != nil {
			return nil, err
		}
		args["redirectAllRequestsTo"] = llx.ResourceData(res, ResourceAwsS3BucketWebsiteConfigurationRedirectAllRequestsToConf)
	}

	routingRules := []any{}
	for i, rule := range website.RoutingRules {
		ruleID := fmt.Sprintf("%s/website/routingRule/%d", a.Arn.Data, i)
		args := map[string]*llx.RawData{"__id": llx.StringData(ruleID)}
		if rule.Redirect != nil {
			redirectRes, err := CreateResource(a.MqlRuntime, ResourceAwsS3BucketWebsiteConfigurationRoutingRuleRedirectConf, map[string]*llx.RawData{
				"__id":                 llx.StringData(ruleID + "/redirect"),
				"hostname":             llx.StringData(convert.ToValue(rule.Redirect.HostName)),
				"httpRedirectCode":     llx.StringData(convert.ToValue(rule.Redirect.HttpRedirectCode)),
				"protocol":             llx.StringData(string(rule.Redirect.Protocol)),
				"replaceKeyPrefixWith": llx.StringData(convert.ToValue(rule.Redirect.ReplaceKeyPrefixWith)),
				"replaceKeyWith":       llx.StringData(convert.ToValue(rule.Redirect.ReplaceKeyWith)),
			})
			if err != nil {
				return nil, err
			}
			args["redirect"] = llx.ResourceData(redirectRes, ResourceAwsS3BucketWebsiteConfigurationRoutingRuleRedirectConf)
		}

		if rule.Condition != nil {
			condition, err := CreateResource(a.MqlRuntime, ResourceAwsS3BucketWebsiteConfigurationRoutingRuleConditionConf, map[string]*llx.RawData{
				"__id":                        llx.StringData(ruleID + "/condition"),
				"httpErrorCodeReturnedEquals": llx.StringData(convert.ToValue(rule.Condition.HttpErrorCodeReturnedEquals)),
				"keyPrefixEquals":             llx.StringData(convert.ToValue(rule.Condition.KeyPrefixEquals)),
			})
			if err != nil {
				return nil, err
			}
			args["condition"] = llx.ResourceData(condition, ResourceAwsS3BucketWebsiteConfigurationRoutingRuleConditionConf)
		}

		ruleRes, err := CreateResource(a.MqlRuntime, ResourceAwsS3BucketWebsiteConfigurationRoutingRule, args)
		if err != nil {
			return nil, err
		}

		routingRules = append(routingRules, ruleRes)
	}
	args["routingRules"] = llx.ArrayData(routingRules, types.Resource(ResourceAwsS3BucketWebsiteConfigurationRoutingRule))

	mqlWebsiteConfig, err := CreateResource(a.MqlRuntime, ResourceAwsS3BucketWebsiteConfiguration, args)
	if err != nil {
		return nil, err
	}

	return mqlWebsiteConfig.(*mqlAwsS3BucketWebsiteConfiguration), nil
}

func (a *mqlAwsS3BucketGrant) id() (string, error) {
	return a.Id.Data, nil
}

// id returns the bucket-and-index qualified cache key set at construction.
// `name` is the bucket name, which every CORS rule on a bucket shares, so it
// cannot be the key on its own.
func (a *mqlAwsS3BucketCorsrule) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsS3BucketPolicy) id() (string, error) {
	// NOTE that `policy.Id` might or might not exist and,
	// it is NOT unique for s3 bucket policies. what we need
	// here is the bucket name, which is unique globally.
	return fmt.Sprintf("aws.s3.bucket/%s/policy", a.BucketName.Data), nil
}

func (a *mqlAwsS3BucketPolicy) parsePolicyDocument() (*awspolicy.S3BucketPolicy, error) {
	return parseS3BucketPolicy(a.Document.Data)
}

func parseS3BucketPolicy(document string) (*awspolicy.S3BucketPolicy, error) {
	var policy awspolicy.S3BucketPolicy
	err := json.Unmarshal([]byte(document), &policy)
	return &policy, err
}

func (a *mqlAwsS3BucketPolicy) version() (string, error) {
	policy, err := a.parsePolicyDocument()
	if err != nil {
		return "", err
	}
	return policy.Version, nil
}

func (a *mqlAwsS3Bucket) fetchLifecycleConfig() ([]s3types.LifecycleRule, error) {
	a.lifecycleOnce.Do(func() {
		region, ok, err := a.bucketRegion()
		if err != nil {
			a.lifecycleErr = err
			return
		}
		if !ok {
			return
		}
		bucketname := a.Name.Data
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.S3(region)
		ctx := context.Background()

		resp, err := svc.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: &bucketname,
		})
		if err != nil {
			if isNotFoundForS3(err) {
				return
			}
			a.lifecycleErr = err
			return
		}
		a.lifecycleRulesData = resp.Rules
	})
	return a.lifecycleRulesData, a.lifecycleErr
}

func (a *mqlAwsS3Bucket) lifecycleRules() ([]any, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	if !a.Exists.Data {
		return nil, nil
	}
	bucketArn := a.Arn.Data

	rules, err := a.fetchLifecycleConfig()
	if err != nil {
		return nil, err
	}
	if rules == nil {
		return []any{}, nil
	}

	res := []any{}
	for i, rule := range rules {
		ruleId := ""
		if rule.ID != nil {
			ruleId = *rule.ID
		}

		resourceId := fmt.Sprintf("%s/lifecycle/%d", bucketArn, i)
		if ruleId != "" {
			resourceId = fmt.Sprintf("%s/lifecycle/%s", bucketArn, ruleId)
		}

		filterDict, err := convert.JsonToDict(rule.Filter)
		if err != nil {
			return nil, err
		}
		expirationDict, err := convert.JsonToDict(rule.Expiration)
		if err != nil {
			return nil, err
		}
		noncurrentExpDict, err := convert.JsonToDict(rule.NoncurrentVersionExpiration)
		if err != nil {
			return nil, err
		}

		transitions := []any{}
		for _, t := range rule.Transitions {
			td, err := convert.JsonToDict(t)
			if err != nil {
				return nil, err
			}
			transitions = append(transitions, td)
		}

		noncurrentTransitions := []any{}
		for _, t := range rule.NoncurrentVersionTransitions {
			td, err := convert.JsonToDict(t)
			if err != nil {
				return nil, err
			}
			noncurrentTransitions = append(noncurrentTransitions, td)
		}

		abortDays := int64(0)
		if rule.AbortIncompleteMultipartUpload != nil && rule.AbortIncompleteMultipartUpload.DaysAfterInitiation != nil {
			abortDays = int64(*rule.AbortIncompleteMultipartUpload.DaysAfterInitiation)
		}

		mqlRule, err := CreateResource(a.MqlRuntime, "aws.s3.bucket.lifecycleRule",
			map[string]*llx.RawData{
				"resourceId":                         llx.StringData(resourceId),
				"id":                                 llx.StringData(ruleId),
				"status":                             llx.StringData(string(rule.Status)),
				"filter":                             llx.DictData(filterDict),
				"transitions":                        llx.ArrayData(transitions, types.Dict),
				"expiration":                         llx.DictData(expirationDict),
				"noncurrentVersionTransitions":       llx.ArrayData(noncurrentTransitions, types.Dict),
				"noncurrentVersionExpiration":        llx.DictData(noncurrentExpDict),
				"abortIncompleteMultipartUploadDays": llx.IntData(abortDays),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAwsS3BucketLifecycleRule) id() (string, error) {
	return a.ResourceId.Data, nil
}

func (a *mqlAwsS3Bucket) notificationConfiguration() (any, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	resp, err := svc.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isNotFoundForS3(err) {
			return nil, nil
		}
		return nil, err
	}

	result := map[string]any{}
	if len(resp.LambdaFunctionConfigurations) > 0 {
		lambdas := []any{}
		for _, lc := range resp.LambdaFunctionConfigurations {
			d, _ := convert.JsonToDict(lc)
			lambdas = append(lambdas, d)
		}
		result["lambdaFunctionConfigurations"] = lambdas
	}
	if len(resp.QueueConfigurations) > 0 {
		queues := []any{}
		for _, qc := range resp.QueueConfigurations {
			d, _ := convert.JsonToDict(qc)
			queues = append(queues, d)
		}
		result["queueConfigurations"] = queues
	}
	if len(resp.TopicConfigurations) > 0 {
		topics := []any{}
		for _, tc := range resp.TopicConfigurations {
			d, _ := convert.JsonToDict(tc)
			topics = append(topics, d)
		}
		result["topicConfigurations"] = topics
	}
	if resp.EventBridgeConfiguration != nil {
		result["eventBridgeEnabled"] = true
	}

	return result, nil
}

func (a *mqlAwsS3Bucket) eventNotifications() ([]any, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	resp, err := svc.GetBucketNotificationConfiguration(ctx, &s3.GetBucketNotificationConfigurationInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isNotFoundForS3(err) {
			return nil, nil
		}
		return nil, err
	}

	build := func(notifType, id, targetArn string, events []s3types.Event) (any, error) {
		eventList := make([]any, 0, len(events))
		for _, e := range events {
			eventList = append(eventList, string(e))
		}
		return CreateResource(a.MqlRuntime, "aws.s3.bucket.eventNotification",
			map[string]*llx.RawData{
				"__id":   llx.StringData(fmt.Sprintf("%s/notification/%s/%s/%s", a.Arn.Data, notifType, id, targetArn)),
				"id":     llx.StringData(id),
				"type":   llx.StringData(notifType),
				"arn":    llx.StringData(targetArn),
				"events": llx.ArrayData(eventList, types.String),
			})
	}

	res := []any{}
	for _, lc := range resp.LambdaFunctionConfigurations {
		mql, err := build("lambda", aws.ToString(lc.Id), aws.ToString(lc.LambdaFunctionArn), lc.Events)
		if err != nil {
			return nil, err
		}
		res = append(res, mql)
	}
	for _, qc := range resp.QueueConfigurations {
		mql, err := build("queue", aws.ToString(qc.Id), aws.ToString(qc.QueueArn), qc.Events)
		if err != nil {
			return nil, err
		}
		res = append(res, mql)
	}
	for _, tc := range resp.TopicConfigurations {
		mql, err := build("topic", aws.ToString(tc.Id), aws.ToString(tc.TopicArn), tc.Events)
		if err != nil {
			return nil, err
		}
		res = append(res, mql)
	}
	return res, nil
}

func (a *mqlAwsS3BucketEventNotification) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	if a.Type.Data != "lambda" || a.Arn.Data == "" {
		a.LambdaFunction.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function",
		map[string]*llx.RawData{"arn": llx.StringData(a.Arn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsS3BucketEventNotification) queue() (*mqlAwsSqsQueue, error) {
	if a.Type.Data != "queue" || a.Arn.Data == "" {
		a.Queue.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sqs.queue",
		map[string]*llx.RawData{"arn": llx.StringData(a.Arn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSqsQueue), nil
}

func (a *mqlAwsS3BucketEventNotification) topic() (*mqlAwsSnsTopic, error) {
	if a.Type.Data != "topic" || a.Arn.Data == "" {
		a.Topic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringData(a.Arn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsS3Bucket) intelligentTieringConfigurations() ([]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	res := []any{}
	var token *string
	for {
		resp, err := svc.ListBucketIntelligentTieringConfigurations(ctx, &s3.ListBucketIntelligentTieringConfigurationsInput{
			Bucket:            &bucketName,
			ContinuationToken: token,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, c := range resp.IntelligentTieringConfigurationList {
			d, err := convert.JsonToDict(c)
			if err != nil {
				return nil, err
			}
			res = append(res, d)
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		token = resp.NextContinuationToken
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) inventoryConfigurations() ([]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	res := []any{}
	var token *string
	for {
		resp, err := svc.ListBucketInventoryConfigurations(ctx, &s3.ListBucketInventoryConfigurationsInput{
			Bucket:            &bucketName,
			ContinuationToken: token,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, c := range resp.InventoryConfigurationList {
			d, err := convert.JsonToDict(c)
			if err != nil {
				return nil, err
			}
			res = append(res, d)
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		token = resp.NextContinuationToken
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) analyticsConfigurations() ([]any, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	res := []any{}
	var token *string
	for {
		resp, err := svc.ListBucketAnalyticsConfigurations(ctx, &s3.ListBucketAnalyticsConfigurationsInput{
			Bucket:            &bucketName,
			ContinuationToken: token,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, c := range resp.AnalyticsConfigurationList {
			d, err := convert.JsonToDict(c)
			if err != nil {
				return nil, err
			}
			res = append(res, d)
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		token = resp.NextContinuationToken
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) requestPayment() (string, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	resp, err := svc.GetBucketRequestPayment(ctx, &s3.GetBucketRequestPaymentInput{Bucket: &bucketName})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "", nil
		}
		return "", err
	}
	return string(resp.Payer), nil
}

func (a *mqlAwsS3Bucket) transferAcceleration() (string, error) {
	region, ok, err := a.bucketRegion()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	bucketName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	resp, err := svc.GetBucketAccelerateConfiguration(ctx, &s3.GetBucketAccelerateConfigurationInput{Bucket: &bucketName})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return "", nil
		}
		return "", err
	}
	return string(resp.Status), nil
}

func (a *mqlAwsS3Bucket) ownershipControls() (string, error) {
	// Placeholder buckets (e.g., cross-account references) can't be queried
	region, ok, err := a.bucketRegion()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	bucketname := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3(region)
	ctx := context.Background()

	resp, err := svc.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{
		Bucket: &bucketname,
	})
	if err != nil {
		if isNotFoundForS3(err) {
			return "", nil
		}
		return "", err
	}
	if resp.OwnershipControls != nil && len(resp.OwnershipControls.Rules) > 0 {
		return string(resp.OwnershipControls.Rules[0].ObjectOwnership), nil
	}
	return "", nil
}

func isNotFoundForS3(err error) bool {
	if err == nil {
		return false
	}

	var respErr *http.ResponseError
	var notFoundErr *s3types.NotFound

	if errors.As(err, &notFoundErr) {
		return true
	} else if errors.As(err, &respErr) {
		if respErr.HTTPStatusCode() == 404 {
			return true
		}
	}

	return false
}

// isS3BucketInaccessible reports whether err from an S3 bucket data call means
// the bucket's data is unavailable from the account being scanned, rather than a
// genuine failure worth surfacing. Two cases qualify: the bucket no longer
// exists (404), or it lives in another account we have no permission to read
// (403). A CloudTrail organization trail delivers logs to a bucket owned by the
// management account, so a member-account scan hits a 403 on that bucket and
// must treat it as "no data" instead of failing the query.
func isS3BucketInaccessible(err error) bool {
	if err == nil {
		return false
	}
	if isNotFoundForS3(err) || Is400AccessDeniedError(err) {
		return true
	}
	// A forbidden response from a HEAD request carries no AccessDenied body, so
	// fall back to the raw status code.
	var respErr *http.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == 403 {
		return true
	}
	return false
}
