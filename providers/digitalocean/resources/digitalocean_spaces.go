// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// knownSpacesRegions enumerates the DigitalOcean regions that host
// Spaces. The list grows when DO opens new regions — keep it in sync
// with https://docs.digitalocean.com/platform/regional-availability/
var knownSpacesRegions = []string{
	"nyc3", "sfo2", "sfo3", "ams3", "sgp1", "fra1", "syd1", "tor1", "blr1",
}

// regionConcurrency caps the parallel ListBuckets sweep across Spaces
// regions. Most accounts use a handful of regions, so a small number
// is fine.
const regionConcurrency = 5

// bucketConcurrency caps the parallel per-bucket detail fan-out.
// Each bucket triggers up to 7 sequential S3-compatible API calls
// (access block, ACL, encryption, versioning, policy, CORS,
// lifecycle); running them across multiple buckets in parallel is
// the main win.
const bucketConcurrency = 8

// mqlDigitaloceanSpacesBucketInternal carries whether the bucket policy was
// actually read. The policy field is null both when the bucket has no policy
// and when the call to fetch it never succeeded, and only the first of those
// lets hasWildcardPolicy answer false.
type mqlDigitaloceanSpacesBucketInternal struct {
	policyRead bool
}

func (r *mqlDigitaloceanSpacesBucket) id() (string, error) {
	return "digitalocean.spacesBucket/" + r.Region.Data + "/" + r.Name.Data, nil
}

// initDigitaloceanSpacesBucket resolves a single bucket — either from
// explicit name/region args (digitalocean.spacesBucket(name: "...",
// region: "...")) or from a connected digitalocean-spaces-bucket asset,
// whose name and region the discovery step stamped on the connection
// options. A bucket is addressed by (region, name) on the S3-compatible
// API, so both are required.
func initDigitaloceanSpacesBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)

	name := ""
	if a, ok := args["name"]; ok {
		name, _ = a.Value.(string)
	}
	region := ""
	if a, ok := args["region"]; ok {
		region, _ = a.Value.(string)
	}
	if name == "" {
		name = conn.Conf.Options[connection.OptionSpacesBucket]
	}
	if region == "" {
		region = conn.Conf.Options[connection.OptionSpacesRegion]
	}
	if name == "" || region == "" {
		return nil, nil, errors.New("digitalocean.spacesBucket requires name and region (or a connected digitalocean-spaces-bucket asset)")
	}
	if _, _, ok := conn.SpacesCredentials(); !ok {
		return nil, nil, errors.New("DIGITALOCEAN_SPACES_KEY and DIGITALOCEAN_SPACES_SECRET must be set to audit Spaces buckets")
	}

	client, err := conn.SpacesClient(region)
	if err != nil {
		return nil, nil, err
	}

	// Look up the bucket summary in its region so createdAt is
	// preserved; fall back to a name-only summary if the listing is
	// unavailable.
	summary := s3types.Bucket{Name: aws.String(name)}
	if out, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{}); err == nil {
		for _, b := range out.Buckets {
			if aws.ToString(b.Name) == name {
				summary = b
				break
			}
		}
	}

	res, err := newSpacesBucket(runtime, client, region, summary)
	if err != nil {
		return nil, nil, err
	}
	return nil, res.(plugin.Resource), nil
}

// bucketRef carries the (region, client, summary) tuple from the
// per-region ListBuckets pass into the per-bucket detail-fetch pass.
type bucketRef struct {
	region string
	client *s3.Client
	b      s3types.Bucket
}

func (r *mqlDigitalocean) spacesBuckets() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	if _, _, ok := conn.SpacesCredentials(); !ok {
		// Spaces credentials are optional — return an empty list so
		// the rest of the provider stays usable without them.
		return []interface{}{}, nil
	}

	regions := []string{conn.SpacesRegion()}
	if regions[0] == "" {
		regions = knownSpacesRegions
	}

	refs, err := listSpacesBucketRefs(conn, regions)
	if err != nil {
		return nil, err
	}
	return fetchSpacesBucketDetails(r, refs)
}

// listSpacesBucketRefs lists buckets across the requested regions in
// parallel and returns the merged refs slice. ListBuckets is
// region-scoped on DigitalOcean Spaces (each region's endpoint
// returns only that region's buckets), so the refs are disjoint.
func listSpacesBucketRefs(conn *connection.DigitaloceanConnection, regions []string) ([]bucketRef, error) {
	ctx := context.Background()
	var (
		mu   sync.Mutex
		refs []bucketRef
	)
	jobs := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		// Filtering here rather than per bucket skips the ListBuckets call for
		// regions nothing can match. Buckets carry no tags, so an include-tag
		// filter rules out every region.
		if skipSpacesBucket(conn.Filters.General, region) {
			continue
		}
		jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
			client, err := conn.SpacesClient(region)
			if err != nil {
				return nil, err
			}
			out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
			if err != nil {
				return nil, err
			}
			local := make([]bucketRef, 0, len(out.Buckets))
			for _, b := range out.Buckets {
				local = append(local, bucketRef{region: region, client: client, b: b})
			}
			mu.Lock()
			refs = append(refs, local...)
			mu.Unlock()
			return nil, nil
		}))
	}
	pool := jobpool.CreatePool(jobs, regionConcurrency)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	return refs, nil
}

// fetchSpacesBucketDetails runs newSpacesBucket per ref in parallel.
// Results are written into an index-aligned slice so the final order
// is stable, then compacted to drop any nil entries — currently
// newSpacesBucket never returns (nil, nil), but the slot stays nil
// if a future variant ever filters a bucket without erroring, and we
// don't want nil leaking into the user-facing list.
func fetchSpacesBucketDetails(r *mqlDigitalocean, refs []bucketRef) ([]interface{}, error) {
	results := make([]interface{}, len(refs))
	jobs := make([]*jobpool.Job, 0, len(refs))
	for i, ref := range refs {
		idx, ref := i, ref
		jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
			res, err := newSpacesBucket(r.MqlRuntime, ref.client, ref.region, ref.b)
			if err != nil {
				return nil, err
			}
			results[idx] = res
			return nil, nil
		}))
	}
	pool := jobpool.CreatePool(jobs, bucketConcurrency)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	out := make([]interface{}, 0, len(results))
	for _, res := range results {
		if res != nil {
			out = append(out, res)
		}
	}
	return out, nil
}

// newSpacesBucket builds a single bucket resource by fanning out
// to the access/encryption/versioning/policy/cors/lifecycle calls.
// Each call tolerates the "not configured" S3 error codes so an
// un-customized bucket still produces a resource with sensible nil
// defaults.
func newSpacesBucket(runtime *plugin.Runtime, client *s3.Client, region string, b s3types.Bucket) (interface{}, error) {
	ctx := context.Background()
	name := aws.ToString(b.Name)

	var createdAt *time.Time
	if b.CreationDate != nil {
		t := *b.CreationDate
		createdAt = &t
	}

	var pabCfg *s3types.PublicAccessBlockConfiguration
	pab, pabErr := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(name)})
	if pab != nil {
		pabCfg = pab.PublicAccessBlockConfiguration
	}
	publicAccessBlocked, err := publicAccessBlockedValue(pabCfg, pabErr)
	if err != nil {
		return nil, err
	}

	// Each block below keeps three outcomes apart, the same way
	// publicAccessBlockedValue already does for the block-public-access call:
	//
	//   read succeeded            -> report what it said
	//   read succeeded, unset     -> report the absence, which is a real answer
	//   read did not happen       -> report null
	//
	// The third case is the one worth being careful about. Spaces implements a
	// subset of S3 and answers 501 on the calls it does not have, and a token
	// may simply not be allowed to read a bucket. Letting the zero value stand
	// there turns "nothing was read" into "nothing is configured": a bucket
	// whose ACL could not be read would report no public grants, and isPublic
	// would clear it on the strength of a read that never happened.

	var (
		publicReadAcl        *bool
		publicWriteAcl       *bool
		authenticatedReadAcl *bool
		aclGrants            []interface{} // nil means the ACL was not read
	)
	if acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(name)}); err == nil {
		grants := []interface{}{}
		publicRead, publicWrite, authenticatedRead := false, false, false
		for _, g := range acl.Grants {
			perm := string(g.Permission)
			grantee := g.Grantee
			var uri, ty, display string
			if grantee != nil {
				uri = aws.ToString(grantee.URI)
				ty = string(grantee.Type)
				display = aws.ToString(grantee.DisplayName)
			}
			grants = append(grants, map[string]interface{}{
				"granteeType":        ty,
				"granteeUri":         uri,
				"granteeDisplayName": display,
				"permission":         perm,
			})
			if uri == "http://acs.amazonaws.com/groups/global/AllUsers" {
				if perm == "READ" || perm == "FULL_CONTROL" {
					publicRead = true
				}
				if perm == "WRITE" || perm == "FULL_CONTROL" {
					publicWrite = true
				}
			}
			if uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				if perm == "READ" || perm == "FULL_CONTROL" {
					authenticatedRead = true
				}
			}
		}
		aclGrants = grants
		publicReadAcl, publicWriteAcl, authenticatedReadAcl = &publicRead, &publicWrite, &authenticatedRead
	} else if isAccessDenied(err) || isUnsupportedOperation(err) {
		log.Warn().Err(err).Str("bucket", name).
			Msg("digitalocean> bucket ACL could not be read; its grants and public-ACL flags are reported as null")
	} else {
		return nil, err
	}

	var (
		encryptionEnabled   *bool
		encryptionAlgorithm *string
		encryptionKmsKeyId  *string
	)
	if enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(name)}); err == nil {
		enabled, algorithm, kmsKeyId := false, "", ""
		if enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0 {
			rule := enc.ServerSideEncryptionConfiguration.Rules[0]
			if rule.ApplyServerSideEncryptionByDefault != nil {
				enabled = true
				algorithm = string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
				kmsKeyId = aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
			}
		}
		encryptionEnabled, encryptionAlgorithm, encryptionKmsKeyId = &enabled, &algorithm, &kmsKeyId
	} else if isNoSuchConfiguration(err) {
		// The service answered, and the answer is that nothing is configured.
		// Default encryption really is off.
		notEncrypted, none := false, ""
		encryptionEnabled, encryptionAlgorithm, encryptionKmsKeyId = &notEncrypted, &none, &none
	} else if isUnsupportedOperation(err) {
		log.Warn().Err(err).Str("bucket", name).
			Msg("digitalocean> bucket encryption could not be read; it is reported as null")
	} else {
		return nil, err
	}

	var (
		versioningStatus *string
		mfaDeleteEnabled *bool
	)
	if v, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(name)}); err == nil {
		status := string(v.Status)
		mfaDelete := v.MFADelete == s3types.MFADeleteStatusEnabled
		versioningStatus, mfaDeleteEnabled = &status, &mfaDelete
	} else if isAccessDenied(err) || isUnsupportedOperation(err) {
		log.Warn().Err(err).Str("bucket", name).
			Msg("digitalocean> bucket versioning could not be read; it is reported as null")
	} else {
		return nil, err
	}

	// policyRead separates "this bucket has no policy" from "the policy was
	// never read". Both leave policy null, but only the first lets
	// hasWildcardPolicy answer false.
	var policyDict interface{}
	policyRead := false
	if p, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(name)}); err == nil {
		policyRead = true
		raw := aws.ToString(p.Policy)
		if raw != "" {
			var parsed interface{}
			if jerr := json.Unmarshal([]byte(raw), &parsed); jerr == nil {
				policyDict = parsed
			} else {
				policyDict = raw
			}
		}
	} else if isNoSuchConfiguration(err) {
		policyRead = true
	} else if isUnsupportedOperation(err) {
		log.Warn().Err(err).Str("bucket", name).
			Msg("digitalocean> bucket policy could not be read; it is reported as null")
	} else {
		return nil, err
	}

	var corsRules []interface{} // nil means the CORS configuration was not read
	if c, err := client.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: aws.String(name)}); err == nil {
		corsRules = []interface{}{}
		for _, rule := range c.CORSRules {
			corsRules = append(corsRules, spacesCorsRuleDict(rule))
		}
	} else if isNoSuchConfiguration(err) {
		corsRules = []interface{}{}
	} else if !isUnsupportedOperation(err) {
		return nil, err
	}

	var lifecycleRules []interface{} // nil means the lifecycle rules were not read
	if l, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(name)}); err == nil {
		lifecycleRules = []interface{}{}
		for _, rule := range l.Rules {
			lifecycleRules = append(lifecycleRules, spacesLifecycleRuleDict(rule))
		}
	} else if isNoSuchConfiguration(err) {
		lifecycleRules = []interface{}{}
	} else if !isUnsupportedOperation(err) {
		return nil, err
	}

	res, err := CreateResource(runtime, "digitalocean.spacesBucket", map[string]*llx.RawData{
		"name":                 llx.StringData(name),
		"region":               llx.StringData(region),
		"createdAt":            llx.TimeDataPtr(createdAt),
		"publicAccessBlocked":  llx.BoolDataPtr(publicAccessBlocked),
		"publicReadAcl":        llx.BoolDataPtr(publicReadAcl),
		"publicWriteAcl":       llx.BoolDataPtr(publicWriteAcl),
		"authenticatedReadAcl": llx.BoolDataPtr(authenticatedReadAcl),
		"aclGrants":            dictListData(aclGrants),
		"encryptionEnabled":    llx.BoolDataPtr(encryptionEnabled),
		"encryptionAlgorithm":  llx.StringDataPtr(encryptionAlgorithm),
		"encryptionKmsKeyId":   llx.StringDataPtr(encryptionKmsKeyId),
		"versioningStatus":     llx.StringDataPtr(versioningStatus),
		"mfaDeleteEnabled":     llx.BoolDataPtr(mfaDeleteEnabled),
		"policy":               llx.DictData(policyDict),
		"corsRules":            dictListData(corsRules),
		"lifecycleRules":       dictListData(lifecycleRules),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlDigitaloceanSpacesBucket).policyRead = policyRead
	return res, nil
}

// dictListData renders a dict list that was never read as null rather than as
// an empty list, so "nothing came back" cannot be mistaken for "there is
// nothing".
func dictListData(v []interface{}) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.ArrayData(v, types.Dict)
}

// spacesCorsRuleDict builds the dict for one CORS rule. dict values must
// be JSON-native, so the SDK's []string members are widened to []any and
// the *int32 max-age is dereferenced to int64 (only when the API set it).
func spacesCorsRuleDict(rule s3types.CORSRule) map[string]interface{} {
	entry := map[string]interface{}{
		"id":             aws.ToString(rule.ID),
		"allowedHeaders": toStringSlice(rule.AllowedHeaders),
		"allowedMethods": toStringSlice(rule.AllowedMethods),
		"allowedOrigins": toStringSlice(rule.AllowedOrigins),
		"exposeHeaders":  toStringSlice(rule.ExposeHeaders),
	}
	if rule.MaxAgeSeconds != nil {
		entry["maxAgeSeconds"] = int64(*rule.MaxAgeSeconds)
	}
	return entry
}

// spacesLifecycleRuleDict builds the dict for one lifecycle rule. The SDK
// models the day-counts as *int32; dict values must be JSON-native int64,
// so each is dereferenced only when the API actually set it.
func spacesLifecycleRuleDict(rule s3types.LifecycleRule) map[string]interface{} {
	entry := map[string]interface{}{
		"id":     aws.ToString(rule.ID),
		"status": string(rule.Status),
	}
	if f := rule.Filter; f != nil {
		entry["prefix"] = aws.ToString(f.Prefix)
	}
	if rule.Expiration != nil && rule.Expiration.Days != nil {
		entry["expirationDays"] = int64(*rule.Expiration.Days)
	}
	if rule.NoncurrentVersionExpiration != nil && rule.NoncurrentVersionExpiration.NoncurrentDays != nil {
		entry["noncurrentVersionExpirationDays"] = int64(*rule.NoncurrentVersionExpiration.NoncurrentDays)
	}
	if rule.AbortIncompleteMultipartUpload != nil && rule.AbortIncompleteMultipartUpload.DaysAfterInitiation != nil {
		entry["abortIncompleteMultipartUploadDays"] = int64(*rule.AbortIncompleteMultipartUpload.DaysAfterInitiation)
	}
	return entry
}

// noSuchConfigurationCodes are the S3 error codes returned for
// well-formed buckets that have never been configured for a given
// property (no policy, no encryption, no CORS, etc.). Treat as
// soft-absent.
var noSuchConfigurationCodes = []string{
	"NoSuchBucketPolicy",
	"NoSuchPublicAccessBlockConfiguration",
	"ServerSideEncryptionConfigurationNotFoundError",
	"NoSuchCORSConfiguration",
	"NoSuchLifecycleConfiguration",
}

// isNoSuchConfiguration returns true when the S3 error code indicates
// the bucket has never been configured for that property. Both the
// typed APIError code and the raw error string are checked because
// Spaces sometimes surfaces the code only in the body text.
func isNoSuchConfiguration(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		for _, code := range noSuchConfigurationCodes {
			if ae.ErrorCode() == code {
				return true
			}
		}
	}
	msg := err.Error()
	for _, code := range noSuchConfigurationCodes {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// publicAccessBlockedValue folds a GetPublicAccessBlock answer into the
// bucket's publicAccessBlocked field, keeping three outcomes apart.
//
// A service that does not implement the call has no such control, so there is
// nothing to report and the field is null. DigitalOcean Spaces answers this
// way on every account: reporting false there would state as fact that public
// access is not blocked, when in truth nothing was ever read and no setting
// exists to read. A bucket with no configuration, on a service that does
// implement the call, is a real answer and means nothing is blocked. Any
// other failure is a failure and must not become a posture claim.
func publicAccessBlockedValue(cfg *s3types.PublicAccessBlockConfiguration, err error) (*bool, error) {
	if err != nil {
		if isUnsupportedOperation(err) {
			return nil, nil
		}
		if !isNoSuchConfiguration(err) {
			return nil, err
		}
		notBlocked := false
		return &notBlocked, nil
	}
	blocked := cfg != nil &&
		aws.ToBool(cfg.BlockPublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) &&
		aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.RestrictPublicBuckets)
	return &blocked, nil
}

// isUnsupportedOperation returns true when the S3 API answers that it does
// not implement the operation at all. Spaces implements a subset of the S3
// API, so calls that exist only on AWS (GetPublicAccessBlock, for one) come
// back 501 NotImplemented on every account. That describes the service
// rather than the bucket, so the caller keeps its default and carries on
// instead of failing the whole listing.
func isUnsupportedOperation(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NotImplemented", "MethodNotAllowed":
			return true
		}
	}
	return strings.Contains(err.Error(), "NotImplemented")
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == "AccessDenied"
	}
	return strings.Contains(err.Error(), "AccessDenied")
}
