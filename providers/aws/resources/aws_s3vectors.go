// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3vectors"
	s3vtypes "github.com/aws/aws-sdk-go-v2/service/s3vectors/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsS3vectors) id() (string, error) {
	return ResourceAwsS3vectors, nil
}

func (a *mqlAwsS3vectors) vectorBuckets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	tasks := make([]*jobpool.Job, 0, len(regions))
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			res, err := a.listVectorBuckets(conn, region)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS S3 Vectors API")
					return []any{}, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("s3 vectors is not available in region")
					return []any{}, nil
				}
				return nil, err
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	pool := jobpool.CreatePool(tasks, 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	res := []any{}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsS3vectors) listVectorBuckets(conn *connection.AwsConnection, region string) ([]any, error) {
	svc := conn.S3Vectors(region)
	ctx := context.Background()
	res := []any{}
	paginator := s3vectors.NewListVectorBucketsPaginator(svc, &s3vectors.ListVectorBucketsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range page.VectorBuckets {
			mqlBucket, err := CreateResource(a.MqlRuntime, ResourceAwsS3vectorsVectorBucket, map[string]*llx.RawData{
				"__id":      llx.StringDataPtr(b.VectorBucketArn),
				"arn":       llx.StringDataPtr(b.VectorBucketArn),
				"name":      llx.StringDataPtr(b.VectorBucketName),
				"region":    llx.StringData(region),
				"createdAt": llx.TimeDataPtr(b.CreationTime),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBucket)
		}
	}
	return res, nil
}

// --- Vector bucket ---

type mqlAwsS3vectorsVectorBucketInternal struct {
	lazyTags
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *s3vtypes.VectorBucket

	policyLock       sync.Mutex
	policyFetched    atomic.Bool
	policyText       string
	policyAbsent     bool
	policyUnreadable bool
	policyErr        error
}

func (a *mqlAwsS3vectorsVectorBucket) fetchDetail() (*s3vtypes.VectorBucket, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	bucketArn := a.Arn.Data
	out, err := conn.S3Vectors(a.Region.Data).GetVectorBucket(context.Background(), &s3vectors.GetVectorBucketInput{
		VectorBucketArn: &bucketArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("s3vectors:GetVectorBucket"))
		}
		return nil, err
	}
	a.detail = out.VectorBucket
	a.fetched.Store(true)
	return a.detail, nil
}

// s3VectorsEncryption returns the SSE type and the customer-managed key ARN of
// an encryption configuration. The key ARN is empty for S3 managed keys.
func s3VectorsEncryption(cfg *s3vtypes.EncryptionConfiguration) (sseType string, kmsKeyArn string) {
	if cfg == nil {
		return "", ""
	}
	if cfg.SseType == s3vtypes.SseTypeAwsKms {
		return string(cfg.SseType), convert.ToValue(cfg.KmsKeyArn)
	}
	return string(cfg.SseType), ""
}

func s3VectorsKmsKey(runtime *plugin.Runtime, keyArn string, field *plugin.TValue[*mqlAwsKmsKey]) (*mqlAwsKmsKey, error) {
	if keyArn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAwsKmsKey, map[string]*llx.RawData{"arn": llx.StringData(keyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsS3vectorsVectorBucket) sseType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	sse := ""
	if detail != nil {
		sse, _ = s3VectorsEncryption(detail.EncryptionConfiguration)
	}
	if sse == "" {
		a.SseType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return sse, nil
}

func (a *mqlAwsS3vectorsVectorBucket) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	keyArn := ""
	if detail != nil {
		_, keyArn = s3VectorsEncryption(detail.EncryptionConfiguration)
	}
	return s3VectorsKmsKey(a.MqlRuntime, keyArn, &a.KmsKey)
}

func (a *mqlAwsS3vectorsVectorBucket) loadPolicy() error {
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
	bucketArn := a.Arn.Data
	out, err := conn.S3Vectors(a.Region.Data).GetVectorBucketPolicy(context.Background(), &s3vectors.GetVectorBucketPolicyInput{
		VectorBucketArn: &bucketArn,
	})
	if err != nil {
		switch {
		case isResourceNotFoundError(err):
			a.policyAbsent = true
		case Is400AccessDeniedError(err):
			if plugin.StructuredErrors() {
				a.policyErr = llx.Forbidden(err, llx.WithPermissions("s3vectors:GetVectorBucketPolicy"))
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

func (a *mqlAwsS3vectorsVectorBucket) policy() (string, error) {
	if err := a.loadPolicy(); err != nil {
		return "", err
	}
	if a.policyAbsent || a.policyUnreadable {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return a.policyText, nil
}

func (a *mqlAwsS3vectorsVectorBucket) policyStatements() ([]any, error) {
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
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data, a.policyText)
}

func (a *mqlAwsS3vectorsVectorBucket) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

func (a *mqlAwsS3vectorsVectorBucket) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		bucketArn := a.Arn.Data
		out, err := conn.S3Vectors(a.Region.Data).ListTagsForResource(context.Background(), &s3vectors.ListTagsForResourceInput{
			ResourceArn: &bucketArn,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("s3vectors:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return toInterfaceMap(out.Tags), nil
	})
}

func (a *mqlAwsS3vectorsVectorBucket) indexes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.S3Vectors(a.Region.Data)
	bucketArn := a.Arn.Data
	region := a.Region.Data
	res := []any{}
	paginator := s3vectors.NewListIndexesPaginator(svc, &s3vectors.ListIndexesInput{VectorBucketArn: &bucketArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return res, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("s3vectors:ListIndexes"))
			}
			return nil, err
		}
		for _, idx := range page.Indexes {
			mqlIdx, err := CreateResource(a.MqlRuntime, ResourceAwsS3vectorsIndex, map[string]*llx.RawData{
				"__id":      llx.StringDataPtr(idx.IndexArn),
				"arn":       llx.StringDataPtr(idx.IndexArn),
				"name":      llx.StringDataPtr(idx.IndexName),
				"region":    llx.StringData(region),
				"createdAt": llx.TimeDataPtr(idx.CreationTime),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIdx)
		}
	}
	return res, nil
}

// --- Vector index ---

type mqlAwsS3vectorsIndexInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *s3vtypes.Index
}

func (a *mqlAwsS3vectorsIndex) vectorBucket() (*mqlAwsS3vectorsVectorBucket, error) {
	bucketArn := s3VectorBucketArnOfIndex(a.Arn.Data)
	if bucketArn == "" {
		a.VectorBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	b, err := findS3VectorBucket(a.MqlRuntime, bucketArn)
	if err != nil {
		return nil, err
	}
	if b == nil {
		a.VectorBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return b, nil
}

func (a *mqlAwsS3vectorsIndex) fetchDetail() (*s3vtypes.Index, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	indexArn := a.Arn.Data
	out, err := conn.S3Vectors(a.Region.Data).GetIndex(context.Background(), &s3vectors.GetIndexInput{IndexArn: &indexArn})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("s3vectors:GetIndex"))
		}
		return nil, err
	}
	a.detail = out.Index
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsS3vectorsIndex) dimension() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.Dimension == nil {
		a.Dimension.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*detail.Dimension), nil
}

func (a *mqlAwsS3vectorsIndex) distanceMetric() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.DistanceMetric == "" {
		a.DistanceMetric.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.DistanceMetric), nil
}

func (a *mqlAwsS3vectorsIndex) dataType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.DataType == "" {
		a.DataType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.DataType), nil
}

func (a *mqlAwsS3vectorsIndex) nonFilterableMetadataKeys() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.NonFilterableMetadataKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if detail.MetadataConfiguration == nil {
		return []any{}, nil
	}
	return convert.SliceAnyToInterface(detail.MetadataConfiguration.NonFilterableMetadataKeys), nil
}

func (a *mqlAwsS3vectorsIndex) sseType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	sse := ""
	if detail != nil {
		sse, _ = s3VectorsEncryption(detail.EncryptionConfiguration)
	}
	if sse == "" {
		a.SseType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return sse, nil
}

func (a *mqlAwsS3vectorsIndex) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	keyArn := ""
	if detail != nil {
		_, keyArn = s3VectorsEncryption(detail.EncryptionConfiguration)
	}
	return s3VectorsKmsKey(a.MqlRuntime, keyArn, &a.KmsKey)
}

// --- Knowledge base vector store references ---

// s3VectorBucketArnOfIndex derives the vector bucket ARN from an index ARN,
// arn:aws:s3vectors:<region>:<account>:bucket/<bucket>/index/<index>.
func s3VectorBucketArnOfIndex(indexArn string) string {
	parsed, err := arn.Parse(indexArn)
	if err != nil {
		return ""
	}
	bucket, _, ok := strings.Cut(parsed.Resource, "/index/")
	if !ok || !strings.HasPrefix(bucket, "bucket/") {
		return ""
	}
	parsed.Resource = bucket
	return parsed.String()
}

func s3VectorsRoot(runtime *plugin.Runtime) (*mqlAwsS3vectors, error) {
	obj, err := CreateResource(runtime, ResourceAwsS3vectors, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsS3vectors), nil
}

func findS3VectorBucket(runtime *plugin.Runtime, bucketArn string) (*mqlAwsS3vectorsVectorBucket, error) {
	root, err := s3VectorsRoot(runtime)
	if err != nil {
		return nil, err
	}
	buckets := root.GetVectorBuckets()
	if buckets.Error != nil {
		return nil, buckets.Error
	}
	for _, raw := range buckets.Data {
		if b, ok := raw.(*mqlAwsS3vectorsVectorBucket); ok && b.Arn.Data == bucketArn {
			return b, nil
		}
	}
	return nil, nil
}

func (a *mqlAwsBedrockKnowledgeBaseVectorStore) s3VectorBucket() (*mqlAwsS3vectorsVectorBucket, error) {
	bucketArn := a.S3VectorBucketArn.Data
	if bucketArn == "" {
		bucketArn = s3VectorBucketArnOfIndex(a.S3VectorIndexArn.Data)
	}
	if bucketArn == "" {
		a.S3VectorBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	b, err := findS3VectorBucket(a.MqlRuntime, bucketArn)
	if err != nil {
		return nil, err
	}
	if b == nil {
		a.S3VectorBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return b, nil
}

func (a *mqlAwsBedrockKnowledgeBaseVectorStore) s3VectorIndex() (*mqlAwsS3vectorsIndex, error) {
	indexArn := a.S3VectorIndexArn.Data
	if indexArn == "" && a.Type.Data != "S3_VECTORS" {
		a.S3VectorIndex.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	bucket, err := a.s3VectorBucket()
	if err != nil {
		return nil, err
	}
	if bucket == nil {
		a.S3VectorIndex.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	indexes := bucket.GetIndexes()
	if indexes.Error != nil {
		return nil, indexes.Error
	}
	for _, raw := range indexes.Data {
		idx, ok := raw.(*mqlAwsS3vectorsIndex)
		if !ok {
			continue
		}
		if (indexArn != "" && idx.Arn.Data == indexArn) || (indexArn == "" && idx.Name.Data == a.VectorIndexName.Data) {
			return idx, nil
		}
	}
	a.S3VectorIndex.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
