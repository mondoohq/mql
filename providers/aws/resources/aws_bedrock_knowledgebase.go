// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// --- Embedding model ---

// embeddingModel resolves the model used to embed documents into the vector
// store. Only vector knowledge bases embed anything; a KENDRA or SQL knowledge
// base retrieves through another service and has no embedding model.
func (a *mqlAwsBedrockKnowledgeBase) embeddingModel() (*mqlAwsBedrockFoundationModel, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	modelArn := ""
	if detail != nil && detail.KnowledgeBase != nil && detail.KnowledgeBase.KnowledgeBaseConfiguration != nil {
		if vector := detail.KnowledgeBase.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration; vector != nil {
			modelArn = convert.ToValue(vector.EmbeddingModelArn)
		}
	}
	if modelArn == "" {
		a.EmbeddingModel.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.foundationModel",
		map[string]*llx.RawData{"modelArn": llx.StringData(modelArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockFoundationModel), nil
}

// --- Vector store ---

type mqlAwsBedrockKnowledgeBaseVectorStoreInternal struct {
	cacheRdsResourceArn      string
	cacheCredentialsSecret   string
	cacheOpensearchDomainArn string
}

// vectorStore resolves the backing store named by the knowledge base's storage
// configuration. Which fields carry values depends on the store type, so the
// unset ones are left null rather than zeroed.
func (a *mqlAwsBedrockKnowledgeBase) vectorStore() (*mqlAwsBedrockKnowledgeBaseVectorStore, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.KnowledgeBase == nil || detail.KnowledgeBase.StorageConfiguration == nil {
		a.VectorStore.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	storage := detail.KnowledgeBase.StorageConfiguration

	var vectorIndexName, endpoint, databaseName, tableName string
	var opensearchServerlessCollectionArn, neptuneGraphArn string
	var s3VectorBucketArn, s3VectorIndexArn string
	var rdsResourceArn, credentialsSecretArn, opensearchDomainArn string

	switch storage.Type {
	case bedrockagenttypes.KnowledgeBaseStorageTypeOpensearchServerless:
		if c := storage.OpensearchServerlessConfiguration; c != nil {
			opensearchServerlessCollectionArn = convert.ToValue(c.CollectionArn)
			vectorIndexName = convert.ToValue(c.VectorIndexName)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeOpensearchManagedCluster:
		if c := storage.OpensearchManagedClusterConfiguration; c != nil {
			opensearchDomainArn = convert.ToValue(c.DomainArn)
			endpoint = convert.ToValue(c.DomainEndpoint)
			vectorIndexName = convert.ToValue(c.VectorIndexName)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeRds:
		if c := storage.RdsConfiguration; c != nil {
			rdsResourceArn = convert.ToValue(c.ResourceArn)
			credentialsSecretArn = convert.ToValue(c.CredentialsSecretArn)
			databaseName = convert.ToValue(c.DatabaseName)
			tableName = convert.ToValue(c.TableName)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypePinecone:
		if c := storage.PineconeConfiguration; c != nil {
			endpoint = convert.ToValue(c.ConnectionString)
			credentialsSecretArn = convert.ToValue(c.CredentialsSecretArn)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeMongoDbAtlas:
		if c := storage.MongoDbAtlasConfiguration; c != nil {
			endpoint = convert.ToValue(c.Endpoint)
			credentialsSecretArn = convert.ToValue(c.CredentialsSecretArn)
			databaseName = convert.ToValue(c.DatabaseName)
			tableName = convert.ToValue(c.CollectionName)
			vectorIndexName = convert.ToValue(c.VectorIndexName)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeRedisEnterpriseCloud:
		if c := storage.RedisEnterpriseCloudConfiguration; c != nil {
			endpoint = convert.ToValue(c.Endpoint)
			credentialsSecretArn = convert.ToValue(c.CredentialsSecretArn)
			vectorIndexName = convert.ToValue(c.VectorIndexName)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeNeptuneAnalytics:
		if c := storage.NeptuneAnalyticsConfiguration; c != nil {
			neptuneGraphArn = convert.ToValue(c.GraphArn)
		}
	case bedrockagenttypes.KnowledgeBaseStorageTypeS3Vectors:
		if c := storage.S3VectorsConfiguration; c != nil {
			s3VectorBucketArn = convert.ToValue(c.VectorBucketArn)
			s3VectorIndexArn = convert.ToValue(c.IndexArn)
			vectorIndexName = convert.ToValue(c.IndexName)
		}
	}

	res, err := CreateResource(a.MqlRuntime, "aws.bedrock.knowledgeBase.vectorStore",
		map[string]*llx.RawData{
			"__id":                              llx.StringData("aws.bedrock.knowledgeBase/" + a.Region.Data + "/" + a.Id.Data + "/vectorStore"),
			"type":                              llx.StringData(string(storage.Type)),
			"vectorIndexName":                   llx.StringData(vectorIndexName),
			"endpoint":                          llx.StringData(endpoint),
			"opensearchServerlessCollectionArn": llx.StringData(opensearchServerlessCollectionArn),
			"neptuneGraphArn":                   llx.StringData(neptuneGraphArn),
			"s3VectorBucketArn":                 llx.StringData(s3VectorBucketArn),
			"s3VectorIndexArn":                  llx.StringData(s3VectorIndexArn),
			"databaseName":                      llx.StringData(databaseName),
			"tableName":                         llx.StringData(tableName),
		})
	if err != nil {
		return nil, err
	}
	mqlStore := res.(*mqlAwsBedrockKnowledgeBaseVectorStore)
	mqlStore.cacheRdsResourceArn = rdsResourceArn
	mqlStore.cacheCredentialsSecret = credentialsSecretArn
	mqlStore.cacheOpensearchDomainArn = opensearchDomainArn
	return mqlStore, nil
}

func (a *mqlAwsBedrockKnowledgeBaseVectorStore) rdsCluster() (*mqlAwsRdsDbcluster, error) {
	if a.cacheRdsResourceArn == "" {
		a.RdsCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.rds.dbcluster",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheRdsResourceArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRdsDbcluster), nil
}

func (a *mqlAwsBedrockKnowledgeBaseVectorStore) credentialsSecret() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheCredentialsSecret == "" {
		a.CredentialsSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheCredentialsSecret)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func (a *mqlAwsBedrockKnowledgeBaseVectorStore) opensearchDomain() (*mqlAwsOpensearchDomain, error) {
	if a.cacheOpensearchDomainArn == "" {
		a.OpensearchDomain.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.opensearch.domain",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheOpensearchDomainArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsOpensearchDomain), nil
}

// --- Data sources ---

func (a *mqlAwsBedrockKnowledgeBase) dataSourceDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgent(a.cacheRegion)
	ctx := context.Background()
	kbId := a.Id.Data
	region := a.Region.Data
	res := []any{}

	paginator := bedrockagent.NewListDataSourcesPaginator(svc, &bedrockagent.ListDataSourcesInput{
		KnowledgeBaseId: &kbId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "bedrock:ListDataSources")
		}
		for _, ds := range page.DataSourceSummaries {
			dsId := convert.ToValue(ds.DataSourceId)
			mqlDS, err := CreateResource(a.MqlRuntime, "aws.bedrock.knowledgeBase.dataSource",
				map[string]*llx.RawData{
					"__id":            llx.StringData(region + "/" + kbId + "/dataSource/" + dsId),
					"id":              llx.StringData(dsId),
					"knowledgeBaseId": llx.StringData(kbId),
					"region":          llx.StringData(region),
					"name":            llx.StringDataPtr(ds.Name),
					"status":          llx.StringData(string(ds.Status)),
					"description":     llx.StringDataPtr(ds.Description),
					"updatedAt":       llx.TimeDataPtr(ds.UpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDS)
		}
	}
	return res, nil
}

type mqlAwsBedrockKnowledgeBaseDataSourceInternal struct {
	fetchLock sync.Mutex
	fetched   bool
	detail    *bedrockagent.GetDataSourceOutput
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) id() (string, error) {
	return a.Region.Data + "/" + a.KnowledgeBaseId.Data + "/dataSource/" + a.Id.Data, nil
}

// fetchDetail loads the connector configuration and deletion policy, which the
// list operation does not return.
func (a *mqlAwsBedrockKnowledgeBaseDataSource) fetchDetail() (*bedrockagenttypes.DataSource, error) {
	if !a.fetched {
		a.fetchLock.Lock()
		defer a.fetchLock.Unlock()
		if !a.fetched {
			conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
			svc := conn.BedrockAgent(a.Region.Data)
			kbId := a.KnowledgeBaseId.Data
			dsId := a.Id.Data
			detail, err := svc.GetDataSource(context.Background(), &bedrockagent.GetDataSourceInput{
				KnowledgeBaseId: &kbId,
				DataSourceId:    &dsId,
			})
			if err != nil {
				return nil, classifyAwsError(err, "bedrock:GetDataSource")
			}
			a.detail = detail
			a.fetched = true
		}
	}
	if a.detail == nil {
		return nil, nil
	}
	return a.detail.DataSource, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) compute_type() (string, error) {
	ds, err := a.fetchDetail()
	if err != nil || ds == nil || ds.DataSourceConfiguration == nil {
		return "", err
	}
	return string(ds.DataSourceConfiguration.Type), nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) dataDeletionPolicy() (string, error) {
	ds, err := a.fetchDetail()
	if err != nil || ds == nil {
		return "", err
	}
	return string(ds.DataDeletionPolicy), nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) kmsKey() (*mqlAwsKmsKey, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if ds == nil || ds.ServerSideEncryptionConfiguration == nil ||
		convert.ToValue(ds.ServerSideEncryptionConfiguration.KmsKeyArn) == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(ds.ServerSideEncryptionConfiguration.KmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) s3Bucket() (*mqlAwsS3Bucket, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	bucketArn := ""
	if s3 := dataSourceS3Config(ds); s3 != nil {
		bucketArn = convert.ToValue(s3.BucketArn)
	}
	return s3BucketRefFromArn(a.MqlRuntime, bucketArn, &a.S3Bucket)
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) s3BucketOwnerAccountId() (string, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if s3 := dataSourceS3Config(ds); s3 != nil {
		return convert.ToValue(s3.BucketOwnerAccountId), nil
	}
	return "", nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) s3InclusionPrefixes() ([]any, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if s3 := dataSourceS3Config(ds); s3 != nil {
		for _, p := range s3.InclusionPrefixes {
			res = append(res, p)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) webCrawlerSeedUrls() ([]any, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	web := dataSourceWebConfig(ds)
	if web == nil || web.SourceConfiguration == nil || web.SourceConfiguration.UrlConfiguration == nil {
		return res, nil
	}
	for _, seed := range web.SourceConfiguration.UrlConfiguration.SeedUrls {
		if url := convert.ToValue(seed.Url); url != "" {
			res = append(res, url)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) webCrawlerScope() (string, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	web := dataSourceWebConfig(ds)
	if web == nil || web.CrawlerConfiguration == nil {
		return "", nil
	}
	return string(web.CrawlerConfiguration.Scope), nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) webCrawlerUserAgent() (string, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	web := dataSourceWebConfig(ds)
	if web == nil || web.CrawlerConfiguration == nil {
		return "", nil
	}
	// UserAgentHeader is the full header Bedrock sends; UserAgent is the suffix
	// appended to the Bedrock default. Report whichever the data source set.
	if header := convert.ToValue(web.CrawlerConfiguration.UserAgentHeader); header != "" {
		return header, nil
	}
	return convert.ToValue(web.CrawlerConfiguration.UserAgent), nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) configuration() (any, error) {
	ds, err := a.fetchDetail()
	if err != nil || ds == nil {
		return nil, err
	}
	result, _ := convert.JsonToDict(ds.DataSourceConfiguration)
	return result, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) vectorIngestionConfiguration() (any, error) {
	ds, err := a.fetchDetail()
	if err != nil || ds == nil {
		return nil, err
	}
	result, _ := convert.JsonToDict(ds.VectorIngestionConfiguration)
	return result, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) failureReasons() ([]any, error) {
	ds, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if ds == nil {
		return res, nil
	}
	for _, reason := range ds.FailureReasons {
		res = append(res, reason)
	}
	return res, nil
}

func (a *mqlAwsBedrockKnowledgeBaseDataSource) createdAt() (*time.Time, error) {
	ds, err := a.fetchDetail()
	if err != nil || ds == nil {
		return nil, err
	}
	return ds.CreatedAt, nil
}

// dataSourceS3Config returns the S3 connector configuration, or nil when the
// data source reads through a different connector.
func dataSourceS3Config(ds *bedrockagenttypes.DataSource) *bedrockagenttypes.S3DataSourceConfiguration {
	if ds == nil || ds.DataSourceConfiguration == nil {
		return nil
	}
	return ds.DataSourceConfiguration.S3Configuration
}

// dataSourceWebConfig returns the web-crawler configuration, or nil when the
// data source reads through a different connector.
func dataSourceWebConfig(ds *bedrockagenttypes.DataSource) *bedrockagenttypes.WebDataSourceConfiguration {
	if ds == nil || ds.DataSourceConfiguration == nil {
		return nil
	}
	return ds.DataSourceConfiguration.WebConfiguration
}
