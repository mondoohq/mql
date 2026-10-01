// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// lastIndexingJobDict flattens a godo *LastIndexingJob into a dict for
// embedding on knowledge bases and data sources.
func lastIndexingJobDict(j *godo.LastIndexingJob) map[string]interface{} {
	if j == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{
		"uuid":                 j.Uuid,
		"knowledgeBaseUuid":    j.KnowledgeBaseUuid,
		"phase":                j.Phase,
		"status":               j.Status,
		"tokens":               int64(j.Tokens),
		"completedDatasources": int64(j.CompletedDatasources),
		"totalDatasources":     int64(j.TotalDatasources),
		"totalItemsIndexed":    j.TotalItemsIndexed,
		"totalItemsFailed":     j.TotalItemsFailed,
		"totalItemsSkipped":    j.TotalItemsSkipped,
	}
	if t := gradientaiTime(j.StartedAt); t != nil {
		out["startedAt"] = t.String()
	}
	if t := gradientaiTime(j.FinishedAt); t != nil {
		out["finishedAt"] = t.String()
	}
	return out
}

// ----- Knowledge bases -----

func (r *mqlDigitaloceanGradientai) knowledgeBases() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	kbs, err := paginate(context.Background(), client.AgentPlatform.ListKnowledgeBases)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(kbs))
	for i := range kbs {
		res, err := newMqlGradientaiKnowledgeBase(r.MqlRuntime, &kbs[i])
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

func newMqlGradientaiKnowledgeBase(runtime *plugin.Runtime, kb *godo.KnowledgeBase) (*mqlDigitaloceanGradientaiKnowledgeBase, error) {
	if kb == nil {
		return nil, nil
	}
	tags := make([]interface{}, len(kb.Tags))
	for i, t := range kb.Tags {
		tags[i] = t
	}
	res, err := CreateResource(runtime, "digitalocean.gradientai.knowledgeBase", map[string]*llx.RawData{
		"__id":               llx.StringData(kb.Uuid),
		"uuid":               llx.StringData(kb.Uuid),
		"name":               llx.StringData(kb.Name),
		"region":             llx.StringData(kb.Region),
		"isPublic":           llx.BoolData(kb.IsPublic),
		"embeddingModelUuid": llx.StringData(kb.EmbeddingModelUuid),
		"databaseId":         llx.StringData(kb.DatabaseId),
		"projectId":          llx.StringData(kb.ProjectId),
		"tags":               llx.ArrayData(tags, types.String),
		"lastIndexingJob":    llx.DictData(lastIndexingJobDict(kb.LastIndexingJob)),
		"addedToAgentAt":     llx.TimeDataPtr(gradientaiTime(kb.AddedToAgentAt)),
		"createdAt":          llx.TimeDataPtr(gradientaiTime(kb.CreatedAt)),
		"updatedAt":          llx.TimeDataPtr(gradientaiTime(kb.UpdatedAt)),
		"isDeleted":          llx.BoolData(kb.IsDeleted),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanGradientaiKnowledgeBase), nil
}

func (r *mqlDigitaloceanGradientaiKnowledgeBase) embeddingModel() (*mqlDigitaloceanGradientaiModel, error) {
	if r.EmbeddingModelUuid.Data == "" {
		r.EmbeddingModel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentGradientai(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	model, err := parent.modelByUUID(r.EmbeddingModelUuid.Data)
	if err != nil {
		return nil, err
	}
	if model == nil {
		r.EmbeddingModel.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return model, nil
}

func (r *mqlDigitaloceanGradientaiKnowledgeBase) database() (*mqlDigitaloceanDatabase, error) {
	if r.DatabaseId.Data == "" {
		r.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db, err := parent.databaseByID(r.DatabaseId.Data)
	if err != nil {
		return nil, err
	}
	if db == nil {
		r.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return db, nil
}

func (r *mqlDigitaloceanGradientaiKnowledgeBase) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

func (r *mqlDigitaloceanGradientaiKnowledgeBase) dataSources() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	sources, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.KnowledgeBaseDataSource, *godo.Response, error) {
		return client.AgentPlatform.ListKnowledgeBaseDataSources(c, r.Uuid.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(sources))
	for i := range sources {
		s := sources[i]
		sourceType := ""
		webCrawler := map[string]interface{}{}
		spaces := map[string]interface{}{}
		fileUpload := map[string]interface{}{}
		if s.WebCrawlerDataSource != nil {
			sourceType = "web_crawler"
			webCrawler = map[string]interface{}{
				"baseUrl":        s.WebCrawlerDataSource.BaseUrl,
				"crawlingOption": s.WebCrawlerDataSource.CrawlingOption,
				"embedMedia":     s.WebCrawlerDataSource.EmbedMedia,
			}
		}
		if s.SpacesDataSource != nil {
			sourceType = "spaces"
			spaces = map[string]interface{}{
				"bucketName": s.SpacesDataSource.BucketName,
				"itemPath":   s.SpacesDataSource.ItemPath,
				"region":     s.SpacesDataSource.Region,
			}
		}
		if s.FileUploadDataSource != nil {
			sourceType = "file_upload"
			fileUpload = map[string]interface{}{
				"originalFileName": s.FileUploadDataSource.OriginalFileName,
				"size":             s.FileUploadDataSource.Size,
				"storedObjectKey":  s.FileUploadDataSource.StoredObjectKey,
			}
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.knowledgeBase.dataSource", map[string]*llx.RawData{
			"__id":            llx.StringData(r.Uuid.Data + "/" + s.Uuid),
			"uuid":            llx.StringData(s.Uuid),
			"type":            llx.StringData(sourceType),
			"webCrawler":      llx.DictData(webCrawler),
			"spaces":          llx.DictData(spaces),
			"fileUpload":      llx.DictData(fileUpload),
			"lastIndexingJob": llx.DictData(lastIndexingJobDict(s.LastIndexingJob)),
			"createdAt":       llx.TimeDataPtr(gradientaiTime(s.CreatedAt)),
			"updatedAt":       llx.TimeDataPtr(gradientaiTime(s.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// ----- Indexing jobs -----

func (r *mqlDigitaloceanGradientai) indexingJobs() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.ListOptions{PerPage: 200}
	for {
		resp, httpResp, err := client.AgentPlatform.ListIndexingJobs(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		if resp != nil {
			for i := range resp.Jobs {
				j := resp.Jobs[i]
				uuids := make([]interface{}, len(j.DataSourceUuids))
				for k, u := range j.DataSourceUuids {
					uuids[k] = u
				}
				res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.indexingJob", map[string]*llx.RawData{
					"__id":                 llx.StringData(j.Uuid),
					"uuid":                 llx.StringData(j.Uuid),
					"knowledgeBaseUuid":    llx.StringData(j.KnowledgeBaseUuid),
					"phase":                llx.StringData(j.Phase),
					"status":               llx.StringData(j.Status),
					"tokens":               llx.IntData(int64(j.Tokens)),
					"completedDatasources": llx.IntData(int64(j.CompletedDatasources)),
					"totalDatasources":     llx.IntData(int64(j.TotalDatasources)),
					"totalItemsIndexed":    llx.StringData(j.TotalItemsIndexed),
					"totalItemsFailed":     llx.StringData(j.TotalItemsFailed),
					"totalItemsSkipped":    llx.StringData(j.TotalItemsSkipped),
					"dataSourceUuids":      llx.ArrayData(uuids, types.String),
					"startedAt":            llx.TimeDataPtr(gradientaiTime(j.StartedAt)),
					"finishedAt":           llx.TimeDataPtr(gradientaiTime(j.FinishedAt)),
					"createdAt":            llx.TimeDataPtr(gradientaiTime(j.CreatedAt)),
					"updatedAt":            llx.TimeDataPtr(gradientaiTime(j.UpdatedAt)),
				})
				if err != nil {
					return nil, err
				}
				all = append(all, res)
			}
		}
		if httpResp == nil || httpResp.Links == nil || httpResp.Links.IsLastPage() {
			break
		}
		page, err := httpResp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

func (r *mqlDigitaloceanGradientaiIndexingJob) knowledgeBase() (*mqlDigitaloceanGradientaiKnowledgeBase, error) {
	if r.KnowledgeBaseUuid.Data == "" {
		r.KnowledgeBase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentGradientai(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	kb, err := parent.knowledgeBaseByUUID(r.KnowledgeBaseUuid.Data)
	if err != nil {
		return nil, err
	}
	if kb == nil {
		r.KnowledgeBase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return kb, nil
}
