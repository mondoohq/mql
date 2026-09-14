// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	polardb "github.com/alibabacloud-go/polardb-20170801/v9/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// polardbKnowledgeMaxPages caps a knowledge listing walk. Every other stop
// condition depends on the server honoring PageNumber; this one does not, so a
// server that answers every page with the same full batch stops here instead of
// repeating until the scan is killed.
const polardbKnowledgeMaxPages = 500

// polardbSyncLinkPageSize is the page size the synchronization link walk asks
// for. DescribeKBSyncLinks accepts 10, 20, 30, 50, 100, 200 or 500 and defaults
// to 30, so asking for the value below trades a smaller number of calls for the
// same set of links.
const polardbSyncLinkPageSize = int32(100)

// mqlAlicloudPolardbKnowledgeSpaceInternal caches the values the space needs to
// list its knowledge bases and to resolve its typed cluster and bucket
// references.
type mqlAlicloudPolardbKnowledgeSpaceInternal struct {
	region           string
	knowledgeSpaceId string
	cacheClusterID   string
	cacheOssBucket   string
}

// mqlAlicloudPolardbKnowledgeBaseInternal caches the keys the knowledge base
// needs to read its synchronization links and to resolve its owning space.
type mqlAlicloudPolardbKnowledgeBaseInternal struct {
	region          string
	knowledgeBaseId string
	cacheSpaceID    string
}

// mqlAlicloudPolardbInternal memoizes the account-wide knowledge-base listing.
// Both knowledgeBases and knowledgeSpaces walk it, because the spaces are only
// reachable through the bases, and a query touching both would otherwise pay
// the whole region walk twice.
type mqlAlicloudPolardbInternal struct {
	knowledgeLock  sync.Mutex
	knowledgeReady bool
	kbRecords      map[string][]*polardb.DescribeKnowledgeBasesResponseBodyItems
}

// listKnowledgeBaseRecords walks DescribeKnowledgeBases for one region,
// optionally narrowed to a single knowledge space.
//
// A first-page error means the region has no knowledge-base feature or the
// credential cannot read it there; that region yields no records rather than
// failing a query over the whole account. A later-page error is real and is
// returned, because truncating the walk silently would report fewer corpora
// than exist, and a shorter list satisfies every assertion made about it.
func listKnowledgeBaseRecords(client *polardb.Client, region, knowledgeSpaceID string) ([]*polardb.DescribeKnowledgeBasesResponseBodyItems, error) {
	res := []*polardb.DescribeKnowledgeBasesResponseBodyItems{}
	pageNumber := int32(1)
	pageSize := int32(100)
	pages := 0
	for {
		pn := pageNumber
		ps := pageSize
		req := &polardb.DescribeKnowledgeBasesRequest{
			RegionId:   tea.String(region),
			PageNumber: &pn,
			PageSize:   &ps,
		}
		if knowledgeSpaceID != "" {
			req.KnowledgeSpaceId = tea.String(knowledgeSpaceID)
		}
		resp, err := client.DescribeKnowledgeBases(req)
		if err != nil {
			if pages == 0 {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list PolarDB knowledge bases")
				return res, nil
			}
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			return res, nil
		}

		items := resp.Body.Items
		for _, kb := range items {
			if kb == nil || kb.KnowledgeBaseId == nil {
				continue
			}
			res = append(res, kb)
		}

		pages++
		if len(items) == 0 || len(items) < int(pageSize) || pages >= polardbKnowledgeMaxPages {
			return res, nil
		}
		pageNumber++
	}
}

// knowledgeBaseRecordsByRegion walks every enabled region once and hands the
// same records to both knowledge accessors. A failed walk is not memoized, so a
// later access retries rather than permanently reporting an account as having
// no corpora.
func (r *mqlAlicloudPolardb) knowledgeBaseRecordsByRegion() (map[string][]*polardb.DescribeKnowledgeBasesResponseBodyItems, error) {
	r.knowledgeLock.Lock()
	defer r.knowledgeLock.Unlock()
	if r.knowledgeReady {
		return r.kbRecords, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	records := map[string][]*polardb.DescribeKnowledgeBasesResponseBodyItems{}
	for _, region := range regions {
		client, err := conn.PolarDBClient(region)
		if err != nil {
			return nil, err
		}
		bases, err := listKnowledgeBaseRecords(client, region, "")
		if err != nil {
			return nil, err
		}
		records[region] = bases
	}

	r.kbRecords = records
	r.knowledgeReady = true
	return r.kbRecords, nil
}

// knowledgeBases lists the knowledge bases across every enabled region.
func (r *mqlAlicloudPolardb) knowledgeBases() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}
	records, err := r.knowledgeBaseRecordsByRegion()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		for _, kb := range records[region] {
			mqlBase, err := newPolardbKnowledgeBase(r.MqlRuntime, region, kb)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBase)
		}
	}
	return res, nil
}

// polardbKnowledgeSpaceIDs collects the distinct knowledge space ids named by a
// batch of knowledge bases, in the order they were first seen. Alibaba Cloud
// offers no listing of knowledge spaces, so the knowledge bases are the only
// route to them; the order is kept stable so the same account produces the same
// list twice running.
func polardbKnowledgeSpaceIDs(bases []*polardb.DescribeKnowledgeBasesResponseBodyItems) []string {
	seen := map[string]struct{}{}
	res := []string{}
	for _, kb := range bases {
		if kb == nil {
			continue
		}
		id := polardbStr(kb.KnowledgeSpaceId)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		res = append(res, id)
	}
	return res
}

// knowledgeSpaces lists the knowledge spaces reached from the knowledge bases in
// every enabled region. A space holding no knowledge base cannot be discovered
// this way and has to be named directly through the resource's own lookup.
func (r *mqlAlicloudPolardb) knowledgeSpaces() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}
	records, err := r.knowledgeBaseRecordsByRegion()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.PolarDBClient(region)
		if err != nil {
			return nil, err
		}
		for _, spaceID := range polardbKnowledgeSpaceIDs(records[region]) {
			body, err := describeKnowledgeSpace(client, region, spaceID)
			if err != nil {
				// one space the credential cannot read must not hide the rest
				log.Warn().Err(err).Str("knowledgeSpaceId", spaceID).Str("region", region).
					Msg("alicloud> unable to read a PolarDB knowledge space")
				continue
			}
			mqlSpace, err := newPolardbKnowledgeSpace(r.MqlRuntime, region, body)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSpace)
		}
	}
	return res, nil
}

// describeKnowledgeSpace reads one knowledge space, reporting a response that
// carries no space as a not-found error rather than as an empty record.
func describeKnowledgeSpace(client *polardb.Client, region, knowledgeSpaceID string) (*polardb.DescribeKnowledgeSpaceAttributeResponseBody, error) {
	resp, err := client.DescribeKnowledgeSpaceAttribute(&polardb.DescribeKnowledgeSpaceAttributeRequest{
		RegionId:         tea.String(region),
		KnowledgeSpaceId: tea.String(knowledgeSpaceID),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || polardbStr(resp.Body.KnowledgeSpaceId) == "" {
		return nil, fmt.Errorf("alicloud.polardb.knowledgeSpace %q not found in region %q", knowledgeSpaceID, region)
	}
	return resp.Body, nil
}

func newPolardbKnowledgeSpace(runtime *plugin.Runtime, region string, s *polardb.DescribeKnowledgeSpaceAttributeResponseBody) (*mqlAlicloudPolardbKnowledgeSpace, error) {
	spaceID := polardbStr(s.KnowledgeSpaceId)
	resource, err := CreateResource(runtime, "alicloud.polardb.knowledgeSpace", map[string]*llx.RawData{
		"__id":               llx.StringData(region + "/" + spaceID),
		"regionId":           llx.StringData(region),
		"knowledgeSpaceId":   llx.StringData(spaceID),
		"name":               llx.StringDataPtr(s.Name),
		"description":        llx.StringDataPtr(s.Description),
		"aclMode":            llx.StringDataPtr(s.ACLMode),
		"status":             llx.StringDataPtr(s.Status),
		"dbName":             llx.StringDataPtr(s.DBName),
		"dbType":             llx.StringDataPtr(s.DBType),
		"embeddingModel":     llx.StringDataPtr(s.EmbeddingModel),
		"embeddingDimension": llx.IntDataPtr(s.EmbeddingDimension),
		"llmModel":           llx.StringDataPtr(s.LLMModel),
		"rerankModel":        llx.StringDataPtr(s.RerankModel),
		"strategy":           llx.StringDataPtr(s.Strategy),
		"shardSize":          llx.IntDataPtr(s.ShardSize),
		"knowledgeBaseCount": llx.IntDataPtr(s.KnowledgeBaseCount),
		"totalDocs":          llx.IntDataPtr(s.TotalDocs),
		"totalSizeBytes":     llx.IntDataPtr(s.TotalSizeBytes),
		"createTime":         llx.TimeDataPtr(polardbParseTime(s.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	space := resource.(*mqlAlicloudPolardbKnowledgeSpace)
	space.region = region
	space.knowledgeSpaceId = spaceID
	space.cacheClusterID = polardbStr(s.DBClusterId)
	space.cacheOssBucket = polardbStr(s.OSSBucket)
	return space, nil
}

// initAlicloudPolardbKnowledgeSpace resolves a knowledge space by its id within
// a region. It is the only route to a space that holds no knowledge base, since
// Alibaba Cloud offers no listing of knowledge spaces.
func initAlicloudPolardbKnowledgeSpace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	spaceID, err := requiredStringArg(args, "knowledgeSpaceId", "alicloud.polardb.knowledgeSpace")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.polardb.knowledgeSpace")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.polardb.knowledgeSpace\x00" + region + "/" + spaceID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(region)
	if err != nil {
		return nil, nil, err
	}
	body, err := describeKnowledgeSpace(client, region, spaceID)
	if err != nil {
		return nil, nil, err
	}
	res, err := newPolardbKnowledgeSpace(runtime, region, body)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// dbCluster resolves the PolarDB cluster that stores the space's vectors. A
// cluster that cannot be read resolves to null rather than failing the space
// query, because the cluster may sit outside the scanned regions.
func (r *mqlAlicloudPolardbKnowledgeSpace) dbCluster() (*mqlAlicloudPolardbCluster, error) {
	if r.cacheClusterID == "" {
		r.DbCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.polardb.cluster", map[string]*llx.RawData{
		"dbClusterId": llx.StringData(r.cacheClusterID),
		"regionId":    llx.StringData(r.region),
	})
	if err != nil {
		log.Warn().Err(err).Str("dbClusterId", r.cacheClusterID).Str("knowledgeSpaceId", r.knowledgeSpaceId).
			Msg("alicloud> unable to resolve the cluster of a PolarDB knowledge space")
		r.DbCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAlicloudPolardbCluster), nil
}

// ossBucket resolves the OSS bucket the space's source documents are drawn
// from. A bucket that cannot be read resolves to null: OSS is a separate
// service the credential may not reach, and that must not fail the space query.
func (r *mqlAlicloudPolardbKnowledgeSpace) ossBucket() (*mqlAlicloudOssBucket, error) {
	if r.cacheOssBucket == "" {
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	bucket, err := resolveOssBucket(r.MqlRuntime, r.cacheOssBucket)
	if err != nil {
		log.Warn().Err(err).Str("bucket", r.cacheOssBucket).Str("knowledgeSpaceId", r.knowledgeSpaceId).
			Msg("alicloud> unable to resolve the OSS bucket of a PolarDB knowledge space")
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if bucket == nil {
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return bucket, nil
}

// knowledgeBases lists the knowledge bases held in the space.
func (r *mqlAlicloudPolardbKnowledgeSpace) knowledgeBases() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}

	bases, err := listKnowledgeBaseRecords(client, r.region, r.knowledgeSpaceId)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, kb := range bases {
		mqlBase, err := newPolardbKnowledgeBase(r.MqlRuntime, r.region, kb)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBase)
	}
	return res, nil
}

func newPolardbKnowledgeBase(runtime *plugin.Runtime, region string, kb *polardb.DescribeKnowledgeBasesResponseBodyItems) (*mqlAlicloudPolardbKnowledgeBase, error) {
	baseID := polardbStr(kb.KnowledgeBaseId)
	resource, err := CreateResource(runtime, "alicloud.polardb.knowledgeBase", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + baseID),
		"regionId":          llx.StringData(region),
		"knowledgeBaseId":   llx.StringData(baseID),
		"name":              llx.StringDataPtr(kb.Name),
		"description":       llx.StringDataPtr(kb.Description),
		"knowledgeBaseType": llx.StringDataPtr(kb.KnowledgeBaseType),
		"status":            llx.StringDataPtr(kb.Status),
		"bindingAppCount":   llx.IntDataPtr(kb.BindingAppCount),
		"totalDocs":         llx.IntDataPtr(kb.TotalDocs),
		"totalSizeBytes":    llx.IntDataPtr(kb.TotalSizeBytes),
		"createTime":        llx.TimeDataPtr(polardbParseTime(kb.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	base := resource.(*mqlAlicloudPolardbKnowledgeBase)
	base.region = region
	base.knowledgeBaseId = baseID
	base.cacheSpaceID = polardbStr(kb.KnowledgeSpaceId)
	return base, nil
}

// knowledgeSpace resolves the space that contains the knowledge base. A space
// that cannot be read resolves to null rather than failing the knowledge base
// query.
func (r *mqlAlicloudPolardbKnowledgeBase) knowledgeSpace() (*mqlAlicloudPolardbKnowledgeSpace, error) {
	if r.cacheSpaceID == "" {
		r.KnowledgeSpace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.polardb.knowledgeSpace", map[string]*llx.RawData{
		"knowledgeSpaceId": llx.StringData(r.cacheSpaceID),
		"regionId":         llx.StringData(r.region),
	})
	if err != nil {
		log.Warn().Err(err).Str("knowledgeSpaceId", r.cacheSpaceID).Str("knowledgeBaseId", r.knowledgeBaseId).
			Msg("alicloud> unable to resolve the space of a PolarDB knowledge base")
		r.KnowledgeSpace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAlicloudPolardbKnowledgeSpace), nil
}

// polardbSyncLinkPageFunc reads one page of synchronization links. The walk is
// written against this rather than against the client so that the paging can be
// exercised without a PolarDB endpoint.
type polardbSyncLinkPageFunc func(pageNumber, pageSize int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error)

// collectPolardbSyncLinks walks every page of DescribeKBSyncLinks and returns
// the links it gathered.
//
// The endpoint is paginated and answers with the first page of 30 when no page
// is asked for, so a knowledge base carrying more feeds than that reported only
// the first 30 of them. A page shorter than the one requested ends the walk, and
// polardbKnowledgeMaxPages ends a walk whose server keeps answering with a full
// page whatever PageNumber it is given. An error on any page fails the walk:
// returning the pages gathered so far would report fewer feeds than exist, and a
// shorter list satisfies every assertion made about it.
func collectPolardbSyncLinks(pageSize int32, fetch polardbSyncLinkPageFunc) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
	res := []*polardb.DescribeKBSyncLinksResponseBodyItems{}
	pageNumber := int32(1)
	pages := 0
	for {
		items, err := fetch(pageNumber, pageSize)
		if err != nil {
			return nil, err
		}

		for _, l := range items {
			if l == nil {
				continue
			}
			res = append(res, l)
		}

		pages++
		if len(items) < int(pageSize) || pages >= polardbKnowledgeMaxPages {
			return res, nil
		}
		pageNumber++
	}
}

// syncLinks lists the links that pull content into the knowledge base from an
// external messaging platform.
func (r *mqlAlicloudPolardbKnowledgeBase) syncLinks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.PolarDBClient(r.region)
	if err != nil {
		return nil, err
	}

	links, err := collectPolardbSyncLinks(polardbSyncLinkPageSize,
		func(pageNumber, pageSize int32) ([]*polardb.DescribeKBSyncLinksResponseBodyItems, error) {
			pn := pageNumber
			ps := pageSize
			resp, err := client.DescribeKBSyncLinks(&polardb.DescribeKBSyncLinksRequest{
				RegionId:        tea.String(r.region),
				KnowledgeBaseId: tea.String(r.knowledgeBaseId),
				PageNumber:      &pn,
				PageSize:        &ps,
			})
			if err != nil {
				return nil, err
			}
			if resp == nil || resp.Body == nil {
				return nil, nil
			}
			return resp.Body.Items, nil
		})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, l := range links {
		link, err := newPolardbKnowledgeBaseSyncLink(r.MqlRuntime, r.region, r.knowledgeBaseId, l)
		if err != nil {
			return nil, err
		}
		res = append(res, link)
	}
	return res, nil
}

// polardbSyncLinkKey builds the identifying suffix of a synchronization link's
// cache key. LinkId is the natural key, but it is optional in the response, so a
// link without one falls back to its platform and source directory. Without the
// fallback two such links would share a cache key and the second would report
// the first one's source.
func polardbSyncLinkKey(l *polardb.DescribeKBSyncLinksResponseBodyItems) string {
	if l == nil {
		return ""
	}
	if id := polardbStr(l.LinkId); id != "" {
		return id
	}
	return polardbStr(l.ImPlatform) + "/" + polardbStr(l.SourceDir)
}

func newPolardbKnowledgeBaseSyncLink(runtime *plugin.Runtime, region, knowledgeBaseID string, l *polardb.DescribeKBSyncLinksResponseBodyItems) (*mqlAlicloudPolardbKnowledgeBaseSyncLink, error) {
	resource, err := CreateResource(runtime, "alicloud.polardb.knowledgeBase.syncLink", map[string]*llx.RawData{
		"__id":                llx.StringData(region + "/" + knowledgeBaseID + "/link/" + polardbSyncLinkKey(l)),
		"linkId":              llx.StringDataPtr(l.LinkId),
		"linkName":            llx.StringDataPtr(l.LinkName),
		"description":         llx.StringDataPtr(l.Description),
		"imPlatform":          llx.StringDataPtr(l.ImPlatform),
		"clientId":            llx.StringDataPtr(l.ClientId),
		"sourceDir":           llx.StringDataPtr(l.SourceDir),
		"syncIntervalMinutes": llx.IntDataPtr(l.SyncIntervalMinutes),
		"syncStatus":          llx.StringDataPtr(l.SyncStatus),
		"createTime":          llx.TimeDataPtr(polardbParseTime(l.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudPolardbKnowledgeBaseSyncLink), nil
}
