// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// slsMaxListPages caps an offset-paginated Log Service listing. It exists for
// the case where the server answers every request with the same full page,
// which no other stop condition catches: the offset keeps advancing, the page
// stays full, and the walk would repeat until the scan is killed.
const slsMaxListPages = 500

// slsOffsetListDone reports whether an offset-paginated Log Service listing has
// reached its end.
//
// A page shorter than the requested size is the last one, and an empty page is
// the end whatever the size. An offset that has caught up with the reported
// total is the end too, for a server that keeps answering with full pages. The
// page count is the last resort, for a server that ignores the offset and
// reports no total.
func slsOffsetListDone(pageLen, pageSize int, offset, total int32, pages int) bool {
	if pageLen == 0 || pageLen < pageSize {
		return true
	}
	if total > 0 && offset >= total {
		return true
	}
	return pages >= slsMaxListPages
}

// slsAllowedStoreNames flattens an API key's store scope, dropping nil and
// blank entries so a blank name is never handed to a logstore lookup. The
// Alibaba Cloud SDK models the scope as a pointer slice whose elements may each
// be nil, so dereferencing them unguarded would panic on a key nobody could
// have predicted the shape of.
func slsAllowedStoreNames(in []*string) []string {
	return strPtrsToStrings(in)
}

// slsApiKeyAllowsAllStores reports whether an API key carries no store
// restriction. Log Service treats an empty scope as "every store in the
// project", so an empty list is the widest scope a key can have and not the
// narrowest, which is the reading a plain length check invites.
func slsApiKeyAllowsAllStores(allowedStores []string) bool {
	return len(allowedStores) == 0
}

// apiKeys lists the standing API keys scoped to the project. Log Service scopes
// API keys to a project rather than to a region, so the keys of an account are
// reached through alicloud.log.projects rather than through a region fan-out.
func (r *mqlAlicloudLogProject) apiKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(r.region)
	if err != nil {
		return nil, err
	}
	projectName := r.Name.Data

	res := []any{}
	offset := int32(0)
	size := int32(100)
	pages := 0
	firstPage := true
	for {
		resp, err := client.ListApiKeys(new(projectName), &slsclient.ListApiKeysRequest{
			Offset: new(offset),
			Size:   new(size),
		})
		if err != nil {
			// A first-page error means the project has no API key surface or
			// the credential lacks log:ListApiKeys here; skip it. A later-page
			// error is real, and truncating the list silently would report
			// fewer standing credentials than exist.
			if firstPage {
				log.Debug().Err(err).Str("project", projectName).
					Msg("alicloud> could not list Log Service API keys")
				break
			}
			return nil, err
		}
		firstPage = false
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.ApiKeys
		for _, k := range items {
			if k == nil || k.ApiKeyName == nil {
				continue
			}
			mqlKey, err := newLogApiKey(r.MqlRuntime, r.region, projectName, k)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlKey)
		}

		pages++
		offset += int32(len(items))
		if slsOffsetListDone(len(items), int(size), offset, tea.Int32Value(resp.Body.Total), pages) {
			break
		}
	}
	return res, nil
}

// logApiKeyArgs maps a ListApiKeys record onto the resource fields.
//
// The record also carries the key in plaintext. It is deliberately absent from
// this map: a field built from it would reach every report and every recording
// the moment anyone queried the resource, so the key material never leaves the
// SDK struct.
func logApiKeyArgs(region, projectName string, k *slsclient.ListApiKeysResponseBodyApiKeys) map[string]*llx.RawData {
	name := tea.StringValue(k.ApiKeyName)
	allowedStores := slsAllowedStoreNames(k.AllowedStores)
	stores := make([]any, 0, len(allowedStores))
	for _, s := range allowedStores {
		stores = append(stores, s)
	}

	return map[string]*llx.RawData{
		"__id":            llx.StringData(region + "/" + projectName + "/" + name),
		"regionId":        llx.StringData(region),
		"projectName":     llx.StringData(projectName),
		"apiKeyName":      llx.StringData(name),
		"description":     llx.StringDataPtr(k.Description),
		"status":          llx.StringDataPtr(k.Status),
		"allowedStores":   llx.ArrayData(stores, types.String),
		"allowsAllStores": llx.BoolData(slsApiKeyAllowsAllStores(allowedStores)),
		"createTime":      llx.TimeDataPtr(slsEpochTime(k.CreateTime)),
		"updateTime":      llx.TimeDataPtr(slsEpochTime(k.UpdateTime)),
	}
}

// newLogApiKey builds an alicloud.log.apiKey from a ListApiKeys record.
func newLogApiKey(runtime *plugin.Runtime, region, projectName string, k *slsclient.ListApiKeysResponseBodyApiKeys) (*mqlAlicloudLogApiKey, error) {
	resource, err := CreateResource(runtime, "alicloud.log.apiKey", logApiKeyArgs(region, projectName, k))
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudLogApiKey), nil
}

// project resolves the Log Service project the key is scoped to. A key cannot
// outlive its project, so a failure to read it is a real error.
func (r *mqlAlicloudLogApiKey) project() (*mqlAlicloudLogProject, error) {
	project, err := resolveLogProject(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

// allowedLogstores resolves the logstores named in the key's store scope. A
// name that does not resolve is skipped with a warning rather than failing the
// list: the scope may also name a metricstore, which is not a logstore and has
// no resource of its own, and one such name must not hide the logstores beside
// it. allowedStores keeps every name, so nothing is lost.
func (r *mqlAlicloudLogApiKey) allowedLogstores() ([]any, error) {
	res := []any{}
	for _, raw := range r.AllowedStores.Data {
		name, ok := raw.(string)
		if !ok || name == "" {
			continue
		}
		store, err := resolveLogStore(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data, name)
		if err != nil {
			log.Warn().Err(err).Str("store", name).Str("project", r.ProjectName.Data).
				Msg("alicloud> unable to resolve a store named in a Log Service API key scope")
			continue
		}
		if store == nil {
			continue
		}
		res = append(res, store)
	}
	return res, nil
}
