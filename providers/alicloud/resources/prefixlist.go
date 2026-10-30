// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// prefixLists enumerates every prefix list in every enabled region.
//
// Discovery filters are deliberately not applied here. Prefix lists are not a
// discovery target, and they exist mainly to be resolved from the security
// group rules that point at them: dropping a list because it lacks a tag would
// make those references resolve to null and hide the very CIDR blocks the rule
// admits.
func (r *mqlAlicloudEcs) prefixLists() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.EcsClient(region)
		if err != nil {
			return nil, err
		}

		var nextToken *string
		firstPage := true
		for {
			resp, err := client.DescribePrefixLists(&ecsclient.DescribePrefixListsRequest{
				RegionId:   new(region),
				MaxResults: tea.Int32(100),
				NextToken:  nextToken,
			})
			if err != nil {
				// A first-page error means the region is unreachable for this
				// credential; skip it. A later-page error is real, so surface it
				// rather than silently truncating the list.
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil || resp.Body.PrefixLists == nil {
				break
			}

			for _, pl := range resp.Body.PrefixLists.PrefixList {
				if pl == nil || pl.PrefixListId == nil {
					continue
				}
				mqlList, err := newEcsPrefixList(r.MqlRuntime, region, pl)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlList)
			}

			if resp.Body.NextToken == nil || *resp.Body.NextToken == "" {
				break
			}
			nextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// mqlAlicloudEcsPrefixListInternal caches the region needed to rebuild a
// region-scoped client and memoizes the entry list, which the list call omits.
type mqlAlicloudEcsPrefixListInternal struct {
	region string

	entriesLock    sync.Mutex
	entriesFetched atomic.Bool
	entries        []any
}

// newEcsPrefixList builds an alicloud.ecs.prefixList from a DescribePrefixLists
// item. The CIDR blocks are not in that response and load lazily.
func newEcsPrefixList(runtime *plugin.Runtime, region string, pl *ecsclient.DescribePrefixListsResponseBodyPrefixListsPrefixList) (*mqlAlicloudEcsPrefixList, error) {
	tags := map[string]any{}
	if pl.Tags != nil {
		for _, t := range pl.Tags.Tag {
			if t == nil || tea.StringValue(t.TagKey) == "" {
				continue
			}
			tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
		}
	}

	resource, err := CreateResource(runtime, "alicloud.ecs.prefixList", map[string]*llx.RawData{
		// region-qualified so two lists can never share a cache key
		"__id":             llx.StringData(region + "/" + tea.StringValue(pl.PrefixListId)),
		"prefixListId":     llx.StringDataPtr(pl.PrefixListId),
		"prefixListName":   llx.StringDataPtr(pl.PrefixListName),
		"description":      llx.StringDataPtr(pl.Description),
		"addressFamily":    llx.StringDataPtr(pl.AddressFamily),
		"maxEntries":       llx.IntData(int64(tea.Int32Value(pl.MaxEntries))),
		"associationCount": llx.IntData(int64(tea.Int32Value(pl.AssociationCount))),
		"regionId":         llx.StringData(region),
		"resourceGroupId":  llx.StringDataPtr(pl.ResourceGroupId),
		"tags":             llx.MapData(tags, types.String),
		"creationTime":     llx.TimeDataPtr(parseEcsTime(pl.CreationTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlList := resource.(*mqlAlicloudEcsPrefixList)
	mqlList.region = region
	return mqlList, nil
}

func (r *mqlAlicloudEcsPrefixList) id() (string, error) {
	// Read the public RegionId rather than the Internal region cache, which is
	// set after CreateResource and would build the key from an empty region.
	return r.RegionId.Data + "/" + r.PrefixListId.Data, nil
}

func (r *mqlAlicloudEcsPrefixList) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// cidrBlocks lazily loads the list's entries. Only the CIDR is exposed: the
// per-entry description is a human label with no bearing on what the list
// admits. A transient error is not cached, so a later access retries rather
// than permanently reporting an unread list as empty, which would read as a
// rule that admits nothing.
func (r *mqlAlicloudEcsPrefixList) cidrBlocks() ([]any, error) {
	if r.entriesFetched.Load() {
		return r.entries, nil
	}
	r.entriesLock.Lock()
	defer r.entriesLock.Unlock()
	if r.entriesFetched.Load() {
		return r.entries, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.EcsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribePrefixListAttributes(&ecsclient.DescribePrefixListAttributesRequest{
		RegionId:     new(r.region),
		PrefixListId: new(r.PrefixListId.Data),
	})
	if err != nil {
		return nil, err
	}

	entries := []any{}
	if resp != nil && resp.Body != nil && resp.Body.Entries != nil {
		for _, e := range resp.Body.Entries.Entry {
			if e == nil || tea.StringValue(e.Cidr) == "" {
				continue
			}
			entries = append(entries, tea.StringValue(e.Cidr))
		}
	}
	r.entries = entries
	r.entriesFetched.Store(true)
	return r.entries, nil
}

// ecsService returns the alicloud.ecs singleton. CreateResource returns the
// already-cached instance once the __id exists, so every rule resolving a
// prefix list shares one enumeration instead of paying for its own.
func ecsService(runtime *plugin.Runtime) (*mqlAlicloudEcs, error) {
	res, err := CreateResource(runtime, "alicloud.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudEcs), nil
}

// prefixListByID finds a prefix list in the account-wide list. Resolving through
// the list rather than a per-rule lookup matters because a security group can
// hold hundreds of rules, and an init would run before the resource cache is
// consulted and turn one enumeration into one API call per rule.
func prefixListByID(runtime *plugin.Runtime, region, listID string) (*mqlAlicloudEcsPrefixList, error) {
	if region == "" || listID == "" {
		return nil, nil
	}
	svc, err := ecsService(runtime)
	if err != nil {
		return nil, err
	}
	lists := svc.GetPrefixLists()
	if lists.Error != nil {
		return nil, lists.Error
	}
	for _, entry := range lists.Data {
		list, ok := entry.(*mqlAlicloudEcsPrefixList)
		if !ok {
			continue
		}
		if list.PrefixListId.Data == listID && list.RegionId.Data == region {
			return list, nil
		}
	}
	return nil, nil
}

// resolvePrefixList returns the prefix list a security group rule is scoped to.
// A list can be deleted while rules that named it are still being read, and an
// account may lack DescribePrefixLists while still being able to read its
// rules, so both resolve to null with a warning rather than failing the rule
// listing. The raw id stays readable either way.
func resolvePrefixList(runtime *plugin.Runtime, region, listID string, field *plugin.TValue[*mqlAlicloudEcsPrefixList]) (*mqlAlicloudEcsPrefixList, error) {
	if listID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	list, err := prefixListByID(runtime, region, listID)
	if err != nil || list == nil {
		if err != nil {
			log.Warn().Err(err).Str("prefixListId", listID).Str("region", region).
				Msg("alicloud> unable to resolve the security group rule prefix list")
		}
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return list, nil
}

func (r *mqlAlicloudEcsSecuritygroupPermission) sourcePrefixList() (*mqlAlicloudEcsPrefixList, error) {
	return resolvePrefixList(r.MqlRuntime, r.cacheRegion, r.SourcePrefixListId.Data, &r.SourcePrefixList)
}

func (r *mqlAlicloudEcsSecuritygroupPermission) destPrefixList() (*mqlAlicloudEcsPrefixList, error) {
	return resolvePrefixList(r.MqlRuntime, r.cacheRegion, r.DestPrefixListId.Data, &r.DestPrefixList)
}
