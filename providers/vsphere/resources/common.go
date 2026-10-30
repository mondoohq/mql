// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25/mo"
	vmwaretypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

// extractTagKeys extracts tag keys from vmware Tag slice
func extractTagKeys(tags []vmwaretypes.Tag) []string {
	tagKeys := make([]string, len(tags))
	for i, tag := range tags {
		tagKeys[i] = tag.Key
	}
	return tagKeys
}

// BatchGetTags fetches the attached vAPI tags for every reference in `refs`
// using a single batched API call and caching category lookups across the
// batch. The returned map is keyed by ref.Reference().Value (the MOID) and
// holds tag strings formatted as "category:tag".
//
// The vAPI REST session is owned by the connection and reused across calls,
// so within a single `mql run` we pay the ~hundreds-of-ms login cost only
// once per connection rather than once per batch.
//
// On any error (login failure, missing credentials, vAPI unavailable) it
// returns an empty map — callers should fall back to mo.ManagedEntity.Tag,
// which preserves the previous "vAPI is best-effort" behavior.
func BatchGetTags(ctx context.Context, refs []mo.Reference, conn *connection.VsphereConnection) map[string][]string {
	out := map[string][]string{}
	if len(refs) == 0 {
		return out
	}

	restClient, err := conn.RestClient(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("vsphere> vAPI rest client unavailable; falling back to mo.ManagedEntity.Tag")
		return out
	}
	tagManager := tags.NewManager(restClient)

	attached, err := tagManager.GetAttachedTagsOnObjects(ctx, refs)
	if err != nil {
		log.Debug().Err(err).Msg("vsphere> GetAttachedTagsOnObjects failed; falling back to mo.ManagedEntity.Tag")
		return out
	}

	return resolveAttachedTags(ctx, attached, func(ctx context.Context, id string) (string, error) {
		cat, err := tagManager.GetCategory(ctx, id)
		if err != nil {
			return "", err
		}
		return cat.Name, nil
	})
}

// categoryNameFetcher resolves a category ID to a name. Returning a non-nil
// error tells resolveAttachedTags to skip the cache entry and try again the
// next time the category is encountered in the batch.
type categoryNameFetcher func(ctx context.Context, categoryID string) (string, error)

// resolveAttachedTags formats the (object → tags) pairs from
// GetAttachedTagsOnObjects into the moid → []string form callers want, looking
// up category names via getCategory. Categories are fetched at most once per
// successful lookup per call. A getCategory failure is NOT cached, so a
// transient error doesn't permanently strip the category prefix from every
// later tag using that category in the same batch.
func resolveAttachedTags(ctx context.Context, attached []tags.AttachedTags, getCategory categoryNameFetcher) map[string][]string {
	out := map[string][]string{}
	categoryNames := map[string]string{}
	for _, entry := range attached {
		moid := entry.ObjectID.Reference().Value
		strs := make([]string, 0, len(entry.Tags))
		for _, tag := range entry.Tags {
			catName, ok := categoryNames[tag.CategoryID]
			if !ok {
				if name, err := getCategory(ctx, tag.CategoryID); err == nil {
					catName = name
					categoryNames[tag.CategoryID] = catName
				}
			}
			if catName == "" {
				strs = append(strs, tag.Name)
			} else {
				strs = append(strs, fmt.Sprintf("%s:%s", catName, tag.Name))
			}
		}
		out[moid] = strs
	}
	return out
}
