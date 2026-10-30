// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// tagsToStringMap converts a slice of AWS SDK tag structs into a
// map[string]string, using the supplied key and value accessors. The accessors
// absorb the only variation across the ~100 AWS tag shapes: the field names
// (Key/Value vs KMS-style TagKey/TagValue).
//
// Nil policy: an entry whose key is nil is skipped (a tag key is never
// legitimately empty), while a nil value is normalized to the empty string so a
// tag key present on a resource is always represented.
func tagsToStringMap[T any](tags []T, key func(T) *string, value func(T) *string) map[string]string {
	m := make(map[string]string, len(tags))
	for i := range tags {
		k := key(tags[i])
		if k == nil {
			continue
		}
		m[*k] = convert.ToValue(value(tags[i]))
	}
	return m
}

// lazyTags caches a tag lookup that costs its own API call. Most AWS services
// leave tags out of their list and describe responses, so those resources
// declare tags as a computed field and resolve it through this handler on first
// read. Embed it in the resource's Internal struct:
//
//	type mqlAwsRdsParameterGroupInternal struct {
//		lazyTags
//	}
//
//	func (a *mqlAwsRdsParameterGroup) tags() (map[string]any, error) {
//		return a.resolveTags(&a.Tags, func() (map[string]any, error) { ... })
//	}
//
// A resource with no tags caches an empty map, so an untagged resource costs
// one call rather than one per read. Errors are not cached: a throttled call is
// worth retrying, and caching the failure would turn it into a permanent empty
// tag set.
type lazyTags struct {
	cacheTags   map[string]any
	tagsFetched atomic.Bool
	tagsLock    sync.Mutex
}

// errTagsUnreadable reports that a tag lookup could not be performed at all, as
// distinct from a resource that carries no tags. Access-denied is the usual
// cause; Backup also raises it for resources it does not manage.
//
// The distinction matters because an empty tag map is an assertion. A scan role
// without the tag permission would otherwise report every resource as untagged,
// and an audit that exempts resources by tag, or requires one, would pass
// vacuously over the whole account. An unreadable tag set cannot prove a match,
// so we do not claim one. This mirrors the reasoning in fetchTagsConcurrently.
var errTagsUnreadable = errors.New("tags could not be read")

// markTagsUnreadable marks a computed tags field null and reports no tags, for
// an accessor that reads its tags directly rather than caching them through
// lazyTags.
//
// Setting the state is the one way to make a computed map field surface as
// null: returning a nil map on its own is indistinguishable from a resource
// that carries no tags, because the runtime normalizes it to an empty map.
// GetOrCompute honors a state the accessor set itself.
func markTagsUnreadable(field *plugin.TValue[map[string]any]) (map[string]any, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// tagsOrUnreadable adapts a shared tag helper that reports an unreadable tag
// set as errTagsUnreadable to an accessor that must express it as a null field.
// The helper cannot mark the field itself: it serves several resources and does
// not know which one it is answering for.
func tagsOrUnreadable(field *plugin.TValue[map[string]any], tags map[string]any, err error) (map[string]any, error) {
	if errors.Is(err, errTagsUnreadable) {
		return markTagsUnreadable(field)
	}
	return tags, err
}

// resolveTags runs fetch once and caches the result, and is the only place tag
// nullness is decided.
//
// fetch reports an unreadable tag set by returning errTagsUnreadable, which
// marks field null rather than caching an empty map. It takes the field pointer
// because only the caller knows which field to mark, and because setting the
// state is the one way to make a computed map field surface as null:
// GetOrCompute honors a state the accessor set itself. A nil map with no error
// still means "no tags" and is normalized to an empty map.
func (h *lazyTags) resolveTags(field *plugin.TValue[map[string]any], fetch func() (map[string]any, error)) (map[string]any, error) {
	if h.tagsFetched.Load() {
		return h.cacheTags, nil
	}
	h.tagsLock.Lock()
	defer h.tagsLock.Unlock()
	if h.tagsFetched.Load() {
		return h.cacheTags, nil
	}

	tags, err := fetch()
	if err != nil {
		if errors.Is(err, errTagsUnreadable) {
			// Cache the miss: a missing permission does not change mid-scan,
			// and re-asking per read would cost a denied call every time.
			field.State = plugin.StateIsSet | plugin.StateIsNull
			h.cacheTags = nil
			h.tagsFetched.Store(true)
			return nil, nil
		}
		return nil, err
	}
	if tags == nil {
		tags = map[string]any{}
	}

	h.cacheTags = tags
	h.tagsFetched.Store(true)
	return tags, nil
}

// tagsToMap is tagsToStringMap with a map[string]any result, the shape MQL
// expects for tag fields. It builds the map directly rather than converting a
// map[string]string, avoiding a second allocation and copy.
func tagsToMap[T any](tags []T, key func(T) *string, value func(T) *string) map[string]any {
	m := make(map[string]any, len(tags))
	for i := range tags {
		k := key(tags[i])
		if k == nil {
			continue
		}
		m[*k] = convert.ToValue(value(tags[i]))
	}
	return m
}
