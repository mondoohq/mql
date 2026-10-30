// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vapi/tags"
	vmwaretypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/types"
)

// mqlVsphereTagInternal caches the category ID so vsphere.tag.category can
// resolve the typed reference against the (memoized) vsphere.categories list
// without re-querying the vAPI per tag.
type mqlVsphereTagInternal struct {
	cacheCategoryID string
}

func (v *mqlVsphere) categories() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	cats, err := tags.NewManager(rc).GetCategories(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tag categories: %w", err)
	}

	res := make([]any, 0, len(cats))
	for i := range cats {
		cat := cats[i]
		mqlCat, err := CreateResource(v.MqlRuntime, "vsphere.category", map[string]*llx.RawData{
			"__id":            llx.StringData(cat.ID),
			"id":              llx.StringData(cat.ID),
			"name":            llx.StringData(cat.Name),
			"description":     llx.StringData(cat.Description),
			"cardinality":     llx.StringData(cat.Cardinality),
			"associableTypes": llx.ArrayData(convert.SliceAnyToInterface(cat.AssociableTypes), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCat)
	}
	return res, nil
}

func (v *mqlVsphere) tags() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	vsphereTags, err := tags.NewManager(rc).GetTags(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	res := make([]any, 0, len(vsphereTags))
	for i := range vsphereTags {
		tag := vsphereTags[i]
		mqlTag, err := CreateResource(v.MqlRuntime, "vsphere.tag", map[string]*llx.RawData{
			"__id":        llx.StringData(tag.ID),
			"id":          llx.StringData(tag.ID),
			"name":        llx.StringData(tag.Name),
			"description": llx.StringData(tag.Description),
		})
		if err != nil {
			return nil, err
		}
		mqlTag.(*mqlVsphereTag).cacheCategoryID = tag.CategoryID
		res = append(res, mqlTag)
	}
	return res, nil
}

func (t *mqlVsphereTag) category() (*mqlVsphereCategory, error) {
	if t.cacheCategoryID == "" {
		t.Category.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(t.MqlRuntime, "vsphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	cats := res.(*mqlVsphere).GetCategories()
	if cats.Error != nil {
		return nil, cats.Error
	}
	for _, c := range cats.Data {
		cat := c.(*mqlVsphereCategory)
		if cat.Id.Data == t.cacheCategoryID {
			return cat, nil
		}
	}

	t.Category.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (c *mqlVsphereCategory) tags() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	tagIDs, err := tags.NewManager(rc).ListTagsForCategory(ctx, c.Id.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags for category: %w", err)
	}
	return resolveTagRefs(c.MqlRuntime, tagIDs)
}

// loadTagIndex builds (once per scan) a map of vAPI tag ID to the shared
// vsphere.tag resource, so per-object tag accessors hand back the same
// instances as the root vsphere.tags list (and their resolved categories).
func loadTagIndex(runtime *plugin.Runtime) (map[string]*mqlVsphereTag, error) {
	res, err := CreateResource(runtime, "vsphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	v := res.(*mqlVsphere)

	v.tagIndexMu.Lock()
	defer v.tagIndexMu.Unlock()
	if v.tagIndex != nil {
		return v.tagIndex, nil
	}

	tagsRes := v.GetTags()
	if tagsRes.Error != nil {
		return nil, tagsRes.Error
	}
	idx := make(map[string]*mqlVsphereTag, len(tagsRes.Data))
	for _, t := range tagsRes.Data {
		mqlTag := t.(*mqlVsphereTag)
		idx[mqlTag.Id.Data] = mqlTag
	}
	v.tagIndex = idx
	return idx, nil
}

// resolveTagRefs maps a list of vAPI tag IDs to their shared vsphere.tag
// resources, skipping any ID not present in the index.
func resolveTagRefs(runtime *plugin.Runtime, tagIDs []string) ([]any, error) {
	if len(tagIDs) == 0 {
		return []any{}, nil
	}
	idx, err := loadTagIndex(runtime)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(tagIDs))
	for _, id := range tagIDs {
		if t, ok := idx[id]; ok {
			res = append(res, t)
		}
	}
	return res, nil
}

// decodeMoRef reverses ManagedObjectReference.Encode (which joins type and a
// URL-escaped value with "-"). FromString is not the inverse of Encode (it
// splits on ":"), so we parse the encoded form here: managed-object type names
// never contain "-", so the first "-" separates type from value.
func decodeMoRef(encoded string) (vmwaretypes.ManagedObjectReference, bool) {
	before, after, ok := strings.Cut(encoded, "-")
	if !ok {
		return vmwaretypes.ManagedObjectReference{}, false
	}
	value, err := url.QueryUnescape(after)
	if err != nil {
		return vmwaretypes.ManagedObjectReference{}, false
	}
	return vmwaretypes.ManagedObjectReference{Type: before, Value: value}, true
}

// attachedTagRefs resolves the vAPI tags attached to the inventory object
// identified by the encoded managed-object reference moid.
func attachedTagRefs(runtime *plugin.Runtime, moid string) ([]any, error) {
	ref, ok := decodeMoRef(moid)
	if !ok {
		return []any{}, nil
	}

	conn := runtime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()
	// tagRefs is the typed sibling of the best-effort mo.ManagedEntity.Tag
	// string field (see BatchGetTags in common.go): when the vAPI is
	// unreachable (direct ESXi connection, or a token without vAPI scope) it
	// degrades to an empty list rather than erroring the whole object, so the
	// two tag views stay consistent.
	rc, err := conn.RestClient(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("vsphere> vAPI rest client unavailable; returning no tag refs")
		return []any{}, nil
	}

	tagIDs, err := tags.NewManager(rc).ListAttachedTags(ctx, ref)
	if err != nil {
		log.Debug().Err(err).Msg("vsphere> ListAttachedTags failed; returning no tag refs")
		return []any{}, nil
	}
	return resolveTagRefs(runtime, tagIDs)
}

func (x *mqlVsphereVm) tagRefs() ([]any, error) { return attachedTagRefs(x.MqlRuntime, x.Moid.Data) }

func (x *mqlVsphereHost) tagRefs() ([]any, error) { return attachedTagRefs(x.MqlRuntime, x.Moid.Data) }

func (x *mqlVsphereDatacenter) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereCluster) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereDatastore) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereResourcepool) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereFolder) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereVswitchDvs) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (x *mqlVsphereVswitchPortgroup) tagRefs() ([]any, error) {
	return attachedTagRefs(x.MqlRuntime, x.Moid.Data)
}

func (v *mqlVsphere) customFields() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	m, err := object.GetCustomFieldsManager(conn.Client().Client)
	if err != nil {
		return nil, fmt.Errorf("failed to get custom fields manager: %w", err)
	}
	defs, err := m.Field(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list custom field definitions: %w", err)
	}

	res := make([]any, 0, len(defs))
	for _, def := range defs {
		mqlField, err := CreateResource(v.MqlRuntime, "vsphere.customField", map[string]*llx.RawData{
			"__id":              llx.StringData(fmt.Sprintf("vsphere.customField/%d", def.Key)),
			"key":               llx.IntData(int64(def.Key)),
			"name":              llx.StringData(def.Name),
			"managedObjectType": llx.StringData(def.ManagedObjectType),
			"type":              llx.StringData(def.Type),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlField)
	}
	return res, nil
}
