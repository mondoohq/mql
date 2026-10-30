// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/members"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.image ----

type mqlOpenstackImageInternal struct {
	cacheOwnerID string
}

func (r *mqlOpenstackImage) id() (string, error) {
	return "openstack.image/" + r.Id.Data, nil
}

func initOpenstackImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetImages()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		img := raw.(*mqlOpenstackImage)
		if img.Id.Data == id {
			return args, img, nil
		}
	}
	initSyntheticID("openstack.image", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) images() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ImageClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := images.List(client, images.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := images.ExtractImages(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		img := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.image", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.image/" + img.ID),
			"id":               llx.StringData(img.ID),
			"name":             llx.StringData(img.Name),
			"status":           llx.StringData(string(img.Status)),
			"visibility":       llx.StringData(string(img.Visibility)),
			"protected":        llx.BoolData(img.Protected),
			"hidden":           llx.BoolData(img.Hidden),
			"containerFormat":  llx.StringData(img.ContainerFormat),
			"diskFormat":       llx.StringData(img.DiskFormat),
			"minDiskGigabytes": llx.IntData(int64(img.MinDiskGigabytes)),
			"minRamMegabytes":  llx.IntData(int64(img.MinRAMMegabytes)),
			"checksum":         llx.StringData(img.Checksum),
			"osHashAlgo":       llx.StringData(imagePropertyString(img.Properties, "os_hash_algo")),
			"osHashValue":      llx.StringData(imagePropertyString(img.Properties, "os_hash_value")),
			"sizeBytes":        llx.IntData(img.SizeBytes),
			"virtualSize":      llx.IntData(img.VirtualSize),
			"tags":             stringSliceData(img.Tags),
			"metadata":         stringMapData(img.Metadata),
			"properties":       llx.DictData(toDict(img.Properties)),
			"createdAt":        llx.TimeDataPtr(timePtr(img.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(timePtr(img.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlImage := res.(*mqlOpenstackImage)
		mqlImage.cacheOwnerID = img.Owner
		out = append(out, mqlImage)
	}
	return out, nil
}

// imageSignatureFromProperties extracts the Glance `img_signature` property
// value from an image's free-form properties dict. It returns an empty string
// when the property is absent, null, or not a string (i.e. the image is
// unsigned).
func imageSignatureFromProperties(properties any) string {
	props, ok := properties.(map[string]any)
	if !ok {
		return ""
	}
	sig, ok := props["img_signature"].(string)
	if !ok {
		return ""
	}
	return sig
}

func (r *mqlOpenstackImage) imageSignature() (string, error) {
	props := r.GetProperties()
	if props.Error != nil {
		return "", props.Error
	}
	return imageSignatureFromProperties(props.Data), nil
}

// imagePropertyString returns the string value of a Glance image property,
// or an empty string when the property is absent, null, or not a string.
func imagePropertyString(properties any, key string) string {
	props, ok := properties.(map[string]any)
	if !ok {
		return ""
	}
	v, ok := props[key].(string)
	if !ok {
		return ""
	}
	return v
}

// resolveImageRef resolves an image referenced by a `kernel_id` / `ramdisk_id`
// property to an openstack.image resource, marking the field null when the
// property is absent.
func (r *mqlOpenstackImage) resolveImageRef(key string, field *plugin.TValue[*mqlOpenstackImage]) (*mqlOpenstackImage, error) {
	props := r.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}
	id := imagePropertyString(props.Data, key)
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.image", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackImage), nil
}

func (r *mqlOpenstackImage) kernel() (*mqlOpenstackImage, error) {
	return r.resolveImageRef("kernel_id", &r.Kernel)
}

func (r *mqlOpenstackImage) ramdisk() (*mqlOpenstackImage, error) {
	return r.resolveImageRef("ramdisk_id", &r.Ramdisk)
}

func (r *mqlOpenstackImage) owner() (*mqlOpenstackProject, error) {
	if r.cacheOwnerID == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheOwnerID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

func (r *mqlOpenstackImage) members() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ImageClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := members.List(client, r.Id.Data).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := members.ExtractMembers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, m := range items {
		res, err := CreateResource(r.MqlRuntime, "openstack.image.member", map[string]*llx.RawData{
			"__id":      llx.StringData("openstack.image.member/" + m.ImageID + "/" + m.MemberID),
			"memberId":  llx.StringData(m.MemberID),
			"imageId":   llx.StringData(m.ImageID),
			"status":    llx.StringData(m.Status),
			"createdAt": llx.TimeDataPtr(timePtr(m.CreatedAt)),
			"updatedAt": llx.TimeDataPtr(timePtr(m.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.image.member ----

func (r *mqlOpenstackImageMember) id() (string, error) {
	return "openstack.image.member/" + r.ImageId.Data + "/" + r.MemberId.Data, nil
}

func initOpenstackImageMember(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	imageId, _ := stringArg(args, "imageId")
	memberId, _ := stringArg(args, "memberId")
	if imageId == "" || memberId == "" {
		return args, nil, nil
	}
	if _, ok := args["__id"]; !ok {
		args["__id"] = llx.StringData("openstack.image.member/" + imageId + "/" + memberId)
	}
	return args, nil, nil
}

func (r *mqlOpenstackImageMember) image() (*mqlOpenstackImage, error) {
	if r.ImageId.Data == "" {
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.image", map[string]*llx.RawData{
		"id": llx.StringData(r.ImageId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackImage), nil
}

func (r *mqlOpenstackImageMember) project() (*mqlOpenstackProject, error) {
	if r.MemberId.Data == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.MemberId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}
