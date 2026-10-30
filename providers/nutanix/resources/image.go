// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	vmmcontent "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/models/vmm/v4/content"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nutanix/connection"
)

func newMqlImage(runtime *plugin.Runtime, img *vmmcontent.Image) (*mqlNutanixImage, error) {
	if img.ExtId == nil {
		return nil, nil
	}
	imageType := ""
	if img.Type != nil {
		imageType = img.Type.GetName()
	}
	res, err := CreateResource(runtime, "nutanix.image", map[string]*llx.RawData{
		"__id":        llx.StringDataPtr(img.ExtId),
		"id":          llx.StringDataPtr(img.ExtId),
		"tenantId":    llx.StringDataPtr(img.TenantId),
		"name":        llx.StringDataPtr(img.Name),
		"description": llx.StringDataPtr(img.Description),
		"type":        llx.StringData(imageType),
		"sizeBytes":   llx.IntData(derefInt64(img.SizeBytes)),
		"createTime":  llx.TimeDataPtr(img.CreateTime),
	})
	if err != nil {
		return nil, err
	}
	mqlImage := res.(*mqlNutanixImage)
	mqlImage.cacheClusterIds = img.ClusterLocationExtIds
	if img.OwnerExtId != nil {
		mqlImage.cacheOwnerId = *img.OwnerExtId
	}
	return mqlImage, nil
}

type mqlNutanixImageInternal struct {
	cacheClusterIds []string
	cacheOwnerId    string
}

func (a *mqlNutanixImage) clusters() ([]any, error) {
	res := []any{}
	for _, clusterID := range a.cacheClusterIds {
		if clusterID == "" {
			continue
		}
		cluster, err := clusterByID(a.MqlRuntime, clusterID)
		if err != nil {
			return nil, err
		}
		if cluster == nil {
			continue
		}
		res = append(res, cluster)
	}
	return res, nil
}

func (a *mqlNutanixImage) owner() (*mqlNutanixIamUser, error) {
	if a.cacheOwnerId == "" {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := userByID(a.MqlRuntime, a.cacheOwnerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func listImages(conn *connection.NutanixConnection) ([]vmmcontent.Image, error) {
	api := conn.ImagesApi()
	limit := pageSize
	all := []vmmcontent.Image{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.VmmMu(), func() (*vmmcontent.ListImagesApiResponse, error) {
			return api.ListImages(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]vmmcontent.Image)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListImages", data)
		}
		all = append(all, items...)
		if len(items) < limit {
			break
		}
	}
	return all, nil
}

func (a *mqlNutanix) images() ([]any, error) {
	conn := a.conn()
	imgs, err := listImages(conn)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i := range imgs {
		mqlImg, err := newMqlImage(a.MqlRuntime, &imgs[i])
		if err != nil {
			return nil, err
		}
		if mqlImg == nil {
			continue
		}
		res = append(res, mqlImg)
	}
	return res, nil
}

// imageByID resolves a Nutanix image by its external UUID, returning the cached
// resource when it was already created during this scan and otherwise fetching
// it on demand. A nil result means the image could not be found.
func imageByID(runtime *plugin.Runtime, imageID string) (*mqlNutanixImage, error) {
	if v, ok := cachedResource[*mqlNutanixImage](runtime, "nutanix.image", imageID); ok {
		return v, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	id := imageID
	resp, err := guard(conn.VmmMu(), func() (*vmmcontent.GetImageApiResponse, error) {
		return conn.ImagesApi().GetImageById(&id)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	img, ok := data.(vmmcontent.Image)
	if !ok {
		return nil, nil
	}
	return newMqlImage(runtime, &img)
}
