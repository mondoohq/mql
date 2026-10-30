// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sStorageclassInternal struct {
	lock sync.Mutex
	obj  *storagev1.StorageClass
}

func (k *mqlK8s) storageClasses() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(storagev1.SchemeGroupVersion.WithKind("storageclasses")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		sc, ok := resource.(*storagev1.StorageClass)
		if !ok {
			return nil, errors.New("not a k8s storageclass")
		}

		reclaimPolicy := stringPtrFromTypedPtr(sc.ReclaimPolicy)
		volumeBindingMode := stringPtrFromTypedPtr(sc.VolumeBindingMode)

		r, err := CreateResource(k.MqlRuntime, "k8s.storageclass", map[string]*llx.RawData{
			"id":                   llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":                  llx.StringData(string(obj.GetUID())),
			"resourceVersion":      llx.StringData(obj.GetResourceVersion()),
			"name":                 llx.StringData(obj.GetName()),
			"kind":                 llx.StringData(objT.GetKind()),
			"created":              llx.TimeData(ts.Time),
			"provisioner":          llx.StringData(sc.Provisioner),
			"reclaimPolicy":        llx.StringDataPtr(reclaimPolicy),
			"volumeBindingMode":    llx.StringDataPtr(volumeBindingMode),
			"allowVolumeExpansion": llx.BoolDataPtr(sc.AllowVolumeExpansion),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sStorageclass).obj = sc
		return r, nil
	})
}

func (k *mqlK8sStorageclass) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sStorageclass) parameters() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.Parameters), nil
}

func (k *mqlK8sStorageclass) mountOptions() ([]any, error) {
	res := make([]any, len(k.obj.MountOptions))
	for i, o := range k.obj.MountOptions {
		res[i] = o
	}
	return res, nil
}

// stringPtrFromTypedPtr converts a pointer to a string-based type (e.g., typed K8s enums) to a *string.
func stringPtrFromTypedPtr[T ~string](p *T) *string {
	if p == nil {
		return nil
	}
	s := string(*p)
	return &s
}

func (k *mqlK8sStorageclass) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sStorageclass(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sStorageclass](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetStorageClasses() })
}

func (k *mqlK8sStorageclass) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sStorageclass) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sStorageclass) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sStorageclass) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
