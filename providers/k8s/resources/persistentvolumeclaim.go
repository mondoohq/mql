// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sPersistentvolumeclaimInternal struct {
	lock sync.Mutex
	obj  *corev1.PersistentVolumeClaim
}

func (k *mqlK8s) persistentVolumeClaims() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("persistentvolumeclaims")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		pvc, ok := resource.(*corev1.PersistentVolumeClaim)
		if !ok {
			return nil, errors.New("not a k8s persistentvolumeclaim")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.persistentvolumeclaim", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sPersistentvolumeclaim).obj = pvc
		return r, nil
	})
}

func (k *mqlK8sPersistentvolumeclaim) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sPersistentvolumeclaim) spec() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec)
}

func (k *mqlK8sPersistentvolumeclaim) status() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status)
}

func (k *mqlK8sPersistentvolumeclaim) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sPersistentvolumeclaim(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sPersistentvolumeclaim](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPersistentVolumeClaims() })
}

func (k *mqlK8sPersistentvolumeclaim) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sPersistentvolumeclaim) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sPersistentvolumeclaim) accessModes() ([]any, error) {
	out := make([]any, len(k.obj.Spec.AccessModes))
	for i, m := range k.obj.Spec.AccessModes {
		out[i] = string(m)
	}
	return out, nil
}

func (k *mqlK8sPersistentvolumeclaim) storageClassName() (string, error) {
	if k.obj.Spec.StorageClassName == nil {
		k.StorageClassName.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *k.obj.Spec.StorageClassName, nil
}

func (k *mqlK8sPersistentvolumeclaim) storageClass() (*mqlK8sStorageclass, error) {
	if k.obj.Spec.StorageClassName == nil || *k.obj.Spec.StorageClassName == "" {
		k.StorageClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.storageclass", map[string]*llx.RawData{
		"name": llx.StringData(*k.obj.Spec.StorageClassName),
	})
	if err != nil {
		// StorageClass is cluster-scoped, so it isn't loaded when queried
		// from a namespace-scoped asset, and a referenced StorageClass can
		// genuinely have been deleted. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.StorageClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sStorageclass), nil
}

func (k *mqlK8sPersistentvolumeclaim) volumeName() (string, error) {
	return k.obj.Spec.VolumeName, nil
}

func (k *mqlK8sPersistentvolumeclaim) volume() (*mqlK8sPersistentvolume, error) {
	if k.obj.Spec.VolumeName == "" {
		k.Volume.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.persistentvolume", map[string]*llx.RawData{
		"name": llx.StringData(k.obj.Spec.VolumeName),
	})
	if err != nil {
		// PVs are cluster-scoped, so they aren't loaded when queried from a
		// namespace-scoped asset, and the bound PV can legitimately be
		// missing mid-deletion. Resolve to null; surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Volume.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sPersistentvolume), nil
}

func (k *mqlK8sPersistentvolumeclaim) volumeMode() (string, error) {
	if k.obj.Spec.VolumeMode == nil {
		return "Filesystem", nil
	}
	return string(*k.obj.Spec.VolumeMode), nil
}

func (k *mqlK8sPersistentvolumeclaim) resources() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.Resources)
}

func (k *mqlK8sPersistentvolumeclaim) selector() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.Selector)
}

func (k *mqlK8sPersistentvolumeclaim) dataSource() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.DataSource)
}

func (k *mqlK8sPersistentvolumeclaim) dataSourceRef() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.DataSourceRef)
}

func (k *mqlK8sPersistentvolumeclaim) phase() (string, error) {
	return string(k.obj.Status.Phase), nil
}

func (k *mqlK8sPersistentvolumeclaim) capacity() (map[string]any, error) {
	out := make(map[string]any, len(k.obj.Status.Capacity))
	for name, qty := range k.obj.Status.Capacity {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sPersistentvolumeclaim) boundAccessModes() ([]any, error) {
	out := make([]any, len(k.obj.Status.AccessModes))
	for i, m := range k.obj.Status.AccessModes {
		out[i] = string(m)
	}
	return out, nil
}

func (k *mqlK8sPersistentvolumeclaim) conditions() ([]any, error) {
	return convert.JsonToDictSlice(k.obj.Status.Conditions)
}

func (k *mqlK8sPersistentvolumeclaim) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPersistentvolumeclaim) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
