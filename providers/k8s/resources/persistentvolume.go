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

type mqlK8sPersistentvolumeInternal struct {
	lock sync.Mutex
	obj  *corev1.PersistentVolume
}

func (k *mqlK8s) persistentVolumes() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("persistentvolumes")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		pv, ok := resource.(*corev1.PersistentVolume)
		if !ok {
			return nil, errors.New("not a k8s persistentvolume")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.persistentvolume", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sPersistentvolume).obj = pv
		return r, nil
	})
}

func (k *mqlK8sPersistentvolume) manifest() (map[string]any, error) {
	return convert.JsonToDict(k.obj)
}

func (k *mqlK8sPersistentvolume) spec() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec)
}

func (k *mqlK8sPersistentvolume) status() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Status)
}

func (k *mqlK8sPersistentvolume) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sPersistentvolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sPersistentvolume](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetPersistentVolumes() })
}

func (k *mqlK8sPersistentvolume) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sPersistentvolume) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sPersistentvolume) capacity() (map[string]any, error) {
	out := make(map[string]any, len(k.obj.Spec.Capacity))
	for name, qty := range k.obj.Spec.Capacity {
		out[string(name)] = qty.String()
	}
	return out, nil
}

func (k *mqlK8sPersistentvolume) accessModes() ([]any, error) {
	out := make([]any, len(k.obj.Spec.AccessModes))
	for i, m := range k.obj.Spec.AccessModes {
		out[i] = string(m)
	}
	return out, nil
}

func (k *mqlK8sPersistentvolume) persistentVolumeReclaimPolicy() (string, error) {
	return string(k.obj.Spec.PersistentVolumeReclaimPolicy), nil
}

func (k *mqlK8sPersistentvolume) storageClassName() (string, error) {
	return k.obj.Spec.StorageClassName, nil
}

func (k *mqlK8sPersistentvolume) storageClass() (*mqlK8sStorageclass, error) {
	if k.obj.Spec.StorageClassName == "" {
		k.StorageClass.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.storageclass", map[string]*llx.RawData{
		"name": llx.StringData(k.obj.Spec.StorageClassName),
	})
	if err != nil {
		// A referenced StorageClass can have been deleted. Resolve to null;
		// surface other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.StorageClass.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sStorageclass), nil
}

func (k *mqlK8sPersistentvolume) volumeMode() (string, error) {
	if k.obj.Spec.VolumeMode == nil {
		return "Filesystem", nil
	}
	return string(*k.obj.Spec.VolumeMode), nil
}

func (k *mqlK8sPersistentvolume) mountOptions() ([]any, error) {
	return convert.SliceAnyToInterface(k.obj.Spec.MountOptions), nil
}

func (k *mqlK8sPersistentvolume) claimNamespace() (string, error) {
	if k.obj.Spec.ClaimRef == nil {
		k.ClaimNamespace.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return k.obj.Spec.ClaimRef.Namespace, nil
}

func (k *mqlK8sPersistentvolume) claimName() (string, error) {
	if k.obj.Spec.ClaimRef == nil {
		k.ClaimName.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return k.obj.Spec.ClaimRef.Name, nil
}

func (k *mqlK8sPersistentvolume) claim() (*mqlK8sPersistentvolumeclaim, error) {
	if k.obj.Spec.ClaimRef == nil || k.obj.Spec.ClaimRef.Name == "" {
		k.Claim.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(k.MqlRuntime, "k8s.persistentvolumeclaim", map[string]*llx.RawData{
		"name":      llx.StringData(k.obj.Spec.ClaimRef.Name),
		"namespace": llx.StringData(k.obj.Spec.ClaimRef.Namespace),
	})
	if err != nil {
		// A PV with Retain reclaim policy outlives its PVC, so the
		// referenced PVC can already be gone. Resolve to null; surface
		// other errors.
		if errors.Is(err, ErrResourceNotFound) {
			k.Claim.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlK8sPersistentvolumeclaim), nil
}

func (k *mqlK8sPersistentvolume) nodeAffinity() (map[string]any, error) {
	return convert.JsonToDict(k.obj.Spec.NodeAffinity)
}

func (k *mqlK8sPersistentvolume) phase() (string, error) {
	return string(k.obj.Status.Phase), nil
}

func (k *mqlK8sPersistentvolume) reason() (string, error) {
	return k.obj.Status.Reason, nil
}

func (k *mqlK8sPersistentvolume) message() (string, error) {
	return k.obj.Status.Message, nil
}

func (k *mqlK8sPersistentvolume) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sPersistentvolume) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
