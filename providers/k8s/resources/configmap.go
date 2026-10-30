// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sConfigmapInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sConfigmap) getConfigMap() (*corev1.ConfigMap, error) {
	cm, ok := k.obj.(*corev1.ConfigMap)
	if ok {
		return cm, nil
	}
	return nil, errors.New("invalid k8s configmap")
}

func (k *mqlK8s) configmaps() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(corev1.SchemeGroupVersion.WithKind("configmaps")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		cm, ok := resource.(*corev1.ConfigMap)
		if !ok {
			return nil, errors.New("not a k8s configmap")
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.configmap", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"data":            llx.MapData(convert.MapToInterfaceMap(cm.Data), types.String),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlK8sConfigmap).obj = cm
		return r, nil
	})
}

func (k *mqlK8sConfigmap) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sConfigmap) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sConfigmap(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sConfigmap](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetConfigmaps() })
}

func (k *mqlK8sConfigmap) annotations() (map[string]any, error) {
	// Get the ConfigMap object
	cm, err := k.getConfigMap()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(cm.GetAnnotations()), nil
}

func (k *mqlK8sConfigmap) labels() (map[string]any, error) {
	cm, err := k.getConfigMap()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(cm.GetLabels()), nil
}

func (k *mqlK8sConfigmap) usedBy() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	pods := o.(*mqlK8s).GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}

	cmName := k.Name.Data
	namespace := k.Namespace.Data

	out := []any{}
	for i := range pods.Data {
		p, ok := pods.Data[i].(*mqlK8sPod)
		if !ok {
			continue
		}
		if p.Namespace.Data != namespace {
			continue
		}
		pod, err := p.getPod()
		if err != nil {
			continue
		}
		if podReferencesConfigMap(pod, cmName) {
			out = append(out, p)
		}
	}
	return out, nil
}

func podReferencesConfigMap(pod *corev1.Pod, cmName string) bool {
	for _, v := range pod.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == cmName {
			return true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.ConfigMap != nil && src.ConfigMap.Name == cmName {
					return true
				}
			}
		}
	}
	for _, c := range pod.Spec.Containers {
		if containerReferencesConfigMap(c, cmName) {
			return true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if containerReferencesConfigMap(c, cmName) {
			return true
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if containerReferencesConfigMap(corev1.Container(c.EphemeralContainerCommon), cmName) {
			return true
		}
	}
	return false
}

func containerReferencesConfigMap(c corev1.Container, cmName string) bool {
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil && e.ValueFrom.ConfigMapKeyRef.Name == cmName {
			return true
		}
	}
	for _, ef := range c.EnvFrom {
		if ef.ConfigMapRef != nil && ef.ConfigMapRef.Name == cmName {
			return true
		}
	}
	return false
}

func (k *mqlK8sConfigmap) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sConfigmap) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
