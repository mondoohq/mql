// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sReplicasetInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sReplicaset) getReplicaSet() (*appsv1.ReplicaSet, error) {
	rs, ok := k.obj.(*appsv1.ReplicaSet)
	if ok {
		return rs, nil
	}
	return nil, errors.New("invalid k8s replicaset")
}

func (k *mqlK8s) replicasets() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(appsv1.SchemeGroupVersion.WithKind("replicasets")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.replicaset", map[string]*llx.RawData{
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

		r.(*mqlK8sReplicaset).obj = resource
		return r, nil
	})
}

func (k *mqlK8sReplicaset) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sReplicaset) podSpec() (map[string]any, error) {
	podSpec, err := resources.GetPodSpec(k.obj)
	if err != nil {
		return nil, err
	}
	dict, err := convert.JsonToDict(podSpec)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (k *mqlK8sReplicaset) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sReplicaset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sReplicaset](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetReplicasets() })
}

func (k *mqlK8sReplicaset) annotations() (map[string]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(rs.GetAnnotations()), nil
}

func (k *mqlK8sReplicaset) labels() (map[string]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(rs.GetLabels()), nil
}

func (k *mqlK8sReplicaset) initContainers() ([]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return getContainers(rs, &rs.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sReplicaset) containers() ([]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return getContainers(rs, &rs.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sReplicaset) pods() ([]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return podsMatchingSelector(k.MqlRuntime, rs.Spec.Selector, rs.Namespace)
}

func (k *mqlK8sReplicaset) desiredReplicas() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	if rs.Spec.Replicas == nil {
		return 1, nil
	}
	return int64(*rs.Spec.Replicas), nil
}

func (k *mqlK8sReplicaset) selector() (map[string]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(rs.Spec.Selector)
}

func (k *mqlK8sReplicaset) minReadySeconds() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return int64(rs.Spec.MinReadySeconds), nil
}

func (k *mqlK8sReplicaset) replicas() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return int64(rs.Status.Replicas), nil
}

func (k *mqlK8sReplicaset) fullyLabeledReplicas() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return int64(rs.Status.FullyLabeledReplicas), nil
}

func (k *mqlK8sReplicaset) readyReplicas() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return int64(rs.Status.ReadyReplicas), nil
}

func (k *mqlK8sReplicaset) availableReplicas() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return int64(rs.Status.AvailableReplicas), nil
}

func (k *mqlK8sReplicaset) observedGeneration() (int64, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return 0, err
	}
	return rs.Status.ObservedGeneration, nil
}

func (k *mqlK8sReplicaset) conditions() ([]any, error) {
	rs, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(rs.Status.Conditions)
}

func (k *mqlK8sReplicaset) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sReplicaset) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
