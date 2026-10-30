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

type mqlK8sStatefulsetInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sStatefulset) getStatefulSet() (*appsv1.StatefulSet, error) {
	s, ok := k.obj.(*appsv1.StatefulSet)
	if ok {
		return s, nil
	}
	return nil, errors.New("invalid k8s statefulset")
}

func (k *mqlK8s) statefulsets() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(appsv1.SchemeGroupVersion.WithKind("statefulsets")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.statefulset", map[string]*llx.RawData{
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

		r.(*mqlK8sStatefulset).obj = resource
		return r, nil
	})
}

func (k *mqlK8sStatefulset) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sStatefulset) podSpec() (map[string]any, error) {
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

func (k *mqlK8sStatefulset) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sStatefulset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sStatefulset](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetStatefulsets() })
}

func (k *mqlK8sStatefulset) annotations() (map[string]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(s.GetAnnotations()), nil
}

func (k *mqlK8sStatefulset) labels() (map[string]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(s.GetLabels()), nil
}

func (k *mqlK8sStatefulset) initContainers() ([]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return getContainers(s, &s.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sStatefulset) containers() ([]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return getContainers(s, &s.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sStatefulset) pods() ([]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return podsMatchingSelector(k.MqlRuntime, s.Spec.Selector, s.Namespace)
}

func (k *mqlK8sStatefulset) desiredReplicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	if s.Spec.Replicas == nil {
		return 1, nil
	}
	return int64(*s.Spec.Replicas), nil
}

func (k *mqlK8sStatefulset) selector() (map[string]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(s.Spec.Selector)
}

func (k *mqlK8sStatefulset) serviceName() (string, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return "", err
	}
	return s.Spec.ServiceName, nil
}

func (k *mqlK8sStatefulset) podManagementPolicy() (string, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return "", err
	}
	return string(s.Spec.PodManagementPolicy), nil
}

func (k *mqlK8sStatefulset) updateStrategy() (map[string]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(s.Spec.UpdateStrategy)
}

func (k *mqlK8sStatefulset) revisionHistoryLimit() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	if s.Spec.RevisionHistoryLimit == nil {
		k.RevisionHistoryLimit.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*s.Spec.RevisionHistoryLimit), nil
}

func (k *mqlK8sStatefulset) persistentVolumeClaimRetentionPolicy() (map[string]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(s.Spec.PersistentVolumeClaimRetentionPolicy)
}

func (k *mqlK8sStatefulset) minReadySeconds() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Spec.MinReadySeconds), nil
}

func (k *mqlK8sStatefulset) ordinalsStart() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	if s.Spec.Ordinals == nil {
		return 0, nil
	}
	return int64(s.Spec.Ordinals.Start), nil
}

func (k *mqlK8sStatefulset) replicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Status.Replicas), nil
}

func (k *mqlK8sStatefulset) readyReplicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Status.ReadyReplicas), nil
}

func (k *mqlK8sStatefulset) currentReplicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Status.CurrentReplicas), nil
}

func (k *mqlK8sStatefulset) updatedReplicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Status.UpdatedReplicas), nil
}

func (k *mqlK8sStatefulset) availableReplicas() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return int64(s.Status.AvailableReplicas), nil
}

func (k *mqlK8sStatefulset) observedGeneration() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	return s.Status.ObservedGeneration, nil
}

func (k *mqlK8sStatefulset) currentRevision() (string, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return "", err
	}
	return s.Status.CurrentRevision, nil
}

func (k *mqlK8sStatefulset) updateRevision() (string, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return "", err
	}
	return s.Status.UpdateRevision, nil
}

func (k *mqlK8sStatefulset) collisionCount() (int64, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return 0, err
	}
	if s.Status.CollisionCount == nil {
		k.CollisionCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*s.Status.CollisionCount), nil
}

func (k *mqlK8sStatefulset) conditions() ([]any, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(s.Status.Conditions)
}

func (k *mqlK8sStatefulset) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sStatefulset) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
