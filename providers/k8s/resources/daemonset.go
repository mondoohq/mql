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

type mqlK8sDaemonsetInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sDaemonset) getDaemonSet() (*appsv1.DaemonSet, error) {
	ds, ok := k.obj.(*appsv1.DaemonSet)
	if ok {
		return ds, nil
	}
	return nil, errors.New("invalid k8s daemonset")
}

func (k *mqlK8s) daemonsets() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(appsv1.SchemeGroupVersion.WithKind("daemonsets")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.daemonset", map[string]*llx.RawData{
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

		r.(*mqlK8sDaemonset).obj = resource
		return r, nil
	})
}

func (k *mqlK8sDaemonset) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sDaemonset) podSpec() (map[string]any, error) {
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

func (k *mqlK8sDaemonset) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sDaemonset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sDaemonset](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetDaemonsets() })
}

func (k *mqlK8sDaemonset) annotations() (map[string]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(ds.GetAnnotations()), nil
}

func (k *mqlK8sDaemonset) labels() (map[string]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(ds.GetLabels()), nil
}

func (k *mqlK8sDaemonset) initContainers() ([]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return getContainers(ds, &ds.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sDaemonset) containers() ([]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return getContainers(ds, &ds.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sDaemonset) pods() ([]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return podsMatchingSelector(k.MqlRuntime, ds.Spec.Selector, ds.Namespace)
}

func (k *mqlK8sDaemonset) selector() (map[string]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(ds.Spec.Selector)
}

func (k *mqlK8sDaemonset) updateStrategy() (map[string]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(ds.Spec.UpdateStrategy)
}

func (k *mqlK8sDaemonset) revisionHistoryLimit() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	if ds.Spec.RevisionHistoryLimit == nil {
		k.RevisionHistoryLimit.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*ds.Spec.RevisionHistoryLimit), nil
}

func (k *mqlK8sDaemonset) minReadySeconds() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Spec.MinReadySeconds), nil
}

func (k *mqlK8sDaemonset) currentNumberScheduled() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.CurrentNumberScheduled), nil
}

func (k *mqlK8sDaemonset) numberMisscheduled() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.NumberMisscheduled), nil
}

func (k *mqlK8sDaemonset) desiredNumberScheduled() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.DesiredNumberScheduled), nil
}

func (k *mqlK8sDaemonset) numberReady() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.NumberReady), nil
}

func (k *mqlK8sDaemonset) updatedNumberScheduled() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.UpdatedNumberScheduled), nil
}

func (k *mqlK8sDaemonset) numberAvailable() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.NumberAvailable), nil
}

func (k *mqlK8sDaemonset) numberUnavailable() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return int64(ds.Status.NumberUnavailable), nil
}

func (k *mqlK8sDaemonset) observedGeneration() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	return ds.Status.ObservedGeneration, nil
}

func (k *mqlK8sDaemonset) collisionCount() (int64, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return 0, err
	}
	if ds.Status.CollisionCount == nil {
		k.CollisionCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*ds.Status.CollisionCount), nil
}

func (k *mqlK8sDaemonset) conditions() ([]any, error) {
	ds, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(ds.Status.Conditions)
}

func (k *mqlK8sDaemonset) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sDaemonset) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
