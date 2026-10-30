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

type mqlK8sDeploymentInternal struct {
	lock sync.Mutex
	obj  runtime.Object
}

func (k *mqlK8sDeployment) getDeployment() (*appsv1.Deployment, error) {
	d, ok := k.obj.(*appsv1.Deployment)
	if ok {
		return d, nil
	}
	return nil, errors.New("invalid k8s deployment")
}

func (k *mqlK8s) deployments() ([]any, error) {
	return k8sResourceToMql(k.MqlRuntime, gvkString(appsv1.SchemeGroupVersion.WithKind("deployments")), func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (any, error) {
		ts := obj.GetCreationTimestamp()

		r, err := CreateResource(k.MqlRuntime, "k8s.deployment", map[string]*llx.RawData{
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

		r.(*mqlK8sDeployment).obj = resource
		return r, nil
	})
}

func (k *mqlK8sDeployment) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sDeployment) podSpec() (map[string]any, error) {
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

func (k *mqlK8sDeployment) id() (string, error) {
	return k.Id.Data, nil
}

func initK8sDeployment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initNamespacedResource[*mqlK8sDeployment](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetDeployments() })
}

func (k *mqlK8sDeployment) annotations() (map[string]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(d.GetAnnotations()), nil
}

func (k *mqlK8sDeployment) labels() (map[string]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(d.GetLabels()), nil
}

func (k *mqlK8sDeployment) initContainers() ([]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return getContainers(d, &d.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sDeployment) containers() ([]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return getContainers(d, &d.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}

func (k *mqlK8sDeployment) pods() ([]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return podsMatchingSelector(k.MqlRuntime, d.Spec.Selector, d.Namespace)
}

func (k *mqlK8sDeployment) desiredReplicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	if d.Spec.Replicas == nil {
		// Defaults to 1 when unset.
		return 1, nil
	}
	return int64(*d.Spec.Replicas), nil
}

func (k *mqlK8sDeployment) selector() (map[string]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(d.Spec.Selector)
}

func (k *mqlK8sDeployment) strategy() (map[string]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(d.Spec.Strategy)
}

func (k *mqlK8sDeployment) revisionHistoryLimit() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	if d.Spec.RevisionHistoryLimit == nil {
		k.RevisionHistoryLimit.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*d.Spec.RevisionHistoryLimit), nil
}

func (k *mqlK8sDeployment) progressDeadlineSeconds() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	if d.Spec.ProgressDeadlineSeconds == nil {
		k.ProgressDeadlineSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*d.Spec.ProgressDeadlineSeconds), nil
}

func (k *mqlK8sDeployment) paused() (bool, error) {
	d, err := k.getDeployment()
	if err != nil {
		return false, err
	}
	return d.Spec.Paused, nil
}

func (k *mqlK8sDeployment) minReadySeconds() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Spec.MinReadySeconds), nil
}

func (k *mqlK8sDeployment) replicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Status.Replicas), nil
}

func (k *mqlK8sDeployment) readyReplicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Status.ReadyReplicas), nil
}

func (k *mqlK8sDeployment) availableReplicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Status.AvailableReplicas), nil
}

func (k *mqlK8sDeployment) updatedReplicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Status.UpdatedReplicas), nil
}

func (k *mqlK8sDeployment) unavailableReplicas() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return int64(d.Status.UnavailableReplicas), nil
}

func (k *mqlK8sDeployment) observedGeneration() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	return d.Status.ObservedGeneration, nil
}

func (k *mqlK8sDeployment) collisionCount() (int64, error) {
	d, err := k.getDeployment()
	if err != nil {
		return 0, err
	}
	if d.Status.CollisionCount == nil {
		k.CollisionCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*d.Status.CollisionCount), nil
}

func (k *mqlK8sDeployment) conditions() ([]any, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(d.Status.Conditions)
}

func (k *mqlK8sDeployment) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sDeployment) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
